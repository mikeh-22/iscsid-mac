/*
 * test_login.c - Login FSM tests with fork()-based mock iSCSI targets
 *
 * Socketpair-based mocks cover: no-auth, EOF, CHAP-MD5, CHAP-SHA256, auth
 * failure.  TCP listener-based mocks cover: redirect-then-success, redirect
 * loop.  The mock targets speak the minimum subset of RFC 7143 login protocol
 * needed to exercise the initiator FSM; they do not validate PDU fields.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/auth.h"
#include "../src/daemon/login.h"
#include "../src/daemon/pdu.h"
#include "../src/daemon/session.h"
#include "../src/daemon/connection.h"
#include "../src/shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST(name) \
    do { printf("  %-60s", name); fflush(stdout); } while (0)
#define PASS()    printf("PASS\n")
#define FAIL(msg) do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* -----------------------------------------------------------------------
 * Mock target helpers
 * ----------------------------------------------------------------------- */

/*
 * Build and send a login response PDU on fd.
 * status_class/status_detail: 0/0 = success; 0x01/0x01 = redirect; 0x02/0x01 = auth failed.
 * kv/kv_len: optional key=value data segment (pass NULL/0 for empty).
 */
static void mock_login_rsp(int fd, uint8_t csg, uint8_t nsg, int transit,
                            uint8_t status_class, uint8_t status_detail,
                            uint32_t statsn, const char *kv, uint32_t kv_len)
{
    iscsi_pdu_t pdu;
    memset(&pdu, 0, sizeof(pdu));
    iscsi_login_rsp_t *rsp = (iscsi_login_rsp_t *)&pdu.hdr;
    rsp->opcode         = ISCSI_OP_LOGIN_RSP;
    rsp->flags          = (uint8_t)((transit ? ISCSI_LOGIN_TRANSIT : 0)
                          | ((csg & 0x03) << ISCSI_LOGIN_CSG_SHIFT)
                          | (nsg & ISCSI_LOGIN_NSG_MASK));
    rsp->max_version    = ISCSI_DRAFT20_VERSION;
    rsp->active_version = ISCSI_DRAFT20_VERSION;
    rsp->tsih           = htons(0x0001);
    rsp->itt            = htonl(1);
    rsp->statsn         = htonl(statsn);
    rsp->expcmdsn       = htonl(1);
    rsp->maxcmdsn       = htonl(32);
    rsp->status_class   = status_class;
    rsp->status_detail  = status_detail;
    if (kv_len > 0)
        pdu_set_data_ref(&pdu, kv, kv_len);
    pdu_send(fd, &pdu, 0, 0);
}

/*
 * Mock no-auth target: handles the 4 PDU exchanges of a successful no-auth
 * login (1 security + 1 OpNeg round-trip each).
 * Returns 0 on success, 1 on recv error.
 */
static int mock_noauth_target(int fd)
{
    iscsi_pdu_t req;

    /* Security phase: recv request, send T=1 transit to OpNeg */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    mock_login_rsp(fd, ISCSI_SECURITY_NEGOTIATION,
                       ISCSI_LOGIN_OPERATIONAL_NEG, 1, 0, 0, 0, NULL, 0);

    /* Operational phase: recv request, send T=1 transit to FFP */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    mock_login_rsp(fd, ISCSI_LOGIN_OPERATIONAL_NEG,
                       ISCSI_FULL_FEATURE_PHASE, 1, 0, 0, 1, NULL, 0);
    return 0;
}

/*
 * Mock CHAP target: 3 security round-trips + 1 OpNeg.
 * algorithm: 5 = MD5, 7 = SHA-256.
 * Does NOT verify the initiator's CHAP response — just accepts it.
 * Returns 0 on success, 1 on recv error.
 */
static int mock_chap_target(int fd, int algorithm)
{
    iscsi_pdu_t req;
    char        kv[256];
    int         used;
    char        alg_str[4];

    /* Round 1: recv AuthMethod=CHAP proposal, send ack */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    mock_login_rsp(fd, ISCSI_SECURITY_NEGOTIATION,
                       ISCSI_SECURITY_NEGOTIATION, 0, 0, 0, 0, NULL, 0);

    /* Round 2: recv CHAP_A offer, send challenge */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    used = 0;
    snprintf(alg_str, sizeof(alg_str), "%d", algorithm);
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_A", alg_str);
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_I", "42");
    /* 16-byte all-zero challenge in hex */
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_C",
                         "0x00000000000000000000000000000000");
    mock_login_rsp(fd, ISCSI_SECURITY_NEGOTIATION,
                       ISCSI_SECURITY_NEGOTIATION, 0, 0, 0, 0,
                       kv, (uint32_t)used);

    /* Round 3: recv CHAP_R response, transit to OpNeg */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    mock_login_rsp(fd, ISCSI_SECURITY_NEGOTIATION,
                       ISCSI_LOGIN_OPERATIONAL_NEG, 1, 0, 0, 0, NULL, 0);

    /* OpNeg: recv, send complete */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    mock_login_rsp(fd, ISCSI_LOGIN_OPERATIONAL_NEG,
                       ISCSI_FULL_FEATURE_PHASE, 1, 0, 0, 1, NULL, 0);
    return 0;
}

/*
 * Bind a TCP listening socket on a random ephemeral port.
 * Returns the listener fd; sets *port_out to the assigned port.
 */
static int bind_listener(uint16_t *port_out)
{
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return -1;
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port        = 0;    /* kernel assigns */

    if (bind(lfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        close(lfd); return -1;
    }
    if (listen(lfd, 4) < 0) { close(lfd); return -1; }

    socklen_t slen = sizeof(sin);
    getsockname(lfd, (struct sockaddr *)&sin, &slen);
    *port_out = ntohs(sin.sin_port);
    return lfd;
}

/* Create a minimal session for testing. */
static iscsi_session_t *make_sess(void)
{
    return session_create(SESS_TYPE_NORMAL,
                          "iqn.2024-01.io.test:init",
                          "iqn.2024-01.io.test:target",
                          "127.0.0.1:3260");
}

/*
 * Wrap a raw fd in a heap-allocated iscsi_conn_t.
 * The caller is responsible for zeroing conn->fd before calling free() so
 * the fd is not double-closed.
 */
static iscsi_conn_t *make_conn(int fd)
{
    iscsi_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;
    conn->fd           = fd;
    conn->state        = CONN_STATE_CONNECTING;
    conn->max_recv_dsl = 262144;
    conn->max_send_dsl = 8192;
    return conn;
}

/*
 * Mock mutual-CHAP target: 3 security round-trips + 1 OpNeg.
 * algorithm: 5=MD5, 7=SHA-256.
 * target_secret: the secret the "target" uses to respond to the initiator's
 *                mutual challenge (must match sess->chap_target_secret).
 * correct_response: if non-zero, compute and send the correct CHAP_R;
 *                   if zero, send a garbage response to trigger auth failure.
 * Returns 0 on success, 1 on recv error.
 */
static int mock_mutual_chap_target(int fd, int algorithm,
                                   const char *target_secret,
                                   int correct_response)
{
    iscsi_pdu_t req;
    char        kv[512];
    int         used;
    char        alg_str[4];

    /* Round 1: recv AuthMethod=CHAP proposal, send ack */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    mock_login_rsp(fd, ISCSI_SECURITY_NEGOTIATION,
                       ISCSI_SECURITY_NEGOTIATION, 0, 0, 0, 0, NULL, 0);

    /* Round 2: recv CHAP_A offer, send challenge */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    used = 0;
    snprintf(alg_str, sizeof(alg_str), "%d", algorithm);
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_A", alg_str);
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_I", "42");
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_C",
                         "0x00000000000000000000000000000000");
    mock_login_rsp(fd, ISCSI_SECURITY_NEGOTIATION,
                       ISCSI_SECURITY_NEGOTIATION, 0, 0, 0, 0,
                       kv, (uint32_t)used);

    /* Round 3: recv initiator's CHAP_R + mutual challenge (CHAP_I, CHAP_C) */
    if (pdu_recv(fd, &req, 0, 0)) return 1;

    char resp_hex[CHAP_MAX_RESPONSE_LEN * 2 + 4];
    uint32_t mutual_id = 0;

    if (req.data_len > 0)
        pdu_kv_get_int((char *)req.data, req.data_len, "CHAP_I", &mutual_id);

    if (correct_response && req.data_len > 0) {
        /*
         * Parse the initiator's mutual challenge and compute the correct
         * CHAP response using target_secret.
         * The response is H(mutual_id || target_secret || mutual_challenge).
         */
        char mutual_c_hex[CHAP_MAX_CHALLENGE_LEN * 2 + 4] = {0};
        pdu_kv_get_str((char *)req.data, req.data_len, "CHAP_C",
                       mutual_c_hex, sizeof(mutual_c_hex));

        chap_ctx_t mock_ctx;
        memset(&mock_ctx, 0, sizeof(mock_ctx));
        mock_ctx.algorithm  = (chap_alg_t)algorithm;
        mock_ctx.identifier = (uint8_t)mutual_id;
        snprintf(mock_ctx.initiator_secret, sizeof(mock_ctx.initiator_secret),
                 "%s", target_secret);
        int n = chap_hex_decode(mock_ctx.challenge, sizeof(mock_ctx.challenge),
                                mutual_c_hex);
        mock_ctx.challenge_len = (n > 0) ? (size_t)n : 0;
        chap_compute_response(&mock_ctx, resp_hex, sizeof(resp_hex));
    } else {
        snprintf(resp_hex, sizeof(resp_hex), "0xdeadbeef");
    }
    pdu_free_data(&req);

    /*
     * Echo back CHAP_I (the mutual id from the initiator's challenge) so
     * the initiator can retrieve it with pdu_kv_get_int("CHAP_I") when
     * calling chap_verify_mutual().
     */
    char mutual_i_str[16];
    snprintf(mutual_i_str, sizeof(mutual_i_str), "%u", (unsigned)mutual_id);
    used = 0;
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_I", mutual_i_str);
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_R", resp_hex);
    mock_login_rsp(fd, ISCSI_SECURITY_NEGOTIATION,
                       ISCSI_LOGIN_OPERATIONAL_NEG, 1, 0, 0, 0,
                       kv, (uint32_t)used);

    /* OpNeg: recv, send complete */
    if (pdu_recv(fd, &req, 0, 0)) return 1;
    pdu_free_data(&req);
    mock_login_rsp(fd, ISCSI_LOGIN_OPERATIONAL_NEG,
                       ISCSI_FULL_FEATURE_PHASE, 1, 0, 0, 1, NULL, 0);
    return 0;
}

/* -----------------------------------------------------------------------
 * Tests
 * ----------------------------------------------------------------------- */

static void test_result_str(void)
{
    TEST("login_result_str: every code has a unique description");

    login_result_t codes[] = {
        LOGIN_OK, LOGIN_AUTH_FAILED, LOGIN_IO_ERROR,
        LOGIN_PROTO_ERROR, LOGIN_TARGET_ERROR, LOGIN_NO_RESOURCES,
        LOGIN_REDIRECTED,
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
        const char *s = login_result_str(codes[i]);
        if (!s || strcmp(s, "Unknown error") == 0) { ok = 0; break; }
    }
    if (ok) PASS(); else FAIL("a code returned 'Unknown error'");
}

static void test_login_noauth(void)
{
    TEST("iscsi_login: no-auth success");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { FAIL("socketpair"); return; }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(sv[0]); close(sv[1]); return; }

    if (pid == 0) {
        close(sv[0]);
        _exit(mock_noauth_target(sv[1]) ? 1 : 0);
    }

    close(sv[1]);
    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);
    login_result_t   result = (sess && conn)
                              ? iscsi_login(sess, conn)
                              : LOGIN_IO_ERROR;

    if (conn) { conn->fd = -1; free(conn); }
    if (sess) session_destroy(sess);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_OK && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("unexpected result or mock target error");
}

static void test_login_eof(void)
{
    TEST("iscsi_login: EOF after security PDU → LOGIN_IO_ERROR");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { FAIL("socketpair"); return; }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(sv[0]); close(sv[1]); return; }

    if (pid == 0) {
        close(sv[0]);
        /* Drain the security request, then close without replying */
        iscsi_pdu_t req;
        pdu_recv(sv[1], &req, 0, 0);
        pdu_free_data(&req);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);
    login_result_t   result = (sess && conn)
                              ? iscsi_login(sess, conn)
                              : LOGIN_OK;

    if (conn) { conn->fd = -1; free(conn); }
    if (sess) session_destroy(sess);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_IO_ERROR) PASS(); else FAIL("expected LOGIN_IO_ERROR");
}

static void test_login_chap_md5(void)
{
    TEST("iscsi_login: CHAP-MD5 success");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { FAIL("socketpair"); return; }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(sv[0]); close(sv[1]); return; }

    if (pid == 0) {
        close(sv[0]);
        _exit(mock_chap_target(sv[1], 5) ? 1 : 0);
    }

    close(sv[1]);
    iscsi_session_t *sess = make_sess();
    if (sess) {
        snprintf(sess->chap_username, sizeof(sess->chap_username), "testuser");
        snprintf(sess->chap_secret,   sizeof(sess->chap_secret),   "supersecret12");
    }
    iscsi_conn_t *conn   = make_conn(sv[0]);
    login_result_t result = (sess && conn)
                            ? iscsi_login(sess, conn)
                            : LOGIN_IO_ERROR;

    if (conn) { conn->fd = -1; free(conn); }
    if (sess) session_destroy(sess);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_OK && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("CHAP-MD5 login failed");
}

static void test_login_chap_sha256(void)
{
    TEST("iscsi_login: CHAP-SHA256 success");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { FAIL("socketpair"); return; }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(sv[0]); close(sv[1]); return; }

    if (pid == 0) {
        close(sv[0]);
        _exit(mock_chap_target(sv[1], 7) ? 1 : 0);
    }

    close(sv[1]);
    iscsi_session_t *sess = make_sess();
    if (sess) {
        snprintf(sess->chap_username, sizeof(sess->chap_username), "testuser");
        snprintf(sess->chap_secret,   sizeof(sess->chap_secret),   "supersecret12");
    }
    iscsi_conn_t *conn   = make_conn(sv[0]);
    login_result_t result = (sess && conn)
                            ? iscsi_login(sess, conn)
                            : LOGIN_IO_ERROR;

    if (conn) { conn->fd = -1; free(conn); }
    if (sess) session_destroy(sess);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_OK && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("CHAP-SHA256 login failed");
}

static void test_login_auth_failure(void)
{
    TEST("iscsi_login: auth failure response → LOGIN_AUTH_FAILED");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { FAIL("socketpair"); return; }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(sv[0]); close(sv[1]); return; }

    if (pid == 0) {
        close(sv[0]);
        /* Drain the security request, then send auth-failure */
        iscsi_pdu_t req;
        pdu_recv(sv[1], &req, 0, 0);
        pdu_free_data(&req);
        mock_login_rsp(sv[1], ISCSI_SECURITY_NEGOTIATION,
                               ISCSI_SECURITY_NEGOTIATION, 0,
                               0x02, 0x01, 0, NULL, 0);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);
    login_result_t   result = (sess && conn)
                              ? iscsi_login(sess, conn)
                              : LOGIN_OK;

    if (conn) { conn->fd = -1; free(conn); }
    if (sess) session_destroy(sess);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_AUTH_FAILED) PASS(); else FAIL("expected LOGIN_AUTH_FAILED");
}

static void test_login_redirect_success(void)
{
    TEST("iscsi_login: redirect then success");

    uint16_t port_a, port_b;
    int lfd_a = bind_listener(&port_a);
    int lfd_b = bind_listener(&port_b);
    if (lfd_a < 0 || lfd_b < 0) {
        FAIL("bind_listener");
        if (lfd_a >= 0) close(lfd_a);
        if (lfd_b >= 0) close(lfd_b);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(lfd_a); close(lfd_b); return; }

    if (pid == 0) {
        /* Port A: recv security PDU, send redirect to port B */
        int fd_a = accept(lfd_a, NULL, NULL);
        iscsi_pdu_t req;
        pdu_recv(fd_a, &req, 0, 0);
        pdu_free_data(&req);

        char kv[256];
        char addr_str[64];
        int  used = 0;
        snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%u", (unsigned)port_b);
        used = pdu_kv_append(kv, sizeof(kv), used, "TargetAddress", addr_str);
        mock_login_rsp(fd_a, ISCSI_SECURITY_NEGOTIATION,
                              ISCSI_SECURITY_NEGOTIATION, 0,
                              0x01, 0x01, 0, kv, (uint32_t)used);
        close(fd_a);

        /* Port B: complete login normally */
        int fd_b = accept(lfd_b, NULL, NULL);
        int exit_code = mock_noauth_target(fd_b) ? 1 : 0;
        close(fd_b);

        close(lfd_a);
        close(lfd_b);
        _exit(exit_code);
    }

    close(lfd_a);
    close(lfd_b);

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = conn_create("127.0.0.1", port_a);
    login_result_t   result = (sess && conn)
                              ? iscsi_login(sess, conn)
                              : LOGIN_IO_ERROR;

    conn_destroy(conn);
    if (sess) session_destroy(sess);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_OK && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("redirect-then-success login failed");
}

static void test_login_redirect_loop(void)
{
    TEST("iscsi_login: redirect loop → LOGIN_TARGET_ERROR");

    uint16_t port_a;
    int lfd_a = bind_listener(&port_a);
    if (lfd_a < 0) { FAIL("bind_listener"); return; }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(lfd_a); return; }

    if (pid == 0) {
        /*
         * Accept ISCSI_LOGIN_MAX_REDIRECTS+1 connections (initial attempt
         * plus one per redirect); always send a redirect back to ourselves.
         * The initiator stops retrying after ISCSI_LOGIN_MAX_REDIRECTS.
         */
        char kv[256];
        char addr_str[64];
        snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%u", (unsigned)port_a);

        for (int i = 0; i <= ISCSI_LOGIN_MAX_REDIRECTS; i++) {
            int fd = accept(lfd_a, NULL, NULL);
            if (fd < 0) break;
            iscsi_pdu_t req;
            pdu_recv(fd, &req, 0, 0);
            pdu_free_data(&req);
            int used = 0;
            used = pdu_kv_append(kv, sizeof(kv), used, "TargetAddress", addr_str);
            mock_login_rsp(fd, ISCSI_SECURITY_NEGOTIATION,
                              ISCSI_SECURITY_NEGOTIATION, 0,
                              0x01, 0x01, 0, kv, (uint32_t)used);
            close(fd);
        }
        close(lfd_a);
        _exit(0);
    }

    close(lfd_a);

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = conn_create("127.0.0.1", port_a);
    login_result_t   result = (sess && conn)
                              ? iscsi_login(sess, conn)
                              : LOGIN_OK;

    conn_destroy(conn);
    if (sess) session_destroy(sess);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_TARGET_ERROR) PASS(); else FAIL("expected LOGIN_TARGET_ERROR");
}

static void test_login_mutual_chap_success(void)
{
    TEST("iscsi_login: mutual CHAP success");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { FAIL("socketpair"); return; }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(sv[0]); close(sv[1]); return; }

    if (pid == 0) {
        close(sv[0]);
        _exit(mock_mutual_chap_target(sv[1], 5, "targetsecret12", 1) ? 1 : 0);
    }

    close(sv[1]);
    iscsi_session_t *sess = make_sess();
    if (sess) {
        snprintf(sess->chap_username,      sizeof(sess->chap_username),
                 "testuser");
        snprintf(sess->chap_secret,        sizeof(sess->chap_secret),
                 "supersecret12");
        snprintf(sess->chap_target_secret, sizeof(sess->chap_target_secret),
                 "targetsecret12");
    }
    iscsi_conn_t  *conn   = make_conn(sv[0]);
    login_result_t result = (sess && conn)
                            ? iscsi_login(sess, conn)
                            : LOGIN_IO_ERROR;

    if (conn) { conn->fd = -1; free(conn); }
    if (sess) session_destroy(sess);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_OK && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        PASS();
    else
        FAIL("mutual CHAP success case failed");
}

static void test_login_mutual_chap_failure(void)
{
    TEST("iscsi_login: mutual CHAP wrong response → LOGIN_AUTH_FAILED");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { FAIL("socketpair"); return; }

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(sv[0]); close(sv[1]); return; }

    if (pid == 0) {
        close(sv[0]);
        /* correct_response=0: mock sends garbage CHAP_R */
        _exit(mock_mutual_chap_target(sv[1], 5, "targetsecret12", 0) ? 1 : 0);
    }

    close(sv[1]);
    iscsi_session_t *sess = make_sess();
    if (sess) {
        snprintf(sess->chap_username,      sizeof(sess->chap_username),
                 "testuser");
        snprintf(sess->chap_secret,        sizeof(sess->chap_secret),
                 "supersecret12");
        snprintf(sess->chap_target_secret, sizeof(sess->chap_target_secret),
                 "targetsecret12");
    }
    iscsi_conn_t  *conn   = make_conn(sv[0]);
    login_result_t result = (sess && conn)
                            ? iscsi_login(sess, conn)
                            : LOGIN_OK;

    if (conn) { conn->fd = -1; free(conn); }
    if (sess) session_destroy(sess);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (result == LOGIN_AUTH_FAILED) PASS();
    else FAIL("expected LOGIN_AUTH_FAILED for wrong mutual CHAP response");
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_login\n");

    test_result_str();
    test_login_noauth();
    test_login_eof();
    test_login_chap_md5();
    test_login_chap_sha256();
    test_login_auth_failure();
    test_login_redirect_success();
    test_login_redirect_loop();
    test_login_mutual_chap_success();
    test_login_mutual_chap_failure();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
