/*
 * test_recovery.c - Unit tests for recovery.c (SNACK request PDU)
 *
 * recovery_reconnect() requires a live target so is not tested here.
 * We focus on recovery_send_snack() by capturing the PDU over a socketpair.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/recovery.h"
#include "../src/daemon/pdu.h"
#include "../src/daemon/session.h"
#include "../src/daemon/connection.h"
#include "../src/shared/iscsi_protocol.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TEST(name) \
    do { printf("  %-52s", name); fflush(stdout); } while (0)
#define PASS()  printf("PASS\n")
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static iscsi_conn_t *make_conn(int fd)
{
    iscsi_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd         = fd;
    c->state      = CONN_STATE_LOGGED_IN;
    c->cid        = 1;
    c->exp_statsn = 7;
    return c;
}

static iscsi_session_t *make_sess(void)
{
    return session_create(SESS_TYPE_NORMAL,
                          "iqn.2024-01.io.test:init",
                          "iqn.2024-01.io.test:target",
                          "127.0.0.1:3260");
}

/*
 * Read a raw iSCSI PDU header (48 bytes, no length prefix) from fd.
 * pdu_send() / pdu_recv() use the iSCSI native wire format directly.
 * Optionally drains the data segment as well (using dlength in hdr).
 */
static ssize_t recv_pdu_hdr(int fd, uint8_t hdr48[48])
{
    uint8_t *p = hdr48;
    size_t remaining = 48;
    while (remaining > 0) {
        ssize_t n = recv(fd, p, remaining, 0);
        if (n <= 0) return -1;
        p += n;
        remaining -= (size_t)n;
    }
    return 48;
}

/* -----------------------------------------------------------------------
 * Test: SNACK Request — data-ACK type
 * ----------------------------------------------------------------------- */

static void test_snack_data_ack(void)
{
    TEST("recovery_send_snack: DATA_ACK type fields");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    int rc = recovery_send_snack(conn, sess,
                                  /*itt=*/0x12345678, /*ttt=*/0xABCDEF01,
                                  ISCSI_SNACK_DATA_ACK,
                                  /*begrun=*/10, /*runlength=*/5);
    if (rc != 0) { FAIL("send_snack returned error"); goto done; }

    uint8_t hdr[48];
    if (recv_pdu_hdr(sv[1], hdr) < 0) { FAIL("failed to recv PDU"); goto done; }

    /* opcode must be ISCSI_OP_SNACK_REQ (0x10) */
    if ((hdr[0] & 0x3f) != ISCSI_OP_SNACK_REQ) {
        FAIL("wrong opcode"); goto done;
    }

    /* type nibble in flags (low 4 bits) must be ISCSI_SNACK_DATA_ACK (0) */
    if ((hdr[1] & 0x0f) != ISCSI_SNACK_DATA_ACK) {
        FAIL("wrong SNACK type in flags"); goto done;
    }

    /* ITT at bytes 16-19 */
    uint32_t got_itt = ntohl(*(uint32_t *)(hdr + 16));
    if (got_itt != 0x12345678) { FAIL("ITT mismatch"); goto done; }

    /* TTT at bytes 20-23 */
    uint32_t got_ttt = ntohl(*(uint32_t *)(hdr + 20));
    if (got_ttt != 0xABCDEF01) { FAIL("TTT mismatch"); goto done; }

    /* ExpStatSN at bytes 28-31 */
    uint32_t got_expstatsn = ntohl(*(uint32_t *)(hdr + 28));
    if (got_expstatsn != 7) { FAIL("ExpStatSN mismatch"); goto done; }

    /* BegRun at bytes 40-43 */
    uint32_t got_begrun = ntohl(*(uint32_t *)(hdr + 40));
    if (got_begrun != 10) { FAIL("BegRun mismatch"); goto done; }

    /* RunLength at bytes 44-47 */
    uint32_t got_runlen = ntohl(*(uint32_t *)(hdr + 44));
    if (got_runlen != 5) { FAIL("RunLength mismatch"); goto done; }

    PASS();
done:
    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: SNACK Request — R2T_SNACK type
 * ----------------------------------------------------------------------- */

static void test_snack_r2t(void)
{
    TEST("recovery_send_snack: R2T_SNACK type");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    int rc = recovery_send_snack(conn, sess,
                                  0xDEADBEEF, 0xCAFEBABE,
                                  ISCSI_SNACK_R2T_SNACK,
                                  /*begrun=*/0, /*runlength=*/0);
    if (rc != 0) { FAIL("send_snack returned error"); goto done; }

    uint8_t hdr[48];
    if (recv_pdu_hdr(sv[1], hdr) < 0) { FAIL("failed to recv PDU"); goto done; }

    /* type = ISCSI_SNACK_R2T_SNACK (1) */
    if ((hdr[1] & 0x0f) != ISCSI_SNACK_R2T_SNACK) {
        FAIL("wrong SNACK type for R2T"); goto done;
    }

    uint32_t got_begrun = ntohl(*(uint32_t *)(hdr + 40));
    uint32_t got_runlen = ntohl(*(uint32_t *)(hdr + 44));
    if (got_begrun != 0 || got_runlen != 0) {
        FAIL("BegRun/RunLength should be 0"); goto done;
    }

    PASS();
done:
    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: SNACK Request — STATUS_SNACK type, large begrun
 * ----------------------------------------------------------------------- */

static void test_snack_status(void)
{
    TEST("recovery_send_snack: STATUS_SNACK with large BegRun");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    int rc = recovery_send_snack(conn, sess,
                                  0x00000001, 0xFFFFFFFF,
                                  ISCSI_SNACK_STATUS_SNACK,
                                  /*begrun=*/0xFFFFFFFE, /*runlength=*/1);
    if (rc != 0) { FAIL("send_snack returned error"); goto done; }

    uint8_t hdr[48];
    if (recv_pdu_hdr(sv[1], hdr) < 0) { FAIL("failed to recv PDU"); goto done; }

    if ((hdr[1] & 0x0f) != ISCSI_SNACK_STATUS_SNACK) {
        FAIL("wrong SNACK type for STATUS"); goto done;
    }

    uint32_t got_begrun = ntohl(*(uint32_t *)(hdr + 40));
    if (got_begrun != 0xFFFFFFFE) { FAIL("BegRun mismatch for large value"); goto done; }

    PASS();
done:
    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: session_next_itt never issues 0xFFFFFFFF
 * ----------------------------------------------------------------------- */

static void test_itt_no_rsvd(void)
{
    TEST("session_next_itt: never issues 0xFFFFFFFF");

    iscsi_session_t *sess = make_sess();

    /* Wind next_itt up to the value just before the reserved tag */
    sess->next_itt = 0xFFFFFFFE;

    uint32_t itt1 = session_next_itt(sess);   /* should be 0xFFFFFFFE */
    uint32_t itt2 = session_next_itt(sess);   /* wraps: should be 1, not 0xFFFFFFFF */

    if (itt1 == ISCSI_RSVD_TASK_TAG || itt2 == ISCSI_RSVD_TASK_TAG) {
        FAIL("session_next_itt issued reserved 0xFFFFFFFF");
    } else if (itt2 == 0) {
        FAIL("session_next_itt wrapped to 0");
    } else {
        PASS();
    }

    session_destroy(sess);
}

/* -----------------------------------------------------------------------
 * Tests: iscsi_parse_portal
 * ----------------------------------------------------------------------- */

static void test_parse_portal_ipv4(void)
{
    TEST("iscsi_parse_portal: IPv4 host:port");
    char host[256]; uint16_t port;
    int rc = iscsi_parse_portal("192.168.1.1:3260", host, sizeof(host), &port);
    if (rc == 0 && strcmp(host, "192.168.1.1") == 0 && port == 3260) PASS();
    else FAIL("IPv4 host:port parse failed");
}

static void test_parse_portal_ipv4_default_port(void)
{
    TEST("iscsi_parse_portal: IPv4 host only → default port");
    char host[256]; uint16_t port;
    int rc = iscsi_parse_portal("192.168.1.1", host, sizeof(host), &port);
    if (rc == 0 && strcmp(host, "192.168.1.1") == 0 && port == ISCSI_PORT) PASS();
    else FAIL("IPv4 host-only parse failed");
}

static void test_parse_portal_ipv6(void)
{
    TEST("iscsi_parse_portal: IPv6 bracketed [::1]:3260");
    char host[256]; uint16_t port;
    int rc = iscsi_parse_portal("[::1]:3260", host, sizeof(host), &port);
    if (rc == 0 && strcmp(host, "::1") == 0 && port == 3260) PASS();
    else FAIL("IPv6 parse failed");
}

static void test_parse_portal_ipv6_default_port(void)
{
    TEST("iscsi_parse_portal: IPv6 [::1] only → default port");
    char host[256]; uint16_t port;
    int rc = iscsi_parse_portal("[::1]", host, sizeof(host), &port);
    if (rc == 0 && strcmp(host, "::1") == 0 && port == ISCSI_PORT) PASS();
    else FAIL("IPv6 no-port parse failed");
}

static void test_parse_portal_group_tag(void)
{
    TEST("iscsi_parse_portal: strips ,groupTag suffix");
    char host[256]; uint16_t port;
    int rc = iscsi_parse_portal("10.0.0.1:3260,1", host, sizeof(host), &port);
    if (rc == 0 && strcmp(host, "10.0.0.1") == 0 && port == 3260) PASS();
    else FAIL("group tag stripping failed");
}

static void test_parse_portal_ipv6_group_tag(void)
{
    TEST("iscsi_parse_portal: IPv6 [::1]:3260,2 strips tag");
    char host[256]; uint16_t port;
    int rc = iscsi_parse_portal("[::1]:3260,2", host, sizeof(host), &port);
    if (rc == 0 && strcmp(host, "::1") == 0 && port == 3260) PASS();
    else FAIL("IPv6 group tag stripping failed");
}

static void test_parse_portal_invalid_port(void)
{
    TEST("iscsi_parse_portal: invalid port → -1");
    char host[256]; uint16_t port;
    int rc = iscsi_parse_portal("10.0.0.1:99999", host, sizeof(host), &port);
    if (rc == -1) PASS(); else FAIL("expected -1 for out-of-range port");
}

/* -----------------------------------------------------------------------
 * Test: session_next_cid wraps correctly
 * ----------------------------------------------------------------------- */

static void test_cid_wrap(void)
{
    TEST("session_next_cid: wraps from 65535 → 1");

    iscsi_session_t *sess = make_sess();
    sess->next_cid = 65535;

    uint16_t cid1 = session_next_cid(sess);   /* 65535 */
    uint16_t cid2 = session_next_cid(sess);   /* wraps to 1 */

    if (cid1 != 65535) { FAIL("expected cid1=65535"); }
    else if (cid2 != 1) { FAIL("expected cid2=1 after wrap"); }
    else PASS();

    session_destroy(sess);
}

/* -----------------------------------------------------------------------
 * Test: session_wait_recovery — returns -1 on timeout
 * ----------------------------------------------------------------------- */

static void test_wait_recovery_timeout(void)
{
    TEST("session_wait_recovery: returns -1 when recovery never signals");

    iscsi_session_t *sess = make_sess();
    sess->state = SESS_STATE_LOGGED_IN;
    sess->recovery_in_progress = 1;   /* pretend recovery is stuck */

    /* Use a 1-second timeout so the test completes quickly. */
    int rc = session_wait_recovery(sess, 1);
    if (rc == -1) PASS();
    else          FAIL("expected -1 on timeout");

    /* Clean up: clear the flag so session_destroy doesn't block callers. */
    sess->recovery_in_progress = 0;
    session_destroy(sess);
}

/* -----------------------------------------------------------------------
 * Test: session_wait_recovery — returns 0 after session_signal_recovery
 * ----------------------------------------------------------------------- */

typedef struct {
    iscsi_session_t *sess;
} signal_arg_t;

static void *signal_thread(void *arg)
{
    signal_arg_t *a = arg;
    struct timespec ts = {0, 100000000};   /* 100 ms */
    nanosleep(&ts, NULL);
    /* Simulate recovery_thread completing successfully */
    a->sess->recovery_in_progress = 0;
    session_signal_recovery(a->sess);
    return NULL;
}

static void test_wait_recovery_signal(void)
{
    TEST("session_wait_recovery: returns 0 after signal_recovery");

    iscsi_session_t *sess = make_sess();
    sess->state = SESS_STATE_LOGGED_IN;
    sess->recovery_in_progress = 1;

    signal_arg_t arg = {.sess = sess};
    pthread_t tid;
    if (pthread_create(&tid, NULL, signal_thread, &arg) != 0) {
        FAIL("pthread_create");
        session_destroy(sess);
        return;
    }

    int rc = session_wait_recovery(sess, 5);
    pthread_join(tid, NULL);

    if (rc == 0) PASS();
    else         FAIL("expected 0 after signal");

    session_destroy(sess);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_recovery\n");

    test_snack_data_ack();
    test_snack_r2t();
    test_snack_status();
    test_itt_no_rsvd();
    test_cid_wrap();
    test_parse_portal_ipv4();
    test_parse_portal_ipv4_default_port();
    test_parse_portal_ipv6();
    test_parse_portal_ipv6_default_port();
    test_parse_portal_group_tag();
    test_parse_portal_ipv6_group_tag();
    test_parse_portal_invalid_port();
    test_wait_recovery_timeout();
    test_wait_recovery_signal();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
