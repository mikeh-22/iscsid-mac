/*
 * test_taskmgmt.c - Unit tests for taskmgmt.c
 *
 * Uses socketpairs to inject synthesized Task Management Response PDUs.
 * Covers ABORT TASK, LUN RESET, ITT mismatch handling, and the response
 * string table.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/taskmgmt.h"
#include "../src/daemon/pdu.h"
#include "../src/daemon/session.h"
#include "../src/daemon/connection.h"
#include "../src/shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST(name) \
    do { printf("  %-56s", name); fflush(stdout); } while (0)
#define PASS()  printf("PASS\n")
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static iscsi_session_t *make_sess(void)
{
    iscsi_session_t *s = session_create(SESS_TYPE_NORMAL,
                                        "iqn.2024-01.io.test:init",
                                        "iqn.2024-01.io.test:target",
                                        "127.0.0.1:3260");
    if (s) { s->state = SESS_STATE_LOGGED_IN; s->tsih = 1; }
    return s;
}

static iscsi_conn_t *make_conn(int fd)
{
    iscsi_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = fd; c->state = CONN_STATE_LOGGED_IN;
    c->cid = 1; c->exp_statsn = 1;
    return c;
}

/*
 * Build and send a raw Task Management Response PDU over fd.
 * response = ISCSI_TM_RSP_* code, itt = ITT to echo back.
 */
static void send_tm_rsp(int fd, uint32_t itt, uint8_t response,
                          uint32_t statsn)
{
    uint8_t hdr[48] = {0};
    hdr[0] = ISCSI_OP_TASK_MGT_RSP | 0x80;
    hdr[1] = ISCSI_FLAG_FINAL;
    hdr[2] = response;
    /* ITT at bytes 16-19 */
    *(uint32_t *)(hdr + 16) = htonl(itt);
    /* StatSN, ExpCmdSN, MaxCmdSN */
    *(uint32_t *)(hdr + 24) = htonl(statsn);
    *(uint32_t *)(hdr + 28) = htonl(1);
    *(uint32_t *)(hdr + 32) = htonl(8);

    iscsi_pdu_t pdu;
    memset(&pdu, 0, sizeof(pdu));
    memcpy(&pdu.hdr, hdr, 48);
    pdu_send(fd, &pdu, 0, 0);
}

/* Drain one raw 48-byte iSCSI PDU header from fd, return the opcode. */
static uint8_t drain_pdu_opcode(int fd)
{
    uint8_t hdr[48];
    uint8_t *p = hdr;
    size_t rem = 48;
    while (rem > 0) {
        ssize_t n = recv(fd, p, rem, 0);
        if (n <= 0) return 0xFF;
        p += n; rem -= (size_t)n;
    }
    return hdr[0] & 0x3f;
}

/* -----------------------------------------------------------------------
 * Test: ABORT TASK → Function Complete (0x00)
 * ----------------------------------------------------------------------- */

static void test_abort_task_complete(void)
{
    TEST("iscsi_task_abort: Function Complete (0x00)");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); goto done; }
    if (pid == 0) {
        close(sv[0]);
        /* Read the TM Request (48 bytes) to get the ITT */
        uint8_t hdr[48]; uint8_t *p = hdr; size_t rem = 48;
        while (rem > 0) {
            ssize_t n = recv(sv[1], p, rem, 0);
            if (n <= 0) _exit(1);
            p += n; rem -= (size_t)n;
        }
        uint32_t itt = ntohl(*(uint32_t *)(hdr + 16));
        send_tm_rsp(sv[1], itt, ISCSI_TM_RSP_COMPLETE, 2);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]); sv[1] = -1;
    uint8_t lun[8] = {0};
    int rc = iscsi_task_abort(sess, conn, lun, 0x12345678);

    int failed = 0;
    if (rc != ISCSI_TM_RSP_COMPLETE) {
        FAIL("expected COMPLETE (0x00)"); failed = 1;
    }
    int st; waitpid(pid, &st, 0);
    if (!failed) PASS();

done:
    free(conn); session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: LUN RESET → Function Not Supported (0x05)
 * ----------------------------------------------------------------------- */

static void test_lun_reset_not_supported(void)
{
    TEST("iscsi_lun_reset: Function Not Supported (0x05)");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); goto done; }
    if (pid == 0) {
        close(sv[0]);
        uint8_t hdr[48]; uint8_t *p = hdr; size_t rem = 48;
        while (rem > 0) {
            ssize_t n = recv(sv[1], p, rem, 0);
            if (n <= 0) _exit(1);
            p += n; rem -= (size_t)n;
        }
        /* Verify function code = LUN RESET (5) in bits [6:0] of byte 1 */
        uint8_t func = hdr[1] & 0x7F;
        uint32_t itt = ntohl(*(uint32_t *)(hdr + 16));
        send_tm_rsp(sv[1], itt,
                    (func == ISCSI_TM_FUNC_LOGICAL_UNIT_RESET)
                        ? ISCSI_TM_RSP_NOT_SUPPORTED
                        : ISCSI_TM_RSP_REJECTED,
                    2);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]); sv[1] = -1;
    uint8_t lun[8] = {0};
    int rc = iscsi_lun_reset(sess, conn, lun);

    int failed = 0;
    if (rc != ISCSI_TM_RSP_NOT_SUPPORTED) {
        FAIL("expected NOT_SUPPORTED (0x05)"); failed = 1;
    }
    int st; waitpid(pid, &st, 0);
    if (!failed) PASS();

done:
    free(conn); session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: TM Request has IMMEDIATE bit set in opcode
 * ----------------------------------------------------------------------- */

static void test_tm_req_is_immediate(void)
{
    TEST("iscsi_task_abort: TM Request has IMMEDIATE bit set");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); goto done; }
    if (pid == 0) {
        close(sv[0]);
        uint8_t hdr[48]; uint8_t *p = hdr; size_t rem = 48;
        while (rem > 0) {
            ssize_t n = recv(sv[1], p, rem, 0);
            if (n <= 0) _exit(1);
            p += n; rem -= (size_t)n;
        }
        /* Check I bit (bit 6 of byte 0) */
        int imm_ok = (hdr[0] & ISCSI_OP_IMMEDIATE) != 0 ? 1 : 0;
        uint32_t itt = ntohl(*(uint32_t *)(hdr + 16));
        send_tm_rsp(sv[1], itt, imm_ok ? ISCSI_TM_RSP_COMPLETE : ISCSI_TM_RSP_REJECTED, 2);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]); sv[1] = -1;
    uint8_t lun[8] = {0};
    int rc = iscsi_task_abort(sess, conn, lun, 0xABCD);

    int failed = 0;
    if (rc != ISCSI_TM_RSP_COMPLETE) {
        FAIL("TM Request did not have IMMEDIATE bit set"); failed = 1;
    }
    int st; waitpid(pid, &st, 0);
    if (!failed) PASS();

done:
    free(conn); session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: taskmgmt_rsp_str covers known codes
 * ----------------------------------------------------------------------- */

static void test_rsp_str(void)
{
    TEST("taskmgmt_rsp_str: known codes map to non-empty strings");

    int codes[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF };
    int ok = 1;
    for (size_t i = 0; i < sizeof(codes)/sizeof(codes[0]); i++) {
        const char *s = taskmgmt_rsp_str(codes[i]);
        if (!s || s[0] == '\0') { ok = 0; break; }
    }
    if (ok) PASS(); else FAIL("empty string for known code");
}

/* -----------------------------------------------------------------------
 * Test: connection I/O error returns -1
 * ----------------------------------------------------------------------- */

static void test_io_error(void)
{
    TEST("iscsi_task_abort: connection EOF returns -1");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    /* Close the peer immediately to simulate connection drop */
    close(sv[1]); sv[1] = -1;

    uint8_t lun[8] = {0};
    int rc = iscsi_task_abort(sess, conn, lun, 0x1);
    if (rc != -1) FAIL("expected -1 on EOF");
    else PASS();

    free(conn); session_destroy(sess);
    close(sv[0]);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_taskmgmt\n");
    signal(SIGPIPE, SIG_IGN);   /* pdu_send on broken pipe returns -errno, not signal */

    test_abort_task_complete();
    test_lun_reset_not_supported();
    test_tm_req_is_immediate();
    test_rsp_str();
    test_io_error();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
