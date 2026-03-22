/*
 * test_async.c - Unit tests for async.c (NOP-In reply, ASYNC_MSG dispatch)
 *
 * Uses socketpairs to feed PDUs to conn_handle_incoming() / async_handle_event()
 * without a real network connection.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/async.h"
#include "../src/daemon/pdu.h"
#include "../src/daemon/session.h"
#include "../src/daemon/connection.h"
#include "../src/shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* Build a minimal session + connection backed by a socketpair. */
static iscsi_session_t *make_sess(void)
{
    iscsi_session_t *sess = session_create(SESS_TYPE_NORMAL,
                                           "iqn.2024-01.io.test:init",
                                           "iqn.2024-01.io.test:target",
                                           "127.0.0.1:3260");
    if (!sess) return NULL;
    sess->state = SESS_STATE_LOGGED_IN;
    sess->tsih  = 1;
    return sess;
}

/* Allocate a bare conn struct backed by fd (not via conn_create). */
static iscsi_conn_t *make_conn(int fd)
{
    iscsi_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd           = fd;
    c->state        = CONN_STATE_LOGGED_IN;
    c->cid          = 1;
    c->exp_statsn   = 1;
    c->max_send_dsl = 8192;
    return c;
}

/*
 * Send a raw PDU header (48 bytes) + optional data over fd using pdu_send().
 * Builds an iscsi_pdu_t from a pre-filled 48-byte header buffer.
 */
static int send_raw_pdu(int fd, const uint8_t hdr48[48],
                         const void *data, uint32_t data_len)
{
    iscsi_pdu_t pdu;
    memset(&pdu, 0, sizeof(pdu));
    memcpy(&pdu.hdr, hdr48, 48);
    if (data && data_len > 0) {
        pdu_set_data_ref(&pdu, data, data_len);
    }
    return pdu_send(fd, &pdu, 0, 0);
}

/* -----------------------------------------------------------------------
 * Test: unsolicited NOP-In (TTT=0xFFFFFFFF) → no reply
 * ----------------------------------------------------------------------- */

static void test_nop_in_unsolicited(void)
{
    TEST("NOP-In unsolicited (TTT=0xffffffff): no reply sent");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[1]);

    /* Build a NOP-In PDU with TTT = 0xFFFFFFFF (unsolicited ping) */
    uint8_t hdr[48] = {0};
    hdr[0] = ISCSI_OP_NOOP_IN | 0x80;   /* opcode + I-bit */
    hdr[1] = ISCSI_FLAG_FINAL;           /* F-bit */
    /* ITT = 0xFFFFFFFF */
    hdr[16] = 0xFF; hdr[17] = 0xFF; hdr[18] = 0xFF; hdr[19] = 0xFF;
    /* TTT = 0xFFFFFFFF (unsolicited) */
    hdr[20] = 0xFF; hdr[21] = 0xFF; hdr[22] = 0xFF; hdr[23] = 0xFF;
    /* StatSN = 1 */
    hdr[24] = 0x00; hdr[25] = 0x00; hdr[26] = 0x00; hdr[27] = 0x01;

    send_raw_pdu(sv[0], hdr, NULL, 0);

    int rc = conn_handle_incoming(sess, conn);

    /* Should return 0 (keep monitoring) */
    if (rc != 0) { FAIL("conn_handle_incoming returned non-zero"); goto done; }

    /* sv[0] read-end: there should be no NOP-Out reply sitting in the pipe */
    /* Set non-blocking to check */
    int flags_save = 0;
    {
        /* Use MSG_DONTWAIT on the recv to check for absence of reply */
        uint8_t buf[64];
        ssize_t n = recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) { FAIL("unexpected reply for unsolicited NOP-In"); goto done; }
    }
    (void)flags_save;

    PASS();
done:
    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: solicited NOP-In (TTT != 0xFFFFFFFF) → NOP-Out reply with same TTT
 * ----------------------------------------------------------------------- */

static void test_nop_in_solicited(void)
{
    TEST("NOP-In solicited (TTT=42): NOP-Out reply with TTT=42");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[1]);

    /* Build a NOP-In with TTT = 42 (solicited ping) */
    uint8_t hdr[48] = {0};
    hdr[0] = ISCSI_OP_NOOP_IN | 0x80;
    hdr[1] = ISCSI_FLAG_FINAL;
    /* ITT = 0xFFFFFFFF */
    hdr[16] = 0xFF; hdr[17] = 0xFF; hdr[18] = 0xFF; hdr[19] = 0xFF;
    /* TTT = 42 */
    hdr[20] = 0x00; hdr[21] = 0x00; hdr[22] = 0x00; hdr[23] = 0x2A;
    /* StatSN = 5 */
    hdr[24] = 0x00; hdr[25] = 0x00; hdr[26] = 0x00; hdr[27] = 0x05;

    send_raw_pdu(sv[0], hdr, NULL, 0);

    int rc = conn_handle_incoming(sess, conn);
    if (rc != 0) { FAIL("conn_handle_incoming returned non-zero"); goto done; }

    /*
     * Read the NOP-Out reply from sv[0].
     * pdu_send() writes a raw 48-byte iSCSI header — no length prefix.
     */
    uint8_t reply[48];
    {
        uint8_t *p = reply;
        size_t rem = 48;
        while (rem > 0) {
            ssize_t n = recv(sv[0], p, rem, 0);
            if (n <= 0) { FAIL("short reply read"); goto done; }
            p += n; rem -= (size_t)n;
        }
    }

    /* Check opcode = ISCSI_OP_NOOP_OUT */
    if ((reply[0] & 0x3f) != ISCSI_OP_NOOP_OUT) {
        FAIL("reply opcode not NOP-Out"); goto done;
    }
    /* Check TTT = 42 at bytes 20-23 */
    uint32_t got_ttt = ((uint32_t)reply[20] << 24) | ((uint32_t)reply[21] << 16) |
                       ((uint32_t)reply[22] << 8)  |  (uint32_t)reply[23];
    if (got_ttt != 42) { FAIL("TTT in NOP-Out reply != 42"); goto done; }

    /* Check ITT = 0xFFFFFFFF at bytes 16-19 */
    uint32_t got_itt = ((uint32_t)reply[16] << 24) | ((uint32_t)reply[17] << 16) |
                       ((uint32_t)reply[18] << 8)  |  (uint32_t)reply[19];
    if (got_itt != 0xFFFFFFFF) { FAIL("ITT in NOP-Out reply != 0xFFFFFFFF"); goto done; }

    PASS();
done:
    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: ASYNC_MSG event 0 (SCSI async) → returns 0
 * ----------------------------------------------------------------------- */

static void test_async_scsi_event(void)
{
    TEST("ASYNC_MSG event 0 (SCSI async): returns 0");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[1]);

    /* Build ASYNC_MSG PDU with async_event = 0 */
    uint8_t hdr[48] = {0};
    hdr[0] = ISCSI_OP_ASYNC_MSG | 0x80;
    hdr[1] = ISCSI_FLAG_FINAL;
    /* StatSN = 2 at bytes 24-27 */
    hdr[27] = 2;
    /* async_event at byte 36 = 0 */
    hdr[36] = ISCSI_ASYNC_SCSI_EVENT;

    send_raw_pdu(sv[0], hdr, NULL, 0);

    int rc = conn_handle_incoming(sess, conn);
    if (rc != 0) FAIL("expected 0 for SCSI async event");
    else PASS();

    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: ASYNC_MSG event 1 (logout request) → returns -1
 * ----------------------------------------------------------------------- */

static void test_async_logout_request(void)
{
    TEST("ASYNC_MSG event 1 (logout request): returns -1");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[1]);

    uint8_t hdr[48] = {0};
    hdr[0] = ISCSI_OP_ASYNC_MSG | 0x80;
    hdr[1] = ISCSI_FLAG_FINAL;
    hdr[27] = 3;   /* StatSN = 3 */
    /* async_event = 1 (logout request) at byte 36 */
    hdr[36] = ISCSI_ASYNC_LOGOUT_REQUEST;
    /* param2 = Time2Wait = 5 at bytes 40-41 */
    hdr[40] = 0x00; hdr[41] = 0x05;
    /* param3 = Time2Retain = 30 at bytes 42-43 */
    hdr[42] = 0x00; hdr[43] = 0x1E;

    send_raw_pdu(sv[0], hdr, NULL, 0);

    int rc = conn_handle_incoming(sess, conn);
    if (rc != -1) { FAIL("expected -1 for logout request"); goto done; }

    /* Verify Time2Wait was stored */
    if (sess->params.default_time2wait != 5) {
        FAIL("Time2Wait not stored in session params"); goto done;
    }

    PASS();
done:
    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: ASYNC_MSG event 3 (drop session) → session marked FAILED, returns -1
 * ----------------------------------------------------------------------- */

static void test_async_drop_session(void)
{
    TEST("ASYNC_MSG event 3 (drop session): session FAILED, returns -1");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[1]);

    uint8_t hdr[48] = {0};
    hdr[0] = ISCSI_OP_ASYNC_MSG | 0x80;
    hdr[1] = ISCSI_FLAG_FINAL;
    hdr[27] = 4;
    hdr[36] = ISCSI_ASYNC_DROP_SESSION;  /* event 3 */

    send_raw_pdu(sv[0], hdr, NULL, 0);

    int rc = conn_handle_incoming(sess, conn);
    if (rc != -1) { FAIL("expected -1 for drop session"); goto done; }
    if (sess->state != SESS_STATE_FAILED) { FAIL("session not marked FAILED"); goto done; }

    PASS();
done:
    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: connection EOF → conn_handle_incoming returns -1
 * ----------------------------------------------------------------------- */

static void test_conn_eof(void)
{
    TEST("conn_handle_incoming: EOF → returns -1");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair"); return;
    }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[1]);

    /* Close the writer end to simulate target closing the connection */
    close(sv[0]);
    sv[0] = -1;

    int rc = conn_handle_incoming(sess, conn);
    if (rc != -1) FAIL("expected -1 on EOF");
    else if (conn->state != CONN_STATE_FAILED) FAIL("conn not marked FAILED");
    else PASS();

    free(conn);
    session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_async\n");

    test_nop_in_unsolicited();
    test_nop_in_solicited();
    test_async_scsi_event();
    test_async_logout_request();
    test_async_drop_session();
    test_conn_eof();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
