/*
 * test_scsi.c - Unit tests for SCSI command PDU construction and Data-In assembly
 *
 * Tests scsi_exec() by injecting synthesized target responses over a socketpair.
 * Covers:
 *   - SCSI Response with status GOOD (no data transfer)
 *   - Data-In with embedded status (S-bit)
 *   - Data-In split across multiple PDUs followed by SCSI Response
 *   - Write command: SCSI Response (no data transfer, InitialR2T=Yes)
 *   - CDB > 16 bytes rejected before any I/O
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/scsi.h"
#include "../src/daemon/pdu.h"
#include "../src/daemon/session.h"
#include "../src/daemon/connection.h"
#include "../src/shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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
    if (!s) return NULL;
    s->state = SESS_STATE_LOGGED_IN;
    s->tsih  = 1;
    /* Use defaults: InitialR2T=Yes, ImmediateData=Yes */
    s->params.initial_r2t       = 1;
    s->params.immediate_data    = 1;
    s->params.first_burst_length = 65536;
    s->params.max_burst_length   = 262144;
    return s;
}

static iscsi_conn_t *make_conn(int fd)
{
    iscsi_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd           = fd;
    c->state        = CONN_STATE_LOGGED_IN;
    c->cid          = 1;
    c->exp_statsn   = 0;
    c->max_send_dsl = 8192;
    c->max_recv_dsl = 262144;
    return c;
}

/*
 * Drain and discard one length-prefixed PDU from fd (the SCSI Command PDU
 * sent by scsi_exec to the "target" side of the socketpair).
 */
static int drain_one_pdu(int fd)
{
    uint8_t lbuf[4];
    ssize_t n = recv(fd, lbuf, 4, 0);
    if (n != 4) return -1;
    uint32_t total = ((uint32_t)lbuf[0] << 24) | ((uint32_t)lbuf[1] << 16) |
                     ((uint32_t)lbuf[2] << 8)  |  (uint32_t)lbuf[3];
    if (total == 0) return 0;
    uint8_t *tmp = malloc(total);
    if (!tmp) return -1;
    n = recv(fd, tmp, total, 0);
    free(tmp);
    return (n == (ssize_t)total) ? 0 : -1;
}

/* Read the SCSI Command PDU that scsi_exec sent and return the ITT */
static uint32_t drain_cmd_pdu_get_itt(int fd)
{
    uint8_t lbuf[4];
    ssize_t n = recv(fd, lbuf, 4, 0);
    if (n != 4) return 0xFFFFFFFF;
    uint32_t total = ((uint32_t)lbuf[0] << 24) | ((uint32_t)lbuf[1] << 16) |
                     ((uint32_t)lbuf[2] << 8)  |  (uint32_t)lbuf[3];
    if (total < 48) return 0xFFFFFFFF;
    uint8_t hdr[48];
    uint8_t *rest = malloc(total);
    if (!rest) return 0xFFFFFFFF;
    n = recv(fd, rest, total, 0);
    memcpy(hdr, rest, 48);
    free(rest);
    if (n != (ssize_t)total) return 0xFFFFFFFF;
    return ntohl(*(uint32_t *)(hdr + 16));
}

/*
 * Send a length-prefixed raw PDU (hdr48 + optional data) to fd.
 * This simulates the target sending a response back over the socket.
 */
static int send_raw_pdu(int fd, const uint8_t hdr48[48],
                          const uint8_t *data, uint32_t data_len)
{
    /* pdu_send uses its own length prefix; reuse it via iscsi_pdu_t */
    iscsi_pdu_t pdu;
    memset(&pdu, 0, sizeof(pdu));
    memcpy(&pdu.hdr, hdr48, 48);
    if (data && data_len)
        pdu_set_data_ref(&pdu, data, data_len);
    return pdu_send(fd, &pdu, 0, 0);
}

/* Build a minimal SCSI Response PDU header */
static void build_scsi_rsp(uint8_t hdr[48], uint32_t itt, uint8_t status,
                             uint32_t statsn, uint32_t expcmdsn, uint32_t maxcmdsn)
{
    memset(hdr, 0, 48);
    hdr[0] = ISCSI_OP_SCSI_RSP | 0x80;
    hdr[1] = ISCSI_FLAG_FINAL;
    /* response = 0 (command completed), status = status */
    hdr[2]  = 0x00;                    /* response */
    hdr[3]  = status;
    /* ITT at bytes 16-19 */
    *(uint32_t *)(hdr + 16) = htonl(itt);
    /* StatSN, ExpCmdSN, MaxCmdSN */
    *(uint32_t *)(hdr + 24) = htonl(statsn);
    *(uint32_t *)(hdr + 28) = htonl(expcmdsn);
    *(uint32_t *)(hdr + 32) = htonl(maxcmdsn);
}

/* Build a Data-In PDU header */
static void build_data_in(uint8_t hdr[48], uint32_t itt, uint32_t datasn,
                            uint32_t bufoffset, uint32_t datalen,
                            int final, int has_status, uint8_t status,
                            uint32_t statsn)
{
    memset(hdr, 0, 48);
    hdr[0] = ISCSI_OP_SCSI_DATA_IN | 0x80;
    uint8_t flags = 0;
    if (final)      flags |= ISCSI_FLAG_FINAL;
    if (has_status) flags |= 0x01;   /* S-bit */
    hdr[1] = flags;
    hdr[3] = status;

    /* Data length in bytes 5-7 (big-endian 3 bytes) */
    iscsi_dlength_set(hdr + 5, datalen);

    *(uint32_t *)(hdr + 16) = htonl(itt);
    *(uint32_t *)(hdr + 24) = htonl(statsn);
    *(uint32_t *)(hdr + 28) = htonl(datasn);
    *(uint32_t *)(hdr + 40) = htonl(bufoffset);
}

/* -----------------------------------------------------------------------
 * Test: CDB > 16 bytes rejected immediately, no I/O
 * ----------------------------------------------------------------------- */

static void test_cdb_too_long(void)
{
    TEST("scsi_exec: CDB > 16 bytes → -1 (no I/O)");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    uint8_t lun[8]  = {0};
    uint8_t cdb[17] = {0};  /* 17 bytes — too long */

    int rc = scsi_exec(sess, conn, lun, cdb, 17, SCSI_DIR_NONE, NULL, 0, NULL, NULL);
    if (rc != -1) FAIL("expected -1 for oversized CDB");
    else PASS();

    /* Verify nothing was written to sv[1] */
    uint8_t buf[4];
    ssize_t n = recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT);
    if (n > 0) FAIL("unexpected data sent to socket for oversized CDB");

    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: no-data command → SCSI Response GOOD
 * ----------------------------------------------------------------------- */

static void test_no_data_good(void)
{
    TEST("scsi_exec: no-data cmd, SCSI Rsp GOOD → returns 0");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    /* Will run scsi_exec in a thread-like pattern: we must interleave */
    /* Actually, we'll use a forked helper approach: fork() a child that
     * acts as the "target" on sv[1], while parent calls scsi_exec on sv[0]. */

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); goto done_fds; }

    if (pid == 0) {
        /* Child: target side */
        close(sv[0]);
        /* Read the SCSI Command PDU */
        uint32_t itt = drain_cmd_pdu_get_itt(sv[1]);
        /* Send back SCSI Response GOOD */
        uint8_t hdr[48];
        build_scsi_rsp(hdr, itt, SCSI_STATUS_GOOD, 1, 2, 4);
        send_raw_pdu(sv[1], hdr, NULL, 0);
        close(sv[1]);
        _exit(0);
    }

    /* Parent: initiator */
    close(sv[1]);
    sv[1] = -1;

    uint8_t lun[8] = {0};
    uint8_t cdb[6] = {0x00, 0,0,0,0,0};  /* TEST UNIT READY */

    int rc = scsi_exec(sess, conn, lun, cdb, 6, SCSI_DIR_NONE, NULL, 0, NULL, NULL);
    int failed = 0;
    if (rc != 0) { FAIL("expected GOOD (0)"); failed = 1; }

    int status;
    waitpid(pid, &status, 0);
    if (!failed) PASS();

done_fds:
    free(conn);
    session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: read command → Data-In with S-bit (embedded status)
 * ----------------------------------------------------------------------- */

static void test_read_data_in_s_bit(void)
{
    TEST("scsi_exec: read, Data-In with S-bit → data received, status 0");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    static const uint8_t payload[16] = {
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10,
    };

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); goto done_fds; }

    if (pid == 0) {
        close(sv[0]);
        uint32_t itt = drain_cmd_pdu_get_itt(sv[1]);
        /* Send Data-In with F-bit + S-bit, 16 bytes, status=GOOD */
        uint8_t hdr[48];
        build_data_in(hdr, itt, /*datasn=*/0, /*offset=*/0, 16,
                       /*final=*/1, /*has_status=*/1, SCSI_STATUS_GOOD, /*statsn=*/1);
        send_raw_pdu(sv[1], hdr, payload, 16);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    sv[1] = -1;

    uint8_t lun[8] = {0};
    uint8_t cdb[10] = {0x28, 0,0,0,0,0,0,0,1,0};  /* READ(10) 1 block */
    uint8_t buf[16] = {0};
    uint32_t inlen = 16;

    int rc = scsi_exec(sess, conn, lun, cdb, 10, SCSI_DIR_READ,
                        NULL, 0, buf, &inlen);

    int failed = 0;
    if (rc != 0) { FAIL("expected status GOOD (0)"); failed = 1; }
    else if (inlen != 16) { FAIL("expected 16 bytes received"); failed = 1; }
    else if (memcmp(buf, payload, 16) != 0) { FAIL("data content mismatch"); failed = 1; }

    int status;
    waitpid(pid, &status, 0);
    if (!failed) PASS();

done_fds:
    free(conn);
    session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: read split into two Data-In PDUs, then SCSI Response
 * ----------------------------------------------------------------------- */

static void test_read_split_data_in(void)
{
    TEST("scsi_exec: read split Data-In (2 PDUs) + SCSI Rsp");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); goto done_fds; }

    if (pid == 0) {
        close(sv[0]);
        uint32_t itt = drain_cmd_pdu_get_itt(sv[1]);

        uint8_t hdr[48];
        /* First Data-In: bytes 0-7, not final */
        uint8_t d1[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
        build_data_in(hdr, itt, 0, 0, 8,
                       /*final=*/0, /*has_status=*/0, 0, 1);
        send_raw_pdu(sv[1], hdr, d1, 8);

        /* Second Data-In: bytes 8-15, final, no status */
        uint8_t d2[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11};
        build_data_in(hdr, itt, 1, 8, 8,
                       /*final=*/1, /*has_status=*/0, 0, 2);
        send_raw_pdu(sv[1], hdr, d2, 8);

        /* SCSI Response */
        build_scsi_rsp(hdr, itt, SCSI_STATUS_GOOD, 3, 2, 4);
        send_raw_pdu(sv[1], hdr, NULL, 0);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    sv[1] = -1;

    uint8_t lun[8] = {0};
    uint8_t cdb[10] = {0x28, 0,0,0,0,0,0,0,1,0};
    uint8_t buf[16] = {0};
    uint32_t inlen = 16;

    int rc = scsi_exec(sess, conn, lun, cdb, 10, SCSI_DIR_READ,
                        NULL, 0, buf, &inlen);

    uint8_t expected[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                              0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11};
    int failed = 0;
    if (rc != 0) { FAIL("expected status GOOD"); failed = 1; }
    else if (inlen != 16) { FAIL("expected inlen=16"); failed = 1; }
    else if (memcmp(buf, expected, 16) != 0) { FAIL("data mismatch"); failed = 1; }

    int status;
    waitpid(pid, &status, 0);
    if (!failed) PASS();

done_fds:
    free(conn);
    session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: SCSI Response with non-zero status propagated
 * ----------------------------------------------------------------------- */

static void test_check_condition(void)
{
    TEST("scsi_exec: SCSI Rsp CHECK_CONDITION (0x02) returned");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); goto done_fds; }

    if (pid == 0) {
        close(sv[0]);
        uint32_t itt = drain_cmd_pdu_get_itt(sv[1]);
        uint8_t hdr[48];
        build_scsi_rsp(hdr, itt, SCSI_STATUS_CHECK_CONDITION, 1, 2, 4);
        send_raw_pdu(sv[1], hdr, NULL, 0);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    sv[1] = -1;

    uint8_t lun[8] = {0};
    uint8_t cdb[6] = {0x00};
    int rc = scsi_exec(sess, conn, lun, cdb, 6, SCSI_DIR_NONE, NULL, 0, NULL, NULL);

    int failed = 0;
    if (rc != SCSI_STATUS_CHECK_CONDITION) {
        FAIL("expected CHECK_CONDITION (0x02)"); failed = 1;
    }

    int st;
    waitpid(pid, &st, 0);
    if (!failed) PASS();

done_fds:
    free(conn);
    session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

/* -----------------------------------------------------------------------
 * Test: scsi_sync_cache10 — issues SYNCHRONIZE CACHE(10) and returns 0
 * ----------------------------------------------------------------------- */

static void test_sync_cache10(void)
{
    TEST("scsi_sync_cache10: sends 0x35 CDB, returns 0 on GOOD");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);

    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); goto done_fds; }

    if (pid == 0) {
        /* Child: read the SCSI Command PDU, verify CDB opcode, send GOOD. */
        close(sv[0]);

        /*
         * pdu_send writes the raw 48-byte iSCSI header with no length prefix.
         * Read the full header in a loop to handle partial recv().
         */
        uint8_t hdr[48];
        ssize_t got = 0;
        while (got < 48) {
            ssize_t r = recv(sv[1], hdr + got, (size_t)(48 - got), 0);
            if (r <= 0) _exit(1);
            got += r;
        }

        uint32_t itt = ntohl(*(uint32_t *)(hdr + 16));

        /* CDB starts at byte 32 in the SCSI Command PDU BHS */
        if (hdr[32] != 0x35) _exit(2);   /* wrong opcode */

        /* Send SCSI Response GOOD */
        uint8_t rsp[48];
        build_scsi_rsp(rsp, itt, SCSI_STATUS_GOOD, 1, 2, 4);
        send_raw_pdu(sv[1], rsp, NULL, 0);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    sv[1] = -1;

    uint8_t lun[8] = {0};
    int rc = scsi_sync_cache10(sess, conn, lun);

    int failed = 0;
    if (rc != 0) { FAIL("expected 0 (GOOD)"); failed = 1; }

    int st;
    waitpid(pid, &st, 0);
    if (!failed) {
        /* Child exits 0 on success, 2 if wrong opcode */
        if (WIFEXITED(st) && WEXITSTATUS(st) == 2)
            FAIL("child saw wrong CDB opcode (expected 0x35)");
        else if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            FAIL("child exited with error");
        else
            PASS();
    }

done_fds:
    free(conn);
    session_destroy(sess);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_scsi\n");

    test_cdb_too_long();
    test_no_data_good();
    test_read_data_in_s_bit();
    test_read_split_data_in();
    test_check_condition();
    test_sync_cache10();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
