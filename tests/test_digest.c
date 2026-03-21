/*
 * test_digest.c - Unit tests for CRC32C digest and digest-aware PDU I/O
 *
 * CRC32C known-answer vectors from RFC 3720 Appendix B.4.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/digest.h"
#include "../src/daemon/pdu.h"
#include "../src/shared/iscsi_protocol.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TEST(name) \
    do { printf("  %-54s", name); fflush(stdout); } while (0)
#define PASS()  printf("PASS\n")
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* -----------------------------------------------------------------------
 * CRC32C known-answer tests (RFC 3720 Appendix B.4)
 * ----------------------------------------------------------------------- */

static void test_crc32c_rfc_vectors(void)
{
    /* 32 bytes of zeros → 0xAA36918A */
    TEST("CRC32C: 32 zero bytes (RFC 3720 B.4)");
    {
        uint8_t buf[32];
        memset(buf, 0x00, sizeof(buf));
        uint32_t got = crc32c(buf, sizeof(buf));
        if (got == 0xAA36918Au) PASS();
        else FAIL("expected 0xAA36918A");
    }

    /* 32 bytes of 0xFF → 0x43ABA862 */
    TEST("CRC32C: 32 0xFF bytes (RFC 3720 B.4)");
    {
        uint8_t buf[32];
        memset(buf, 0xFF, sizeof(buf));
        uint32_t got = crc32c(buf, sizeof(buf));
        if (got == 0x43ABA862u) PASS();
        else FAIL("expected 0x43ABA862");
    }

    /* 32 bytes incrementing 0x00..0x1F → 0x4E79DD46 */
    TEST("CRC32C: 32 incrementing bytes (RFC 3720 B.4)");
    {
        uint8_t buf[32];
        for (int i = 0; i < 32; i++) buf[i] = (uint8_t)i;
        uint32_t got = crc32c(buf, sizeof(buf));
        if (got == 0x4E79DD46u) PASS();
        else FAIL("expected 0x4E79DD46");
    }
}

/* -----------------------------------------------------------------------
 * crc32c_extend: verify chaining produces the same result as one-shot
 * ----------------------------------------------------------------------- */

static void test_crc32c_extend(void)
{
    TEST("CRC32C: extend chains correctly");
    uint8_t buf[32];
    for (int i = 0; i < 32; i++) buf[i] = (uint8_t)i;

    uint32_t oneshot  = crc32c(buf, 32);
    uint32_t chained  = crc32c(buf, 16);
    chained = crc32c_extend(chained, buf + 16, 16);

    if (oneshot == chained) PASS();
    else FAIL("chained != one-shot");
}

/* -----------------------------------------------------------------------
 * PDU send/recv with both digests enabled
 * ----------------------------------------------------------------------- */

static void test_pdu_digest_roundtrip(void)
{
    TEST("pdu_send/recv with HeaderDigest + DataDigest");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        FAIL("socketpair");
        return;
    }

    iscsi_pdu_t tx;
    pdu_init(&tx, ISCSI_OP_NOOP_OUT, ISCSI_FLAG_FINAL);
    const char *payload = "CRC32C digest test payload";
    pdu_set_data_copy(&tx, payload, (uint32_t)strlen(payload));

    if (pdu_send(sv[0], &tx, 1, 1) != 0) {
        FAIL("pdu_send with digests failed");
        close(sv[0]); close(sv[1]);
        pdu_free_data(&tx);
        return;
    }

    iscsi_pdu_t rx;
    int rc = pdu_recv(sv[1], &rx, 1, 1);
    close(sv[0]); close(sv[1]);

    if (rc != 0) {
        FAIL("pdu_recv with digests failed");
        pdu_free_data(&tx);
        return;
    }

    if (rx.data_len != strlen(payload) ||
        memcmp(rx.data, payload, strlen(payload)) != 0) {
        FAIL("data mismatch after digest round-trip");
    } else {
        PASS();
    }

    pdu_free_data(&tx);
    pdu_free_data(&rx);
}

static void test_pdu_header_digest_only(void)
{
    TEST("pdu_send/recv with HeaderDigest only (no data)");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        FAIL("socketpair");
        return;
    }

    iscsi_pdu_t tx;
    pdu_init(&tx, ISCSI_OP_NOOP_OUT, ISCSI_FLAG_FINAL);
    /* No data segment */

    if (pdu_send(sv[0], &tx, 1, 0) != 0) {
        FAIL("pdu_send failed");
        close(sv[0]); close(sv[1]);
        return;
    }

    iscsi_pdu_t rx;
    int rc = pdu_recv(sv[1], &rx, 1, 0);
    close(sv[0]); close(sv[1]);

    if (rc != 0) FAIL("pdu_recv failed");
    else if (rx.data_len != 0) FAIL("unexpected data");
    else PASS();

    pdu_free_data(&rx);
}

static void test_pdu_digest_corruption_detected(void)
{
    TEST("pdu_recv detects corrupted header digest");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        FAIL("socketpair");
        return;
    }

    iscsi_pdu_t tx;
    pdu_init(&tx, ISCSI_OP_NOOP_OUT, ISCSI_FLAG_FINAL);

    /* Send with digests enabled, then manually corrupt the digest byte */
    if (pdu_send(sv[0], &tx, 1, 0) != 0) {
        FAIL("pdu_send failed");
        close(sv[0]); close(sv[1]);
        return;
    }
    close(sv[0]);

    /* Read the 48-byte header and 4-byte CRC from the peer side,
     * flip a bit in the CRC, then put the corrupted bytes on a new
     * socketpair so pdu_recv sees them. */
    uint8_t wire[52];
    ssize_t n = recv(sv[1], wire, sizeof(wire), MSG_WAITALL);
    close(sv[1]);

    if (n != 52) {
        FAIL("short read from socket");
        return;
    }

    wire[48] ^= 0xFF;   /* corrupt the header CRC */

    int sv2[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) < 0) {
        FAIL("socketpair2");
        return;
    }
    send(sv2[0], wire, 52, 0);
    close(sv2[0]);

    iscsi_pdu_t rx;
    int rc = pdu_recv(sv2[1], &rx, 1, 0);
    close(sv2[1]);
    pdu_free_data(&rx);

    if (rc == -EBADMSG) PASS();
    else FAIL("expected -EBADMSG on digest mismatch");
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("=== CRC32C digest unit tests ===\n");
    test_crc32c_rfc_vectors();
    test_crc32c_extend();
    test_pdu_digest_roundtrip();
    test_pdu_header_digest_only();
    test_pdu_digest_corruption_detected();

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
