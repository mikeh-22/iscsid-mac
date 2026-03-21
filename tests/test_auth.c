/*
 * test_auth.c - Unit tests for CHAP authentication
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/auth.h"
#include "../src/daemon/pdu.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define TEST(name) \
    do { printf("  %-50s", name); fflush(stdout); } while (0)
#define PASS()  printf("PASS\n")
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* -----------------------------------------------------------------------
 * Hex encode/decode
 * ----------------------------------------------------------------------- */

static void test_hex_roundtrip(void)
{
    TEST("chap_hex_encode / chap_hex_decode roundtrip");
    uint8_t src[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    char hex[40];
    chap_hex_encode(hex, sizeof(hex), src, 16);

    uint8_t dst[16];
    int n = chap_hex_decode(dst, sizeof(dst), hex);
    if (n != 16 || memcmp(src, dst, 16) != 0) {
        FAIL("roundtrip mismatch");
        return;
    }

    /* With 0x prefix stripped */
    n = chap_hex_decode(dst, sizeof(dst), "0123456789abcdef");
    if (n != 8) { FAIL("no-prefix decode length"); return; }
    PASS();
}

/* -----------------------------------------------------------------------
 * Known-answer test: RFC 1994 example
 *
 * The standard doesn't give a fixed test vector for MD5 CHAP, but we can
 * construct one manually:
 *   ID       = 0x42
 *   secret   = "secret"
 *   challenge = 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08  (8 bytes)
 *
 * Expected = MD5(0x42 || "secret" || challenge)
 *
 * Pre-computed: md5(\x42secret\x01\x02\x03\x04\x05\x06\x07\x08)
 *   = 8e 41 81 e5 e7 4d d4 17 d8 ea 15 1f f5 9f 73 72
 * ----------------------------------------------------------------------- */

static void test_chap_response(void)
{
    TEST("CHAP MD5 known-answer test");

    chap_ctx_t ctx;
    chap_init(&ctx, CHAP_ALG_MD5, "secret", NULL);
    ctx.identifier = 0x42;
    ctx.challenge[0] = 0x01; ctx.challenge[1] = 0x02;
    ctx.challenge[2] = 0x03; ctx.challenge[3] = 0x04;
    ctx.challenge[4] = 0x05; ctx.challenge[5] = 0x06;
    ctx.challenge[6] = 0x07; ctx.challenge[7] = 0x08;
    ctx.challenge_len = 8;

    char resp_hex[64];
    if (chap_compute_response(&ctx, resp_hex, sizeof(resp_hex)) != 0) {
        FAIL("compute_response failed");
        return;
    }

    /* Decode and check against known value.
     * Verified: echo -n | md5 where input is bytes 0x42 "secret" 0x01..0x08
     * = 150308aade721ab65a3d254de9c4a60f */
    uint8_t expected[16] = {
        0x15, 0x03, 0x08, 0xaa, 0xde, 0x72, 0x1a, 0xb6,
        0x5a, 0x3d, 0x25, 0x4d, 0xe9, 0xc4, 0xa6, 0x0f
    };
    uint8_t got[16];
    int n = chap_hex_decode(got, sizeof(got), resp_hex);
    if (n != 16 || memcmp(got, expected, 16) != 0) {
        FAIL("response mismatch");
        printf("     got: %s\n", resp_hex);
        return;
    }
    PASS();
}

/* -----------------------------------------------------------------------
 * Challenge parsing from key-value buffer
 * ----------------------------------------------------------------------- */

static void test_chap_parse_challenge(void)
{
    TEST("chap_parse_challenge from KV buffer");

    chap_ctx_t ctx;
    chap_init(&ctx, CHAP_ALG_MD5, "testsecret", NULL);

    /* Build a synthetic KV buffer as the target would send */
    char kv[512];
    int used = 0;
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_A", "5");    /* MD5 */
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_I", "200");
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_C",
                         "0x0102030405060708090a0b0c0d0e0f10");

    int rc = chap_parse_challenge(&ctx, kv, (uint32_t)used);
    if (rc != 0) { FAIL("parse_challenge failed"); return; }
    if (ctx.identifier != 200)      { FAIL("identifier wrong"); return; }
    if (ctx.challenge_len != 16)    { FAIL("challenge_len wrong"); return; }
    if (ctx.challenge[0] != 0x01)   { FAIL("challenge[0] wrong"); return; }
    if (ctx.challenge[15] != 0x10)  { FAIL("challenge[15] wrong"); return; }
    PASS();
}

/* -----------------------------------------------------------------------
 * Wrong algorithm rejected
 * ----------------------------------------------------------------------- */

static void test_chap_wrong_alg(void)
{
    TEST("chap_parse_challenge rejects wrong algorithm");

    chap_ctx_t ctx;
    chap_init(&ctx, CHAP_ALG_MD5, "secret", NULL);

    char kv[256];
    int used = 0;
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_A", "99"); /* bogus */
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_I", "1");
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_C", "0x01020304");

    int rc = chap_parse_challenge(&ctx, kv, (uint32_t)used);
    if (rc == -1) PASS();
    else          FAIL("should have rejected algorithm 99");
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("=== CHAP auth unit tests ===\n");
    test_hex_roundtrip();
    test_chap_response();
    test_chap_parse_challenge();
    test_chap_wrong_alg();

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
