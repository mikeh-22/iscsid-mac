/*
 * auth.c - CHAP authentication for iSCSI (RFC 1994 / RFC 7143)
 *
 * Uses CommonCrypto on macOS (no external dependencies).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Enable C11 Annex K (memset_s) */
#define __STDC_WANT_LIB_EXT1__ 1

#include "auth.h"
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pdu.h"

/*
 * secure_zero: guaranteed-not-elided memory wipe.
 * macOS exposes memset_s (C11 Annex K) but not secure_zero.
 */
static inline void secure_zero(void *buf, size_t len)
{
    memset_s(buf, len, 0, len);
}

/* -----------------------------------------------------------------------
 * Utility: hex encode / decode
 * ----------------------------------------------------------------------- */

void chap_hex_encode(char *dst, size_t dst_size,
                     const uint8_t *src, size_t src_len)
{
    if (dst_size < 3) return;
    dst[0] = '0';
    dst[1] = 'x';
    size_t i;
    for (i = 0; i < src_len && (i * 2 + 4) <= dst_size; i++) {
        snprintf(dst + 2 + i * 2, 3, "%02x", src[i]);
    }
}

int chap_hex_decode(uint8_t *dst, size_t dst_size, const char *hex_str)
{
    const char *p = hex_str;
    /* Skip optional "0x" or "0X" prefix */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    int count = 0;
    while (*p && *(p+1)) {
        if ((size_t)count >= dst_size) return -1;
        char byte_str[3] = { p[0], p[1], '\0' };
        char *end;
        long val = strtol(byte_str, &end, 16);
        if (end != byte_str + 2) return -1;
        dst[count++] = (uint8_t)val;
        p += 2;
    }
    return count;
}

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

void chap_init(chap_ctx_t *ctx, chap_alg_t alg,
               const char *initiator_secret,
               const char *target_secret)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->algorithm = alg;
    if (initiator_secret) {
        snprintf(ctx->initiator_secret, sizeof(ctx->initiator_secret),
                 "%s", initiator_secret);
    }
    if (target_secret) {
        snprintf(ctx->target_secret, sizeof(ctx->target_secret),
                 "%s", target_secret);
    }
}

/* -----------------------------------------------------------------------
 * Challenge parsing
 * ----------------------------------------------------------------------- */

int chap_parse_challenge(chap_ctx_t *ctx,
                          const char *kv_buf, uint32_t kv_len)
{
    /* Parse CHAP_A (algorithm must match) */
    uint32_t alg_num;
    if (pdu_kv_get_int(kv_buf, kv_len, "CHAP_A", &alg_num) != 0) {
        fprintf(stderr, "auth: missing CHAP_A\n");
        return -1;
    }
    if ((chap_alg_t)alg_num != ctx->algorithm) {
        fprintf(stderr, "auth: algorithm mismatch (got %u, want %u)\n",
                alg_num, (unsigned)ctx->algorithm);
        return -1;
    }

    /* Parse CHAP_I (identifier) */
    uint32_t chap_i;
    if (pdu_kv_get_int(kv_buf, kv_len, "CHAP_I", &chap_i) != 0) {
        fprintf(stderr, "auth: missing CHAP_I\n");
        return -1;
    }
    ctx->identifier = (uint8_t)chap_i;

    /* Parse CHAP_C (challenge, hex-encoded) */
    char chap_c_hex[CHAP_MAX_CHALLENGE_LEN * 2 + 4];
    if (pdu_kv_get_str(kv_buf, kv_len, "CHAP_C",
                       chap_c_hex, sizeof(chap_c_hex)) != 0) {
        fprintf(stderr, "auth: missing CHAP_C\n");
        return -1;
    }

    int n = chap_hex_decode(ctx->challenge, sizeof(ctx->challenge), chap_c_hex);
    if (n < 1) {
        fprintf(stderr, "auth: invalid CHAP_C encoding\n");
        return -1;
    }
    ctx->challenge_len = (size_t)n;
    return 0;
}

/* -----------------------------------------------------------------------
 * Response computation: CHAP-Response = H(ID || secret || challenge)
 * ----------------------------------------------------------------------- */

/* MD5 is deprecated on macOS but MANDATORY for iSCSI CHAP per RFC 7143 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static int chap_md5(const uint8_t id, const char *secret,
                    const uint8_t *challenge, size_t chal_len,
                    uint8_t *out)   /* out must be CC_MD5_DIGEST_LENGTH */
{
    CC_MD5_CTX ctx;
    CC_MD5_Init(&ctx);
    CC_MD5_Update(&ctx, &id, 1);
    CC_MD5_Update(&ctx, secret, strlen(secret));
    CC_MD5_Update(&ctx, challenge, chal_len);
    CC_MD5_Final(out, &ctx);
    return 0;
}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static int chap_sha256(const uint8_t id, const char *secret,
                       const uint8_t *challenge, size_t chal_len,
                       uint8_t *out) /* out must be CC_SHA256_DIGEST_LENGTH */
{
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, &id, 1);
    CC_SHA256_Update(&ctx, secret, strlen(secret));
    CC_SHA256_Update(&ctx, challenge, chal_len);
    CC_SHA256_Final(out, &ctx);
    return 0;
}
#pragma GCC diagnostic pop

int chap_compute_response(const chap_ctx_t *ctx,
                           char *resp_hex, size_t resp_hex_size)
{
    uint8_t digest[CHAP_MAX_RESPONSE_LEN];
    size_t  dlen;
    int     rc;

    switch (ctx->algorithm) {
    case CHAP_ALG_MD5:
        rc = chap_md5(ctx->identifier, ctx->initiator_secret,
                      ctx->challenge, ctx->challenge_len, digest);
        dlen = CC_MD5_DIGEST_LENGTH;
        break;
    case CHAP_ALG_SHA256:
        rc = chap_sha256(ctx->identifier, ctx->initiator_secret,
                         ctx->challenge, ctx->challenge_len, digest);
        dlen = CC_SHA256_DIGEST_LENGTH;
        break;
    default:
        return -1;
    }
    if (rc) return rc;

    chap_hex_encode(resp_hex, resp_hex_size, digest, dlen);

    /* Wipe the digest from the stack before returning */
    secure_zero(digest, sizeof(digest));
    return 0;
}

/* -----------------------------------------------------------------------
 * Mutual CHAP: we generate a challenge, target responds
 * ----------------------------------------------------------------------- */

int chap_generate_mutual_challenge(chap_ctx_t *ctx,
                                   char *chap_i_str, size_t chap_i_size,
                                   char *chap_c_hex, size_t chap_c_size)
{
    /* Generate a random challenge from /dev/urandom */
    uint8_t challenge[CHAP_MAX_CHALLENGE_LEN];
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) return -errno;
    size_t clen = (ctx->algorithm == CHAP_ALG_SHA256) ? 32 : 16;
    if (fread(challenge, 1, clen, fp) != clen) {
        fclose(fp);
        return -EIO;
    }
    fclose(fp);

    /* Generate a random identifier for this exchange */
    uint8_t mutual_id;
    fp = fopen("/dev/urandom", "rb");
    if (!fp) return -errno;
    if (fread(&mutual_id, 1, 1, fp) != 1) {
        fclose(fp);
        return -EIO;
    }
    fclose(fp);

    /* Store challenge so we can verify later */
    memcpy(ctx->challenge, challenge, clen);
    ctx->challenge_len = clen;
    /* Reuse identifier field for mutual id (we saved the inbound one earlier) */

    snprintf(chap_i_str, chap_i_size, "%u", (unsigned)mutual_id);
    chap_hex_encode(chap_c_hex, chap_c_size, challenge, clen);
    return 0;
}

int chap_verify_mutual(const chap_ctx_t *ctx,
                        uint8_t peer_id,
                        const char *response_hex)
{
    if (!ctx->target_secret[0]) return -1;  /* no mutual secret configured */

    uint8_t expected[CHAP_MAX_RESPONSE_LEN];
    size_t  elen;

    switch (ctx->algorithm) {
    case CHAP_ALG_MD5:
        chap_md5(peer_id, ctx->target_secret,
                 ctx->challenge, ctx->challenge_len, expected);
        elen = CC_MD5_DIGEST_LENGTH;
        break;
    case CHAP_ALG_SHA256:
        chap_sha256(peer_id, ctx->target_secret,
                    ctx->challenge, ctx->challenge_len, expected);
        elen = CC_SHA256_DIGEST_LENGTH;
        break;
    default:
        return -1;
    }

    uint8_t received[CHAP_MAX_RESPONSE_LEN];
    int rlen = chap_hex_decode(received, sizeof(received), response_hex);
    if (rlen < 0 || (size_t)rlen != elen) {
        secure_zero(expected, sizeof(expected));
        return -1;
    }

    /* Constant-time comparison — prevents timing side-channel */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < elen; i++) {
        diff |= expected[i] ^ received[i];
    }

    /* Wipe both buffers from the stack before returning */
    secure_zero(expected, sizeof(expected));
    secure_zero(received, sizeof(received));

    return (diff == 0) ? 0 : -1;
}

/*
 * Zero all secret material from a CHAP context.
 * Call after authentication completes (success or failure).
 */
void chap_clear(chap_ctx_t *ctx)
{
    secure_zero(ctx->initiator_secret, sizeof(ctx->initiator_secret));
    secure_zero(ctx->target_secret,    sizeof(ctx->target_secret));
    secure_zero(ctx->challenge,        sizeof(ctx->challenge));
}
