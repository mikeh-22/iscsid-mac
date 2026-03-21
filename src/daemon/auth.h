/*
 * auth.h - CHAP authentication for iSCSI (RFC 1994 / RFC 7143)
 *
 * Supports CHAP with MD5 (mandatory) and SHA-256 (optional).
 * Mutual authentication (target also authenticates to initiator) is
 * implemented when a target_secret is supplied.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* Supported CHAP algorithms */
typedef enum {
    CHAP_ALG_MD5    = 5,    /* IANA algorithm number for CHAP with MD5 */
    CHAP_ALG_SHA256 = 7,    /* IANA algorithm number for CHAP with SHA-256 */
} chap_alg_t;

/* Maximum sizes */
#define CHAP_MAX_CHALLENGE_LEN  32      /* bytes */
#define CHAP_MD5_RESPONSE_LEN   16      /* bytes (MD5 digest) */
#define CHAP_SHA256_RESPONSE_LEN 32     /* bytes (SHA-256 digest) */
#define CHAP_MAX_RESPONSE_LEN   32      /* bytes */
#define CHAP_MAX_SECRET_LEN     256

/* CHAP context (initiator side) */
typedef struct {
    chap_alg_t  algorithm;
    uint8_t     identifier;         /* CHAP identifier from target */
    uint8_t     challenge[CHAP_MAX_CHALLENGE_LEN];
    size_t      challenge_len;
    char        initiator_secret[CHAP_MAX_SECRET_LEN];
    char        target_secret[CHAP_MAX_SECRET_LEN];     /* for mutual auth */
} chap_ctx_t;

/*
 * Initialise a CHAP context.
 * initiator_secret: our secret (must be ≥ 12 bytes per RFC 7143)
 * target_secret:    target's secret for mutual auth, or NULL to disable
 */
void chap_init(chap_ctx_t *ctx, chap_alg_t alg,
               const char *initiator_secret,
               const char *target_secret);

/*
 * Parse the target's CHAP challenge from text key-value data.
 * Expects keys: CHAP_A (algorithm), CHAP_I (identifier), CHAP_C (challenge).
 * Returns 0 on success, -1 on error.
 */
int chap_parse_challenge(chap_ctx_t *ctx,
                          const char *kv_buf, uint32_t kv_len);

/*
 * Compute the initiator CHAP response.
 * Fills resp_hex with a hex-encoded string suitable for CHAP_R key.
 * resp_hex must be at least (CHAP_MAX_RESPONSE_LEN*2 + 3) bytes.
 * Returns 0 on success, -1 on error.
 */
int chap_compute_response(const chap_ctx_t *ctx,
                           char *resp_hex, size_t resp_hex_size);

/*
 * Generate a challenge for mutual CHAP (we challenge the target).
 * Fills chap_i_str and chap_c_hex for inclusion in the login PDU.
 * Returns 0 on success, -1 on error.
 */
int chap_generate_mutual_challenge(chap_ctx_t *ctx,
                                   char *chap_i_str, size_t chap_i_size,
                                   char *chap_c_hex, size_t chap_c_size);

/*
 * Verify the target's mutual CHAP response.
 * response_hex: the hex string from CHAP_R in the target's login response.
 * Returns 0 if authentic, -1 if verification fails.
 */
int chap_verify_mutual(const chap_ctx_t *ctx,
                        uint8_t peer_id,
                        const char *response_hex);

/*
 * Zero all secret material in ctx (call after authentication completes).
 */
void chap_clear(chap_ctx_t *ctx);

/*
 * Utility: encode binary data as a hex string with "0x" prefix.
 * dst must be at least (src_len * 2 + 3) bytes.
 */
void chap_hex_encode(char *dst, size_t dst_size,
                     const uint8_t *src, size_t src_len);

/*
 * Utility: decode a hex string (with or without "0x" prefix) into binary.
 * Returns number of bytes decoded, or -1 on error.
 */
int  chap_hex_decode(uint8_t *dst, size_t dst_size, const char *hex_str);
