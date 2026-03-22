/*
 * digest.c - CRC32C for iSCSI header/data digests
 *
 * Uses ARMv8 CRC32C hardware instructions:
 *   __crc32cd  - 8-byte step
 *   __crc32cw  - 4-byte step
 *   __crc32ch  - 2-byte step
 *   __crc32cb  - 1-byte step
 *
 * All Apple Silicon processors (M1 and later) implement the ARMv8.4-A CRC
 * extension.  The instructions are exposed via <arm_acle.h> with no runtime
 * feature check required.
 *
 * Wire format (RFC 7143 §6.7): the 32-bit CRC value is transmitted in
 * network byte order (big-endian) immediately after the header or padded
 * data segment.  Callers must htonl() before sending and ntohl() before
 * comparing.
 *
 * Performance: for buffers >= 8 KiB a 3-way interleaved accumulator loop
 * hides the 3-cycle CRC32CX latency on Apple Silicon, achieving ~3×
 * throughput.  Chunks are recombined with GF(2) matrix-vector arithmetic
 * (the same approach as zlib's crc32_combine / Linux crc32c_combine).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "digest.h"

#include <arm_acle.h>
#include <pthread.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * Single-chain CRC32C update (scalar path for small buffers and tails)
 * ----------------------------------------------------------------------- */

static uint32_t crc32c_update(uint32_t crc, const void *buf, size_t len)
{
    const uint8_t *p = buf;

    /* Consume 8 bytes at a time — most efficient on 64-bit ARM */
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, p, 8);   /* memcpy avoids strict aliasing UB */
        crc = __crc32cd(crc, v);
        p += 8; len -= 8;
    }
    if (len >= 4) {
        uint32_t v;
        memcpy(&v, p, 4);
        crc = __crc32cw(crc, v);
        p += 4; len -= 4;
    }
    if (len >= 2) {
        uint16_t v;
        memcpy(&v, p, 2);
        crc = __crc32ch(crc, v);
        p += 2; len -= 2;
    }
    if (len)
        crc = __crc32cb(crc, *p);

    return crc;
}

/* -----------------------------------------------------------------------
 * GF(2) matrix machinery for combining 3 independent CRC accumulators
 *
 * crc_shift_raw(crc, n) computes the CRC accumulator value you would get
 * by appending n zero bytes to a message whose running (raw, not bswapped)
 * CRC accumulator is `crc`.  Equivalently, it applies the GF(2) linear map
 * M^n to `crc`, where M is the 32×32 bit-matrix for one zero-byte CRC step.
 *
 * This allows combining three independently computed CRC chains over
 * consecutive buffer segments A, B, C (each N8 bytes):
 *
 *   CRC(A || B || C, init) = shift(crc_A, 2·N8) ^ shift(crc_B, N8) ^ crc_C
 *
 * where crc_A started at `init` and crc_B, crc_C started at 0.
 *
 * Derivation: the CRC hardware function is linear over GF(2) in the initial
 * state — f*(s, M) = crc_shift_raw(s, |M|) ^ f*(0, M).  Substituting
 * s = crc_A, M = B, then continuing for C yields the formula above.
 *
 * Reference: same math as zlib crc32_combine() and Linux crc32c_combine().
 * ----------------------------------------------------------------------- */

/* Apply a 32×32 GF(2) matrix (rows stored as uint32_t) to a column vector. */
static uint32_t gf2_mat_vec(const uint32_t mat[32], uint32_t vec)
{
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        if (vec & 1u) r ^= mat[i];
        vec >>= 1;
    }
    return r;
}

/*
 * Precomputed table: gf2_pow2[k] = M^(2^k).
 * Built lazily via pthread_once; 32×32×4 = 4 KiB in BSS.
 */
static uint32_t       gf2_pow2[32][32];
static pthread_once_t gf2_once = PTHREAD_ONCE_INIT;

static void gf2_init_impl(void)
{
    /*
     * gf2_pow2[0] = M^1: row i is the accumulator that results from
     * processing one zero byte starting from state (1 << i).
     */
    const uint8_t z = 0;
    for (int i = 0; i < 32; i++)
        gf2_pow2[0][i] = crc32c_update(1u << i, &z, 1);

    /*
     * gf2_pow2[k] = gf2_pow2[k-1] squared: each row of the new matrix is
     * the previous matrix applied to the previous matrix's own row.
     */
    for (int k = 1; k < 32; k++) {
        const uint32_t *prev = gf2_pow2[k - 1];
        uint32_t       *cur  = gf2_pow2[k];
        for (int i = 0; i < 32; i++)
            cur[i] = gf2_mat_vec(prev, prev[i]);
    }
}

/*
 * Shift a raw CRC accumulator by n zero bytes: result = M^n * crc.
 * Decomposes n in binary and multiplies by the corresponding gf2_pow2[k]
 * entries — at most 32 matrix-vector products of 32 iterations each.
 */
static uint32_t crc_shift_raw(uint32_t crc, size_t n)
{
    pthread_once(&gf2_once, gf2_init_impl);
    for (int k = 0; n; k++, n >>= 1) {
        if (n & 1u)
            crc = gf2_mat_vec(gf2_pow2[k], crc);
    }
    return crc;
}

/* -----------------------------------------------------------------------
 * 3-way interleaved CRC32C for large buffers
 *
 * Apple Silicon M-series: CRC32CX throughput = 1/cycle, latency = 3 cycles.
 * A single accumulator chain is latency-bound (~2.7 B/cycle).  Three
 * independent chains let the CPU overlap three in-flight instructions,
 * approaching throughput saturation (~8 B/cycle, roughly 3× improvement).
 *
 * Only called when len >= CRC3_THRESHOLD; below that the GF(2) combining
 * overhead (two matrix-vector products) exceeds the latency-hiding benefit.
 * ----------------------------------------------------------------------- */

#define CRC3_THRESHOLD 8192u

static uint32_t crc32c_bulk(uint32_t crc, const uint8_t *p, size_t len)
{
    /*
     * Split into three N8-byte chunks (N8 = floor(len/3) rounded down to a
     * multiple of 8) plus a scalar tail of at most 23 bytes.
     */
    const size_t N8   = (len / 3) & ~(size_t)7;
    const size_t tail = len - 3 * N8;

    uint32_t crc0 = crc, crc1 = 0, crc2 = 0;
    const uint8_t *p1 = p  + N8;
    const uint8_t *p2 = p1 + N8;

    /* Bulk: three independent 8-byte chains — CPU overlaps their latencies */
    for (size_t i = 0; i < N8; i += 8) {
        uint64_t v0, v1, v2;
        memcpy(&v0, p  + i, 8);
        memcpy(&v1, p1 + i, 8);
        memcpy(&v2, p2 + i, 8);
        crc0 = __crc32cd(crc0, v0);
        crc1 = __crc32cd(crc1, v1);
        crc2 = __crc32cd(crc2, v2);
    }

    /*
     * Merge the three raw accumulators:
     *   CRC(A || B || C, init) = shift(crc0, 2·N8) ^ shift(crc1, N8) ^ crc2
     */
    crc = crc_shift_raw(crc0, 2 * N8)
        ^ crc_shift_raw(crc1,     N8)
        ^ crc2;

    /* Scalar tail: at most floor(len/3)%8 * 3 + len%3 <= 23 bytes */
    return crc32c_update(crc, p2 + N8, tail);
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

uint32_t crc32c(const void *buf, size_t len)
{
    /*
     * The ARM CRC32C accumulator, when read as a little-endian uint32, has
     * its bytes in the reverse order from the RFC 3720 convention.  Apply
     * __builtin_bswap32 so that crc32c() returns the standard value (e.g.
     * 32 zero bytes → 0xAA36918A per RFC 3720 Appendix B.4).
     */
    uint32_t crc = (len >= CRC3_THRESHOLD)
        ? crc32c_bulk(0xFFFFFFFFu, (const uint8_t *)buf, len)
        : crc32c_update(0xFFFFFFFFu, buf, len);
    return __builtin_bswap32(crc ^ 0xFFFFFFFFu);
}

uint32_t crc32c_extend(uint32_t crc, const void *buf, size_t len)
{
    /*
     * crc is in the RFC/bswapped convention.  Undo the bswap and final XOR,
     * feed more bytes through the hardware, re-apply both.
     */
    uint32_t raw = __builtin_bswap32(crc) ^ 0xFFFFFFFFu;
    raw = (len >= CRC3_THRESHOLD)
        ? crc32c_bulk(raw, (const uint8_t *)buf, len)
        : crc32c_update(raw, buf, len);
    return __builtin_bswap32(raw ^ 0xFFFFFFFFu);
}
