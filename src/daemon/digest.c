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
 * SPDX-License-Identifier: Apache-2.0
 */

#include "digest.h"

#include <arm_acle.h>
#include <string.h>

/*
 * Run bytes through the hardware CRC engine.
 * crc is the raw accumulator (NOT pre-inverted).
 */
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

uint32_t crc32c(const void *buf, size_t len)
{
    /*
     * The ARM CRC32C accumulator, when read as a little-endian uint32, has
     * its bytes in the reverse order from the RFC 3720 convention.  Apply
     * __builtin_bswap32 so that crc32c() returns the standard value (e.g.
     * 32 zero bytes → 0xAA36918A per RFC 3720 Appendix B.4).
     */
    return __builtin_bswap32(crc32c_update(0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu);
}

uint32_t crc32c_extend(uint32_t crc, const void *buf, size_t len)
{
    /*
     * crc is in the RFC/bswapped convention.  Undo the bswap and final XOR,
     * feed more bytes through the hardware, re-apply both.
     */
    return __builtin_bswap32(
        crc32c_update(__builtin_bswap32(crc) ^ 0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu
    );
}
