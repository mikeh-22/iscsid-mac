/*
 * digest.h - CRC32C computation for iSCSI header and data digests (RFC 7143 §6.7)
 *
 * Uses ARMv8 hardware CRC32C instructions (available on all Apple Silicon).
 * The polynomial is 0x1EDC6F41 (Castagnoli); initial and final XOR are 0xFFFFFFFF.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Compute CRC32C over buf[0..len-1].
 * Returns the 32-bit checksum.
 */
uint32_t crc32c(const void *buf, size_t len);

/*
 * Extend an existing CRC32C value with more data.
 * Allows chaining multiple buffers without concatenating them first:
 *
 *   uint32_t crc = crc32c(data, data_len);
 *   crc = crc32c_extend(crc, padding, pad_len);
 *
 * is equivalent to crc32c(data || padding, data_len + pad_len).
 */
uint32_t crc32c_extend(uint32_t crc, const void *buf, size_t len);
