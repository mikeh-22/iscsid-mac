/*
 * pdu.h - iSCSI PDU construction, send, and receive
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "../shared/iscsi_protocol.h"
#include <stdint.h>
#include <stddef.h>

/* An iSCSI PDU with header and optional data segment */
typedef struct {
    iscsi_hdr_t hdr;
    uint8_t    *data;       /* data segment (heap-allocated, or NULL) */
    uint32_t    data_len;   /* bytes in data segment */
    uint8_t     _owned;     /* non-zero if we own data and must free it */
} iscsi_pdu_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/* Initialise a PDU with opcode and flags.  data and data_len are zeroed. */
void pdu_init(iscsi_pdu_t *pdu, uint8_t opcode, uint8_t flags);

/* Attach an existing buffer as the data segment (not owned). */
void pdu_set_data_ref(iscsi_pdu_t *pdu, const void *buf, uint32_t len);

/* Copy buf into a newly allocated data segment (owned). */
int  pdu_set_data_copy(iscsi_pdu_t *pdu, const void *buf, uint32_t len);

/* Free any owned data segment. */
void pdu_free_data(iscsi_pdu_t *pdu);

/* -----------------------------------------------------------------------
 * I/O
 * ----------------------------------------------------------------------- */

/*
 * Send a PDU on fd.
 * Writes header [+ 4-byte CRC] + data segment + padding [+ 4-byte CRC]
 * in a single writev(2) call.
 *
 * hdr_digest / data_digest: non-zero to append CRC32C (RFC 7143 §6.7).
 * Pass 0 for both during the Login phase (digests apply in FFP only).
 *
 * Returns 0 on success, -errno on error.
 */
int pdu_send(int fd, const iscsi_pdu_t *pdu, int hdr_digest, int data_digest);

/*
 * Receive a PDU from fd.
 * Reads the 48-byte header, verifies the header CRC if hdr_digest is set,
 * allocates and reads the data segment, verifies the data CRC if data_digest
 * is set.  The caller must call pdu_free_data() when done.
 *
 * Returns 0 on success, -errno on error, 1 on clean peer close,
 * -EBADMSG on digest mismatch.
 */
int pdu_recv(int fd, iscsi_pdu_t *pdu, int hdr_digest, int data_digest);

/* -----------------------------------------------------------------------
 * Key=Value text helpers
 * ----------------------------------------------------------------------- */

/*
 * Append "key=value\0" to buf (for building login/text PDU data segments).
 * Returns new length, or -1 if it would overflow buf_size.
 */
int  pdu_kv_append(char *buf, int buf_size, int used,
                   const char *key, const char *value);

/*
 * Retrieve the value for key from a NUL-terminated key=value pairs buffer.
 * Returns pointer into buf, or NULL if not found.
 */
const char *pdu_kv_get(const char *buf, uint32_t len, const char *key);

/* Write pdu_kv_get result into dst (max dst_size bytes).
 * Returns 0 on success, -1 if key not found. */
int pdu_kv_get_str(const char *buf, uint32_t len, const char *key,
                   char *dst, size_t dst_size);

/* Parse pdu_kv_get result as an integer.
 * Returns 0 on success, -1 if key not found or not an integer. */
int pdu_kv_get_int(const char *buf, uint32_t len, const char *key,
                   uint32_t *out);
