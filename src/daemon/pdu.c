/*
 * pdu.c - iSCSI PDU construction, send, and receive
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pdu.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

/*
 * Send all bytes described by iov[iovcnt] in a single writev(2) call,
 * looping only on EINTR or a (rare) partial write.
 */
static int writev_all(int fd, struct iovec *iov, int iovcnt, size_t total)
{
    size_t sent = 0;
    while (sent < total) {
        ssize_t n = writev(fd, iov, iovcnt);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return -EIO;
        sent += (size_t)n;
        if (sent >= total) break;
        /* Advance iov past the bytes already sent (partial write path) */
        size_t skip = (size_t)n;
        while (iovcnt > 0 && skip >= iov->iov_len) {
            skip -= iov->iov_len;
            iov++;
            iovcnt--;
        }
        if (iovcnt > 0 && skip > 0) {
            iov->iov_base = (uint8_t *)iov->iov_base + skip;
            iov->iov_len -= skip;
        }
    }
    return 0;
}

/* Fully read len bytes from fd into buf. */
static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return 1;   /* clean close */
        p   += n;
        len -= (size_t)n;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

void pdu_init(iscsi_pdu_t *pdu, uint8_t opcode, uint8_t flags)
{
    memset(pdu, 0, sizeof(*pdu));
    pdu->hdr.opcode = opcode;
    pdu->hdr.flags  = flags;
}

void pdu_set_data_ref(iscsi_pdu_t *pdu, const void *buf, uint32_t len)
{
    pdu_free_data(pdu);
    /* Caller guarantees buf lifetime exceeds the PDU; cast away const
     * since _owned=0 means we will never free this pointer. */
    pdu->data     = (uint8_t *)(uintptr_t)buf;
    pdu->data_len = len;
    pdu->_owned   = 0;
    iscsi_dlength_set(pdu->hdr.dlength, len);
}

int pdu_set_data_copy(iscsi_pdu_t *pdu, const void *buf, uint32_t len)
{
    pdu_free_data(pdu);
    if (len == 0) return 0;
    pdu->data = malloc(len);
    if (!pdu->data) return -ENOMEM;
    memcpy(pdu->data, buf, len);
    pdu->data_len = len;
    pdu->_owned   = 1;
    iscsi_dlength_set(pdu->hdr.dlength, len);
    return 0;
}

void pdu_free_data(iscsi_pdu_t *pdu)
{
    if (pdu->_owned && pdu->data) {
        free(pdu->data);
    }
    pdu->data     = NULL;
    pdu->data_len = 0;
    pdu->_owned   = 0;
}

/* -----------------------------------------------------------------------
 * I/O
 * ----------------------------------------------------------------------- */

int pdu_send(int fd, const iscsi_pdu_t *pdu)
{
    /*
     * Coalesce header + data + padding into a single writev(2) call so
     * that TCP_NODELAY flushes exactly one segment per PDU instead of
     * two or three (one per write).  iov_base is void* so we cast away
     * const — safe because writev only reads from these buffers.
     */
    static const uint8_t zeros[3] = {0, 0, 0};
    struct iovec iov[3];
    int iovcnt = 0;
    size_t total = ISCSI_HDR_LEN;

    iov[iovcnt].iov_base = (void *)(uintptr_t)&pdu->hdr;
    iov[iovcnt].iov_len  = ISCSI_HDR_LEN;
    iovcnt++;

    if (pdu->data_len > 0) {
        iov[iovcnt].iov_base = pdu->data;
        iov[iovcnt].iov_len  = pdu->data_len;
        total += pdu->data_len;
        iovcnt++;

        uint32_t pad = iscsi_pad4(pdu->data_len) - pdu->data_len;
        if (pad > 0) {
            iov[iovcnt].iov_base = (void *)(uintptr_t)zeros;
            iov[iovcnt].iov_len  = pad;
            total += pad;
            iovcnt++;
        }
    }

    return writev_all(fd, iov, iovcnt, total);
}

int pdu_recv(int fd, iscsi_pdu_t *pdu)
{
    int rc;

    memset(pdu, 0, sizeof(*pdu));

    rc = read_all(fd, &pdu->hdr, ISCSI_HDR_LEN);
    if (rc) return rc;

    uint32_t dlen = iscsi_dlength_get(pdu->hdr.dlength);
    if (dlen == 0) return 0;

    /* Reject absurdly large data segments from a malicious peer.
     * RFC 7143 §12 caps MaxRecvDataSegmentLength at 2^24-1 but sane
     * implementations negotiate far lower values.  Hard-limit here. */
    if (dlen > ISCSI_MAX_RECV_SEG_LEN) {
        fprintf(stderr, "pdu: data segment length %u exceeds maximum %u\n",
                dlen, ISCSI_MAX_RECV_SEG_LEN);
        return -EMSGSIZE;
    }

    uint32_t padded = iscsi_pad4(dlen);
    /* +1 so that text segments are always NUL-terminated for safe kv parsing */
    pdu->data = malloc((size_t)padded + 1);
    if (!pdu->data) return -ENOMEM;
    pdu->_owned = 1;

    rc = read_all(fd, pdu->data, padded);
    if (rc) {
        free(pdu->data);
        pdu->data = NULL;
        return rc;
    }

    pdu->data[dlen] = '\0';   /* NUL-terminate; padding bytes already read */
    pdu->data_len = dlen;
    return 0;
}

/* -----------------------------------------------------------------------
 * Key=Value text helpers
 * ----------------------------------------------------------------------- */

int pdu_kv_append(char *buf, int buf_size, int used,
                  const char *key, const char *value)
{
    int need = (int)(strlen(key) + 1 /* = */ + strlen(value) + 1 /* NUL */);
    if (used + need > buf_size) return -1;
    int written = snprintf(buf + used, (size_t)(buf_size - used),
                           "%s=%s", key, value);
    /* Include the NUL terminator in the count */
    return used + written + 1;
}

const char *pdu_kv_get(const char *buf, uint32_t len, const char *key)
{
    size_t klen = strlen(key);
    const char *p = buf;
    const char *end = buf + len;

    while (p < end) {
        /* Each entry is NUL-terminated "key=value" */
        size_t entry_len = strnlen(p, (size_t)(end - p));
        if (entry_len == 0) {
            p++;
            continue;
        }
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            return p + klen + 1;
        }
        p += entry_len + 1;
    }
    return NULL;
}

int pdu_kv_get_str(const char *buf, uint32_t len, const char *key,
                   char *dst, size_t dst_size)
{
    const char *v = pdu_kv_get(buf, len, key);
    if (!v) return -1;
    snprintf(dst, dst_size, "%s", v);
    return 0;
}

int pdu_kv_get_int(const char *buf, uint32_t len, const char *key,
                   uint32_t *out)
{
    const char *v = pdu_kv_get(buf, len, key);
    if (!v) return -1;
    char *end;
    long val = strtol(v, &end, 10);
    if (end == v) return -1;
    *out = (uint32_t)val;
    return 0;
}
