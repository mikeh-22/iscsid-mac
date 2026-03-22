/*
 * isns.c - RFC 4171 iSNS discovery client
 *
 * Wire format (RFC 4171 §3.1):
 *
 *   iSNS PDU header (12 bytes, all fields big-endian):
 *     uint16_t version;       0x0001
 *     uint16_t function_id;
 *     uint16_t length;        payload length in bytes
 *     uint16_t flags;
 *     uint16_t transaction_id;
 *     uint16_t sequence_id;
 *
 *   Payload: TLV attributes
 *     uint32_t tag;    attribute type
 *     uint32_t len;    value length (not including header)
 *     uint8_t  value[len]; padded to 4-byte boundary
 *
 * We send DevAttrQry (func_id=0x0002) with:
 *   Source:           iSCSI Name of our initiator (tag 32)
 *   Message Key:      empty (returns all registered nodes)
 *   Delimiter:        tag 0, len 0
 *   Operating attrs:  iSCSI Name (32), Node Type (33), Portal IP (16), Port (17)
 *
 * The response DevAttrQryRsp (func_id=0x8002) contains:
 *   Status:           tag 263, 4-byte error code (0 = success)
 *   Delimiter:        tag 0, len 0
 *   Attribute groups: one per registered node, each containing the
 *                     requested operating attributes
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "isns.h"
#include "../shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Wire-format constants
 * ----------------------------------------------------------------------- */

/* iSNS function IDs (RFC 4171 §5.1 Table 2) */
#define ISNS_FUNC_DEV_ATTR_QRY      0x0002
#define ISNS_FUNC_DEV_ATTR_QRY_RSP  0x8002

/* iSNS PDU flags (RFC 4171 §3.1) */
#define ISNS_FLAG_CLIENT            0x4000  /* request from client */
#define ISNS_FLAG_SERVER            0x8000  /* response from server */
#define ISNS_FLAG_LAST_PDU          0x0100  /* last (or only) PDU */

/* iSNS TLV attribute tags (RFC 4171 Appendix B) */
#define ISNS_TAG_DELIMITER          0
#define ISNS_TAG_PORTAL_IP_ADDR     16   /* 16 bytes: IPv4-mapped-IPv6 */
#define ISNS_TAG_PORTAL_PORT        17   /* 4 bytes: port (high 16) | type (low 16) */
#define ISNS_TAG_ISCSI_NAME         32   /* UTF-8 string, padded to 4 bytes */
#define ISNS_TAG_ISCSI_NODE_TYPE    33   /* 4 bytes bitmask: 1=Target 2=Initiator */
#define ISNS_TAG_STATUS             263  /* 4 bytes: error code */

/* iSCSI Node Type values */
#define ISNS_NODE_TYPE_TARGET       0x00000001
#define ISNS_NODE_TYPE_INITIATOR    0x00000002

/* Maximum iSNS PDU size we will handle */
#define ISNS_MAX_PDU_LEN            (64 * 1024)

/* -----------------------------------------------------------------------
 * iSNS PDU header (12 bytes, all big-endian)
 * ----------------------------------------------------------------------- */

typedef struct __attribute__((packed)) {
    uint16_t version;
    uint16_t function_id;
    uint16_t length;        /* payload bytes after this header */
    uint16_t flags;
    uint16_t transaction_id;
    uint16_t sequence_id;
} isns_hdr_t;

_Static_assert(sizeof(isns_hdr_t) == 12, "isns_hdr_t size");

/* -----------------------------------------------------------------------
 * TLV builder helpers
 * ----------------------------------------------------------------------- */

/*
 * Append a TLV attribute to buf[*off].
 * value_len: number of meaningful bytes in value (padded to 4 inside).
 * Returns 0 on success, -1 if buf would overflow.
 */
static int tlv_append(uint8_t *buf, size_t buf_size, size_t *off,
                       uint32_t tag, const void *value, uint32_t value_len)
{
    uint32_t padded = (value_len + 3) & ~3u;
    if (*off + 8 + padded > buf_size) return -1;

    uint32_t tag_be  = htonl(tag);
    uint32_t len_be  = htonl(value_len);
    memcpy(buf + *off, &tag_be, 4);  *off += 4;
    memcpy(buf + *off, &len_be, 4);  *off += 4;
    if (value_len > 0) memcpy(buf + *off, value, value_len);
    if (padded > value_len) memset(buf + *off + value_len, 0, padded - value_len);
    *off += padded;
    return 0;
}

/* Convenience: append a zero-length attribute (used for operating attributes) */
static int tlv_append_empty(uint8_t *buf, size_t buf_size, size_t *off, uint32_t tag)
{
    return tlv_append(buf, buf_size, off, tag, NULL, 0);
}

/* -----------------------------------------------------------------------
 * TCP helpers
 * ----------------------------------------------------------------------- */

static int tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints, *res, *rp;
    char port_str[8];
    int fd = -1;

    snprintf(port_str, sizeof(port_str), "%u", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Blocking recv exactly n bytes */
static int recv_all(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, (char *)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Response parser (also exposed for unit tests)
 * ----------------------------------------------------------------------- */

int isns_parse_response(const uint8_t *payload, size_t payload_len,
                         iscsi_target_info_t *targets, int max_targets)
{
    int count = 0;
    iscsi_target_info_t *cur = NULL;
    size_t off = 0;

    /*
     * Skip the mandatory Status attribute (tag 263, 4 bytes).
     * If status != 0 the query failed; return 0 targets.
     */
    if (payload_len < 12) return 0;   /* need at least 1 TLV */

    uint32_t first_tag, first_len;
    memcpy(&first_tag, payload + 0, 4); first_tag = ntohl(first_tag);
    memcpy(&first_len, payload + 4, 4); first_len = ntohl(first_len);

    if (first_tag == ISNS_TAG_STATUS) {
        if (first_len >= 4) {
            uint32_t status;
            memcpy(&status, payload + 8, 4); status = ntohl(status);
            if (status != 0) return 0;   /* query error */
        }
        off = 8 + ((first_len + 3) & ~3u);
    }

    /* Skip the first delimiter (marks end of message key in the response) */
    while (off + 8 <= payload_len) {
        uint32_t tag, len;
        memcpy(&tag, payload + off, 4); tag = ntohl(tag);
        memcpy(&len, payload + off + 4, 4); len = ntohl(len);
        off += 8;

        uint32_t padded = (len + 3) & ~3u;
        if (off + padded > payload_len) break;

        const uint8_t *val = payload + off;
        off += padded;

        switch (tag) {

        case ISNS_TAG_DELIMITER:
            /* Delimiter between objects — already consumed above */
            break;

        case ISNS_TAG_ISCSI_NAME:
            if (count >= max_targets) break;
            cur = &targets[count++];
            memset(cur, 0, sizeof(*cur));
            cur->port = ISCSI_PORT;
            {
                size_t nlen = len < sizeof(cur->target_name) - 1
                            ? len : sizeof(cur->target_name) - 1;
                memcpy(cur->target_name, val, nlen);
                cur->target_name[nlen] = '\0';
            }
            break;

        case ISNS_TAG_ISCSI_NODE_TYPE:
            /* If node type is not target, drop the last entry we started */
            if (cur && len >= 4) {
                uint32_t ntype;
                memcpy(&ntype, val, 4); ntype = ntohl(ntype);
                if (!(ntype & ISNS_NODE_TYPE_TARGET)) {
                    cur = NULL;
                    count--;   /* discard non-target */
                }
            }
            break;

        case ISNS_TAG_PORTAL_IP_ADDR:
            /*
             * 16-byte IPv4-mapped-IPv6 or pure IPv6 address.
             * IPv4-mapped form: ::ffff:a.b.c.d (bytes 10-11 = 0xFF 0xFF,
             * bytes 0-9 = 0x00).
             */
            if (cur && len == 16) {
                int is_v4mapped = 1;
                for (int i = 0; i < 10; i++)
                    if (val[i]) { is_v4mapped = 0; break; }
                if (is_v4mapped && val[10] == 0xff && val[11] == 0xff) {
                    snprintf(cur->host, sizeof(cur->host),
                             "%u.%u.%u.%u",
                             val[12], val[13], val[14], val[15]);
                } else {
                    /* Present the IPv6 address */
                    char tmp[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, val, tmp, sizeof(tmp));
                    snprintf(cur->host, sizeof(cur->host), "%s", tmp);
                }
                /* Keep address string too */
                snprintf(cur->address, sizeof(cur->address), "%s", cur->host);
            }
            break;

        case ISNS_TAG_PORTAL_PORT:
            /* High 16 bits = port number, low 16 bits = protocol type */
            if (cur && len >= 4) {
                uint32_t raw;
                memcpy(&raw, val, 4); raw = ntohl(raw);
                cur->port = (uint16_t)(raw >> 16);
                /* Update address with port */
                if (cur->host[0]) {
                    char tmp[256];
                    snprintf(tmp, sizeof(tmp), "%s:%u", cur->host, cur->port);
                    snprintf(cur->address, sizeof(cur->address), "%s", tmp);
                }
            }
            break;

        default:
            /* Unknown attribute — skip */
            break;
        }
    }

    return count;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

int isns_discover(const char *host, uint16_t port,
                  const char *initiator_name,
                  iscsi_target_info_t *targets, int max_targets)
{
    int fd = tcp_connect(host, port);
    if (fd < 0) {
        syslog(LOG_ERR, "isns: cannot connect to %s:%u", host, port);
        return -1;
    }

    /* ---- Build DevAttrQry payload ---- */
    uint8_t payload[4096];
    size_t  poff = 0;

    /* Source attribute: our iSCSI name (tag 32) */
    size_t name_len = strlen(initiator_name);
    if (tlv_append(payload, sizeof(payload), &poff, ISNS_TAG_ISCSI_NAME,
                   initiator_name, (uint32_t)name_len) < 0) {
        close(fd); return -1;
    }

    /* Message key: empty (query all nodes) */

    /* Delimiter (tag 0, len 0) */
    tlv_append_empty(payload, sizeof(payload), &poff, ISNS_TAG_DELIMITER);

    /* Operating attributes we want returned */
    tlv_append_empty(payload, sizeof(payload), &poff, ISNS_TAG_ISCSI_NAME);
    tlv_append_empty(payload, sizeof(payload), &poff, ISNS_TAG_ISCSI_NODE_TYPE);
    tlv_append_empty(payload, sizeof(payload), &poff, ISNS_TAG_PORTAL_IP_ADDR);
    tlv_append_empty(payload, sizeof(payload), &poff, ISNS_TAG_PORTAL_PORT);

    /* ---- Build and send the 12-byte iSNS header ---- */
    static uint16_t trans_id = 1;
    isns_hdr_t hdr = {
        .version        = htons(0x0001),
        .function_id    = htons(ISNS_FUNC_DEV_ATTR_QRY),
        .length         = htons((uint16_t)poff),
        .flags          = htons(ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU),
        .transaction_id = htons(trans_id++),
        .sequence_id    = htons(0),
    };

    if (send(fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr) ||
        send(fd, payload, poff, 0) != (ssize_t)poff) {
        syslog(LOG_ERR, "isns: send failed");
        close(fd); return -1;
    }

    /* ---- Receive the response header ---- */
    isns_hdr_t rsp_hdr;
    if (recv_all(fd, &rsp_hdr, sizeof(rsp_hdr)) < 0) {
        syslog(LOG_ERR, "isns: recv response header failed");
        close(fd); return -1;
    }

    uint16_t rsp_func  = ntohs(rsp_hdr.function_id);
    uint32_t rsp_len   = ntohs(rsp_hdr.length);   /* promote: ISNS_MAX_PDU_LEN > UINT16_MAX */

    if (rsp_func != ISNS_FUNC_DEV_ATTR_QRY_RSP) {
        syslog(LOG_ERR, "isns: unexpected response function 0x%04x", rsp_func);
        close(fd); return -1;
    }
    if (rsp_len > ISNS_MAX_PDU_LEN) {
        syslog(LOG_WARNING, "isns: response too large (%u bytes)", rsp_len);
        close(fd); return -1;
    }

    /* ---- Receive the response payload ---- */
    uint8_t *rsp_payload = malloc(rsp_len);
    if (!rsp_payload) { close(fd); return -1; }

    if (rsp_len > 0 && recv_all(fd, rsp_payload, rsp_len) < 0) {
        syslog(LOG_ERR, "isns: recv response payload failed");
        free(rsp_payload); close(fd); return -1;
    }

    close(fd);

    int count = isns_parse_response(rsp_payload, rsp_len, targets, max_targets);
    free(rsp_payload);
    return count;
}
