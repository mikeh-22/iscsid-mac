/*
 * discovery.c - iSCSI SendTargets discovery
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "discovery.h"
#include "session.h"
#include "connection.h"
#include "login.h"
#include "pdu.h"
#include "../shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * Parse SendTargets response text data
 *
 * The text data consists of NUL-separated key=value pairs:
 *   TargetName=iqn.xxx\0TargetAddress=host:port,group\0TargetName=...\0
 * ----------------------------------------------------------------------- */

static int parse_targets(const char *data, uint32_t len,
                          iscsi_target_info_t *targets, int max)
{
    int count = 0;
    const char *p   = data;
    const char *end = data + len;

    /* Working slot */
    iscsi_target_info_t *cur = NULL;

    while (p < end && count < max) {
        size_t entry_len = strnlen(p, (size_t)(end - p));
        if (entry_len == 0) { p++; continue; }

        if (strncmp(p, "TargetName=", 11) == 0) {
            /* Start a new target record */
            cur = &targets[count++];
            memset(cur, 0, sizeof(*cur));
            cur->port = ISCSI_PORT;   /* default */
            snprintf(cur->target_name, sizeof(cur->target_name),
                     "%s", p + 11);

        } else if (cur && strncmp(p, "TargetAddress=", 14) == 0) {
            const char *addr = p + 14;
            /* Format: host:port,group or [ipv6]:port,group */
            snprintf(cur->address, sizeof(cur->address), "%s", addr);

            /* Parse host, port, portal-group-tag */
            char tmp[256];
            snprintf(tmp, sizeof(tmp), "%s", addr);

            /* Strip portal group tag */
            char *comma = strrchr(tmp, ',');
            if (comma) {
                char *pg_end;
                long pg = strtol(comma + 1, &pg_end, 10);
                if (pg_end != comma + 1 && pg >= 0 && pg <= 65535)
                    cur->portal_group = (int)pg;
                *comma = '\0';
            }

            /* Check for IPv6 bracket notation */
            if (tmp[0] == '[') {
                char *bracket = strchr(tmp, ']');
                if (bracket) {
                    *bracket = '\0';
                    snprintf(cur->host, sizeof(cur->host), "%s", tmp + 1);
                    if (bracket[1] == ':') {
                        char *port_end;
                        long port = strtol(bracket + 2, &port_end, 10);
                        if (port_end != bracket + 2 && port > 0 && port <= 65535)
                            cur->port = (uint16_t)port;
                    }
                }
            } else {
                char *colon = strrchr(tmp, ':');
                if (colon) {
                    char *port_end;
                    long port = strtol(colon + 1, &port_end, 10);
                    if (port_end != colon + 1 && port > 0 && port <= 65535)
                        cur->port = (uint16_t)port;
                    *colon = '\0';
                }
                snprintf(cur->host, sizeof(cur->host), "%s", tmp);
            }
        }

        p += entry_len + 1;
    }

    return count;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

int iscsi_discover(const char *host, uint16_t port,
                   const char *initiator_name,
                   const char *chap_user,
                   const char *chap_secret,
                   iscsi_target_info_t *targets,
                   int max_targets)
{
    char addr[256];
    snprintf(addr, sizeof(addr), "%s:%u", host, port);

    /* Create a discovery session */
    iscsi_session_t *sess = session_create(SESS_TYPE_DISCOVERY,
                                            initiator_name,
                                            NULL, addr);
    if (!sess) return -ENOMEM;

    if (chap_user && chap_user[0]) {
        snprintf(sess->chap_username, sizeof(sess->chap_username),
                 "%s", chap_user);
    }
    if (chap_secret && chap_secret[0]) {
        snprintf(sess->chap_secret, sizeof(sess->chap_secret),
                 "%s", chap_secret);
    }

    /* Open connection */
    iscsi_conn_t *conn = conn_create(host, port);
    if (!conn) {
        session_destroy(sess);
        return -ECONNREFUSED;
    }
    conn->cid = 1;
    session_add_conn(sess, conn);
    conn_set_keepalive(conn, 60, 10, 3);

    /* Login (discovery session) */
    login_result_t lr = iscsi_login(sess, conn);
    if (lr != LOGIN_OK) {
        fprintf(stderr, "discover: login failed: %s\n", login_result_str(lr));
        session_destroy(sess);
        return -1;
    }

    /* Send "SendTargets=All" text request */
    char kv[64];
    int kv_len = pdu_kv_append(kv, sizeof(kv), 0, "SendTargets", "All");

    iscsi_pdu_t req_pdu;
    pdu_init(&req_pdu, ISCSI_OP_TEXT_REQ | ISCSI_OP_IMMEDIATE, ISCSI_TEXT_FINAL);
    iscsi_text_req_t *treq = (iscsi_text_req_t *)&req_pdu.hdr;
    treq->itt      = htonl(2);
    treq->ttt      = htonl(ISCSI_RSVD_TASK_TAG);
    treq->cmdsn    = htonl(session_next_cmdsn(sess));
    treq->expstatsn = htonl(conn->exp_statsn);
    iscsi_dlength_set(treq->dlength, (uint32_t)kv_len);
    pdu_set_data_ref(&req_pdu, kv, (uint32_t)kv_len);

    int rc = pdu_send(conn->fd, &req_pdu);
    if (rc) {
        fprintf(stderr, "discover: send text request failed: %s\n",
                strerror(-rc));
        session_destroy(sess);
        return rc;
    }

    /* Collect all text response PDUs (may span multiple if F bit not set) */
    char *text_buf  = NULL;
    size_t text_len = 0;
    int    done     = 0;
    int    count    = 0;

    while (!done) {
        iscsi_pdu_t rsp;
        rc = pdu_recv(conn->fd, &rsp);
        if (rc) {
            fprintf(stderr, "discover: recv text response failed\n");
            free(text_buf);
            session_destroy(sess);
            return rc;
        }

        if ((rsp.hdr.opcode & 0x3f) != ISCSI_OP_TEXT_RSP) {
            fprintf(stderr, "discover: unexpected opcode 0x%02x\n",
                    rsp.hdr.opcode & 0x3f);
            pdu_free_data(&rsp);
            free(text_buf);
            session_destroy(sess);
            return -1;
        }

        iscsi_text_rsp_t *trsp = (iscsi_text_rsp_t *)&rsp.hdr;
        done = (trsp->flags & ISCSI_TEXT_FINAL) && !(trsp->flags & ISCSI_TEXT_CONTINUE);

        /* Accumulate text data — hard cap against malicious targets sending
         * unbounded data to exhaust heap memory. */
        if (rsp.data_len > 0) {
#define MAX_DISCOVERY_TEXT 65536u   /* 64 KiB: plenty for any sane target list */
            if (text_len + rsp.data_len > MAX_DISCOVERY_TEXT) {
                fprintf(stderr, "discover: text response exceeds %u bytes\n",
                        MAX_DISCOVERY_TEXT);
                pdu_free_data(&rsp);
                free(text_buf);
                session_destroy(sess);
                return -EMSGSIZE;
            }
            char *new_buf = realloc(text_buf, text_len + rsp.data_len);
            if (!new_buf) {
                pdu_free_data(&rsp);
                free(text_buf);
                session_destroy(sess);
                return -ENOMEM;
            }
            memcpy(new_buf + text_len, rsp.data, rsp.data_len);
            text_len += rsp.data_len;
            text_buf  = new_buf;
        }

        /* Update ExpStatSN */
        conn->exp_statsn = ntohl(trsp->statsn) + 1;
        session_update_sn(sess, ntohl(trsp->statsn),
                          ntohl(trsp->expcmdsn), ntohl(trsp->maxcmdsn));

        pdu_free_data(&rsp);
    }

    /* Parse the accumulated response */
    if (text_buf && text_len > 0) {
        count = parse_targets(text_buf, (uint32_t)text_len, targets, max_targets);
    }
    free(text_buf);

    /* Logout */
    iscsi_logout(sess, conn, ISCSI_LOGOUT_CLOSE_SESSION);
    session_destroy(sess);

    return count;
}

void iscsi_print_targets(const iscsi_target_info_t *targets, int count)
{
    if (count == 0) {
        printf("No targets discovered.\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        printf("Target %d: %s\n", i + 1, targets[i].target_name);
        printf("  Address: %s (portal group %d)\n",
               targets[i].address[0] ? targets[i].address : "(none)",
               targets[i].portal_group);
    }
}
