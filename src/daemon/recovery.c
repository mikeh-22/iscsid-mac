/*
 * recovery.c - iSCSI Error Recovery Level 1 (RFC 7143 §6.1.5)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "recovery.h"
#include "connection.h"
#include "login.h"
#include "pdu.h"
#include "../shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <time.h>
#include <syslog.h>

/* -----------------------------------------------------------------------
 * ERL-1 connection reconnect
 * ----------------------------------------------------------------------- */

iscsi_conn_t *recovery_reconnect(iscsi_session_t *sess,
                                  iscsi_conn_t *failed_conn,
                                  int kq)
{
    if (sess->params.error_recovery_level < 1) {
        syslog(LOG_NOTICE, "recovery: ERL=0, cannot reconnect for %s",
               sess->target_name);
        return NULL;
    }

    /* Mark the connection failed */
    failed_conn->state = CONN_STATE_FAILED;

    /* Deregister from kqueue */
    if (kq >= 0) {
        struct kevent kev;
        EV_SET(&kev, (uintptr_t)failed_conn->fd,
               EVFILT_READ, EV_DELETE, 0, 0, NULL);
        kevent(kq, &kev, 1, NULL, 0, NULL);
    }

    /* RFC 7143 §6.1.5: initiator has [Time2Wait, Time2Wait+Time2Retain] seconds
     * to reinstate the connection.  Record the deadline before sleeping so we
     * can detect expiry after a slow or failed reconnect attempt. */
    uint32_t wait_sec   = sess->params.default_time2wait;
    uint32_t retain_sec = sess->params.default_time2retain;
    time_t   deadline   = time(NULL) + (time_t)wait_sec + (time_t)retain_sec;

    if (wait_sec > 0) {
        syslog(LOG_NOTICE, "recovery: waiting %u s before reconnecting to %s",
               wait_sec, sess->target_name);
        struct timespec ts = { .tv_sec = (time_t)wait_sec, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
    }

    if (time(NULL) > deadline) {
        syslog(LOG_ERR, "recovery: Time2Retain expired for %s — session lost",
               sess->target_name);
        return NULL;
    }

    /* Parse host and port from target_address */
    char host[256];
    uint16_t port;
    if (iscsi_parse_portal(sess->target_address, host, sizeof(host), &port) != 0) {
        syslog(LOG_ERR, "recovery: cannot parse target address '%s'",
               sess->target_address);
        return NULL;
    }

    syslog(LOG_NOTICE, "recovery: reconnecting to %s for session %s",
           sess->target_address, sess->target_name);

    /* Create a new TCP connection */
    iscsi_conn_t *new_conn = conn_create(host, port);
    if (!new_conn) {
        syslog(LOG_ERR, "recovery: conn_create failed for %s", sess->target_name);
        return NULL;
    }

    /* Allocate a new CID and re-login with the existing TSIH */
    new_conn->cid = session_next_cid(sess);
    conn_set_keepalive(new_conn, sess->params.tcp_keepalive_idle,
                       sess->params.tcp_keepalive_interval,
                       sess->params.tcp_keepalive_count);

    login_result_t lr = iscsi_login_add_conn(sess, new_conn);
    if (lr != LOGIN_OK) {
        syslog(LOG_ERR, "recovery: re-login failed for %s: %s",
               sess->target_name, login_result_str(lr));
        conn_destroy(new_conn);
        return NULL;
    }

    if (time(NULL) > deadline) {
        /* Login succeeded but window closed — treat as failure to avoid
         * presenting a technically-expired session to the target. */
        syslog(LOG_WARNING,
               "recovery: Time2Retain expired during re-login for %s",
               sess->target_name);
        conn_destroy(new_conn);
        return NULL;
    }

    /* Replace the failed connection in the session */
    pthread_mutex_lock(&sess->lock);
    iscsi_conn_t **pp = &sess->connections;
    while (*pp && *pp != failed_conn)
        pp = &(*pp)->next;
    if (*pp == failed_conn) {
        new_conn->next = failed_conn->next;
        *pp = new_conn;
        /* num_connections stays the same: 1 removed, 1 added */
    } else {
        /* Not found — just append */
        new_conn->next    = sess->connections;
        sess->connections = new_conn;
        sess->num_connections++;
    }
    pthread_mutex_unlock(&sess->lock);

    conn_destroy(failed_conn);

    /* Register new connection with kqueue */
    if (kq >= 0) {
        struct kevent kev;
        EV_SET(&kev, (uintptr_t)new_conn->fd,
               EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)new_conn);
        kevent(kq, &kev, 1, NULL, 0, NULL);
    }

    syslog(LOG_NOTICE, "recovery: connection reinstated for %s (CID %u)",
           sess->target_name, new_conn->cid);
    return new_conn;
}

/* -----------------------------------------------------------------------
 * SNACK request
 * ----------------------------------------------------------------------- */

int recovery_send_snack(iscsi_conn_t *conn, iscsi_session_t *sess,
                         uint32_t itt, uint32_t ttt,
                         uint8_t type, uint32_t begrun, uint32_t runlength)
{
    iscsi_pdu_t pdu;
    pdu_init(&pdu, ISCSI_OP_SNACK_REQ, ISCSI_FLAG_FINAL | (type & 0x0f));

    iscsi_snack_req_t *req = (iscsi_snack_req_t *)&pdu.hdr;
    req->itt        = htonl(itt);
    req->ttt        = htonl(ttt);
    req->expstatsn  = htonl(conn->exp_statsn);
    req->expdatasn  = 0;
    req->begrun     = htonl(begrun);
    req->runlength  = htonl(runlength);

    (void)sess;   /* available for future CmdSN use */

    return pdu_send(conn->fd, &pdu, conn->header_digest, conn->data_digest);
}
