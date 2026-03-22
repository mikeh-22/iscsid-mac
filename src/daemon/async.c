/*
 * async.c - In-session PDU dispatch: NOP-In ping replies and ASYNC_MSG handling
 *
 * iSCSI targets may send unsolicited PDUs to a logged-in initiator at any
 * time: NOP-In pings (to verify the connection is alive) and Asynchronous
 * Messages (to announce state changes).  The kqueue event loop calls
 * conn_handle_incoming() whenever the connection FD becomes readable during
 * idle time.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "async.h"
#include "login.h"
#include "pdu.h"
#include "../shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

/* Forward declaration */
static int async_renegotiate_params(iscsi_session_t *sess, iscsi_conn_t *conn,
                                     const iscsi_pdu_t *async_pdu);

/* -----------------------------------------------------------------------
 * Public: send a keepalive NOP-Out
 * ----------------------------------------------------------------------- */

int async_send_nop_out(iscsi_session_t *sess, iscsi_conn_t *conn)
{
    uint32_t itt = session_next_itt(sess);

    iscsi_pdu_t pdu;
    pdu_init(&pdu, ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE, ISCSI_FLAG_FINAL);
    iscsi_nop_out_t *req = (iscsi_nop_out_t *)&pdu.hdr;
    req->itt       = htonl(itt);
    req->ttt       = htonl(ISCSI_RSVD_TASK_TAG);   /* unsolicited direction */
    req->cmdsn     = htonl(sess->cmd_sn);           /* immediate: no increment */
    req->expstatsn = htonl(conn->exp_statsn);

    int rc = pdu_send(conn->fd, &pdu, conn->header_digest, conn->data_digest);
    if (rc)
        syslog(LOG_WARNING, "async: NOP-Out keepalive failed on %s CID %u: %d",
               sess->target_name, conn->cid, rc);
    else
        conn->last_activity = time(NULL);
    return rc;
}

/* -----------------------------------------------------------------------
 * NOP-In handling
 * ----------------------------------------------------------------------- */

/*
 * A solicited NOP-In (TTT != 0xFFFFFFFF) requires a NOP-Out reply with
 * the same TTT so the target can match it to its ping.  We use ITT=0xFFFFFFFF
 * (unsolicited) and do NOT increment CmdSN (NOP-Out replies are not counted).
 */
static void nop_in_reply(iscsi_conn_t *conn, iscsi_session_t *sess,
                          const iscsi_pdu_t *in_pdu)
{
    const iscsi_nop_in_t *nop_in = (const iscsi_nop_in_t *)&in_pdu->hdr;

    /* Unsolicited NOP-In (TTT == 0xFFFFFFFF): no reply required */
    if (ntohl(nop_in->ttt) == ISCSI_RSVD_TASK_TAG) return;

    iscsi_pdu_t reply;
    pdu_init(&reply, ISCSI_OP_NOOP_OUT, ISCSI_FLAG_FINAL);
    iscsi_nop_out_t *req = (iscsi_nop_out_t *)&reply.hdr;
    req->itt       = htonl(ISCSI_RSVD_TASK_TAG);   /* not a command */
    req->ttt       = nop_in->ttt;                   /* echo target's TTT */
    req->cmdsn     = htonl(sess->cmd_sn);           /* do NOT increment */
    req->expstatsn = htonl(conn->exp_statsn);

    int rc = pdu_send(conn->fd, &reply, conn->header_digest, conn->data_digest);
    if (rc)
        syslog(LOG_WARNING, "async: NOP-Out reply failed: %d", rc);
}

/* -----------------------------------------------------------------------
 * ASYNC_MSG event dispatch
 * ----------------------------------------------------------------------- */

int async_handle_event(iscsi_session_t *sess, iscsi_conn_t *conn,
                        const iscsi_pdu_t *pdu)
{
    const iscsi_async_t *hdr = (const iscsi_async_t *)&pdu->hdr;
    uint8_t event = hdr->async_event;

    session_update_sn(sess, ntohl(hdr->statsn),
                      ntohl(hdr->expcmdsn), ntohl(hdr->maxcmdsn));
    conn->exp_statsn = ntohl(hdr->statsn) + 1;

    switch (event) {

    case ISCSI_ASYNC_SCSI_EVENT:
        /*
         * SCSI asynchronous event — sense data may be in the data segment.
         * Log it; a real implementation would deliver this to the SCSI layer.
         */
        syslog(LOG_NOTICE, "async: SCSI async event on %s (vcode=%u, %u data bytes)",
               sess->target_name, hdr->async_vcode, pdu->data_len);
        return 0;

    case ISCSI_ASYNC_LOGOUT_REQUEST:
        /*
         * Target requests that we log out.
         * param1 = logout reason code, param2 = Time2Wait, param3 = Time2Retain
         */
        {
            uint16_t reason   = ntohs(hdr->param1);
            uint16_t t2wait   = ntohs(hdr->param2);
            uint16_t t2retain = ntohs(hdr->param3);
            syslog(LOG_NOTICE,
                   "async: target %s requests logout "
                   "(reason=%u Time2Wait=%u Time2Retain=%u)",
                   sess->target_name, reason, t2wait, t2retain);
            sess->params.default_time2wait   = t2wait;
            sess->params.default_time2retain = t2retain;
        }
        return -1;   /* caller should initiate logout + session cleanup */

    case ISCSI_ASYNC_DROP_CONN:
        /*
         * Target will drop a specific connection.
         * param1 = CID of affected connection, param2 = Time2Wait, param3 = Time2Retain
         */
        {
            uint16_t cid      = ntohs(hdr->param1);
            uint16_t t2wait   = ntohs(hdr->param2);
            uint16_t t2retain = ntohs(hdr->param3);
            syslog(LOG_NOTICE,
                   "async: target %s dropping CID %u "
                   "(Time2Wait=%u Time2Retain=%u)",
                   sess->target_name, cid, t2wait, t2retain);
            sess->params.default_time2wait   = t2wait;
            sess->params.default_time2retain = t2retain;
        }
        return -1;   /* ERL-1: caller may reconnect after Time2Wait */

    case ISCSI_ASYNC_DROP_SESSION:
        /*
         * Target will drop the entire session.  All connections affected.
         */
        syslog(LOG_NOTICE, "async: target %s dropping entire session",
               sess->target_name);
        sess->params.default_time2wait   = ntohs(hdr->param1);
        sess->params.default_time2retain = ntohs(hdr->param2);
        sess->state = SESS_STATE_FAILED;
        return -1;

    case ISCSI_ASYNC_PARAM_NEG:
        /*
         * Target requests parameter renegotiation.  The data segment contains
         * a KV text block of the parameters it wants to change.  We echo them
         * back via a Text Request/Response exchange, accepting as-is.
         * If we have no data or the exchange fails, we log and continue.
         */
        {
            int neg_rc = async_renegotiate_params(sess, conn, pdu);
            if (neg_rc != 0)
                syslog(LOG_WARNING,
                       "async: param renegotiation exchange failed for %s",
                       sess->target_name);
            else
                syslog(LOG_NOTICE,
                       "async: param renegotiation complete for %s",
                       sess->target_name);
        }
        return 0;

    default:
        syslog(LOG_NOTICE, "async: unknown event %u from %s",
               event, sess->target_name);
        return 0;
    }
}

/* -----------------------------------------------------------------------
 * ASYNC event 4: parameter renegotiation via Text Request/Response
 * ----------------------------------------------------------------------- */

/*
 * The target's ASYNC_MSG data segment contains the KV text of parameters
 * it wants to renegotiate.  We echo them back in a Text Request (accepting
 * all proposed values as-is) and wait for the Text Response.
 *
 * RFC 7143 §10.10 / §10.11.
 */
static int async_renegotiate_params(iscsi_session_t *sess, iscsi_conn_t *conn,
                                     const iscsi_pdu_t *async_pdu)
{
    /* If the ASYNC_MSG had no data, there's nothing to renegotiate */
    if (!async_pdu->data || async_pdu->data_len == 0) return 0;

    uint32_t itt = session_next_itt(sess);

    /* Build Text Request echoing the proposed parameters back */
    iscsi_pdu_t req;
    pdu_init(&req, ISCSI_OP_TEXT_REQ | ISCSI_OP_IMMEDIATE,
             ISCSI_TEXT_FINAL | ISCSI_FLAG_FINAL);
    iscsi_text_req_t *hdr = (iscsi_text_req_t *)&req.hdr;
    hdr->itt       = htonl(itt);
    hdr->ttt       = htonl(ISCSI_RSVD_TASK_TAG);
    hdr->cmdsn     = htonl(sess->cmd_sn);    /* immediate */
    hdr->expstatsn = htonl(conn->exp_statsn);
    iscsi_dlength_set(hdr->dlength, async_pdu->data_len);
    pdu_set_data_ref(&req, async_pdu->data, async_pdu->data_len);

    int rc = pdu_send(conn->fd, &req, conn->header_digest, conn->data_digest);
    if (rc) return rc;

    /* Wait for Text Response */
    for (;;) {
        iscsi_pdu_t rsp;
        rc = pdu_recv(conn->fd, &rsp, conn->header_digest, conn->data_digest);
        if (rc) { pdu_free_data(&rsp); return rc; }

        uint8_t op = rsp.hdr.opcode & 0x3f;
        if (op == ISCSI_OP_TEXT_RSP) {
            const iscsi_text_rsp_t *trsp = (const iscsi_text_rsp_t *)&rsp.hdr;
            session_update_sn(sess, ntohl(trsp->statsn),
                              ntohl(trsp->expcmdsn), ntohl(trsp->maxcmdsn));
            conn->exp_statsn = ntohl(trsp->statsn) + 1;
            pdu_free_data(&rsp);
            return 0;
        }
        /* Consume other PDUs and keep waiting */
        syslog(LOG_DEBUG,
               "async: draining opcode 0x%02x during param renegotiation", op);
        pdu_free_data(&rsp);
    }
}

/* -----------------------------------------------------------------------
 * Public entry point: read one idle PDU and dispatch
 * ----------------------------------------------------------------------- */

int conn_handle_incoming(iscsi_session_t *sess, iscsi_conn_t *conn)
{
    iscsi_pdu_t pdu;
    int rc = pdu_recv(conn->fd, &pdu, conn->header_digest, conn->data_digest);
    if (rc) {
        /* Connection dropped or digest error */
        syslog(LOG_WARNING, "async: recv error on %s conn %u: %d",
               sess->target_name, conn->cid, rc);
        pdu_free_data(&pdu);
        conn->state = CONN_STATE_FAILED;
        return -1;
    }
    conn->last_activity = time(NULL);

    uint8_t op = pdu.hdr.opcode & 0x3f;
    int ret = 0;

    switch (op) {
    case ISCSI_OP_NOOP_IN:
        nop_in_reply(conn, sess, &pdu);
        /* Update sequence numbers */
        {
            const iscsi_nop_in_t *h = (const iscsi_nop_in_t *)&pdu.hdr;
            conn->exp_statsn = ntohl(h->statsn) + 1;
            session_update_sn(sess, ntohl(h->statsn),
                              ntohl(h->expcmdsn), ntohl(h->maxcmdsn));
        }
        break;

    case ISCSI_OP_ASYNC_MSG:
        ret = async_handle_event(sess, conn, &pdu);
        break;

    case ISCSI_OP_REJECT:
        /* Target rejected one of our PDUs; log the reason */
        syslog(LOG_WARNING, "async: Reject PDU from %s (reason=0x%02x)",
               sess->target_name, pdu.hdr.rsvd2[0]);
        break;

    default:
        syslog(LOG_WARNING,
               "async: unexpected opcode 0x%02x in FFP idle state on %s",
               op, sess->target_name);
        break;
    }

    pdu_free_data(&pdu);
    return ret;
}
