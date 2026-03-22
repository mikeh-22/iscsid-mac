/*
 * taskmgmt.c - iSCSI Task Management Functions (RFC 7143 §10.5-§10.6)
 *
 * Task Management Requests are sent as immediate commands (they bypass
 * the normal CmdSN window) and consume no CmdSN slot.  The target
 * processes them ahead of queued SCSI commands.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "taskmgmt.h"
#include "pdu.h"
#include "../shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

/* -----------------------------------------------------------------------
 * Internal helper: send TM request, wait for TM response
 * ----------------------------------------------------------------------- */

/*
 * Send a Task Management Function Request and wait for the matching response.
 * Intermediate PDUs (e.g. SCSI responses from in-flight commands) are drained
 * and discarded — they belong to a higher layer that is no longer listening.
 *
 * Returns ISCSI_TM_RSP_* on success, -1 on I/O error.
 */
static int send_tm_request(iscsi_session_t *sess, iscsi_conn_t *conn,
                             uint8_t function, const uint8_t lun[8],
                             uint32_t ref_itt)
{
    uint32_t itt = session_next_itt(sess);

    iscsi_pdu_t req;
    pdu_init(&req, ISCSI_OP_TASK_MGT_REQ | ISCSI_OP_IMMEDIATE, ISCSI_FLAG_FINAL);
    iscsi_task_mgmt_req_t *hdr = (iscsi_task_mgmt_req_t *)&req.hdr;

    /* flags[6:0] = function code; F-bit is already set by pdu_init */
    hdr->flags     = ISCSI_FLAG_FINAL | (function & 0x7F);
    memcpy(hdr->lun, lun, 8);
    hdr->itt       = htonl(itt);
    hdr->rtt       = htonl(ref_itt);         /* Referenced Task Tag */
    hdr->cmdsn     = htonl(sess->cmd_sn);    /* immediate: do NOT increment */
    hdr->expstatsn = htonl(conn->exp_statsn);
    hdr->refcmdsn  = htonl(sess->exp_cmd_sn);
    hdr->expdatasn = 0;

    int rc = pdu_send(conn->fd, &req, conn->header_digest, conn->data_digest);
    if (rc) {
        syslog(LOG_ERR, "taskmgmt: send TM request failed: %d", rc);
        return -1;
    }

    /* Wait for the Task Management Response (RFC 7143 §10.6) */
    for (;;) {
        iscsi_pdu_t rsp;
        rc = pdu_recv(conn->fd, &rsp, conn->header_digest, conn->data_digest);
        if (rc) {
            syslog(LOG_ERR, "taskmgmt: recv failed: %d", rc);
            pdu_free_data(&rsp);
            return -1;
        }

        uint8_t op = rsp.hdr.opcode & 0x3f;

        if (op == ISCSI_OP_TASK_MGT_RSP) {
            const iscsi_task_mgmt_rsp_t *mrsp =
                (const iscsi_task_mgmt_rsp_t *)&rsp.hdr;
            /* Verify ITT matches */
            if (ntohl(mrsp->itt) != itt) {
                syslog(LOG_WARNING,
                       "taskmgmt: TM response ITT mismatch "
                       "(got 0x%08x, expected 0x%08x)",
                       ntohl(mrsp->itt), itt);
                pdu_free_data(&rsp);
                continue;
            }
            session_update_sn(sess, ntohl(mrsp->statsn),
                              ntohl(mrsp->expcmdsn), ntohl(mrsp->maxcmdsn));
            conn->exp_statsn = ntohl(mrsp->statsn) + 1;
            int response = mrsp->response;
            pdu_free_data(&rsp);
            return response;
        }

        /*
         * Other PDUs (e.g. SCSI Responses from in-flight commands that
         * completed before the abort took effect) are consumed here.
         * A production implementation would route these to waiting callers.
         */
        if (op == ISCSI_OP_SCSI_RSP || op == ISCSI_OP_SCSI_DATA_IN ||
            op == ISCSI_OP_R2T) {
            /* Update StatSN if available */
            const iscsi_scsi_rsp_t *srsp = (const iscsi_scsi_rsp_t *)&rsp.hdr;
            session_update_sn(sess, ntohl(srsp->statsn),
                              ntohl(srsp->expcmdsn), ntohl(srsp->maxcmdsn));
            syslog(LOG_DEBUG,
                   "taskmgmt: draining opcode 0x%02x while awaiting TM response",
                   op);
        } else {
            syslog(LOG_WARNING,
                   "taskmgmt: unexpected opcode 0x%02x while awaiting TM response",
                   op);
        }
        pdu_free_data(&rsp);
    }
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

int iscsi_task_abort(iscsi_session_t *sess, iscsi_conn_t *conn,
                      const uint8_t lun[8], uint32_t task_itt)
{
    syslog(LOG_NOTICE, "taskmgmt: ABORT TASK ITT=0x%08x on %s",
           task_itt, sess->target_name);
    return send_tm_request(sess, conn, ISCSI_TM_FUNC_ABORT_TASK,
                            lun, task_itt);
}

int iscsi_lun_reset(iscsi_session_t *sess, iscsi_conn_t *conn,
                     const uint8_t lun[8])
{
    syslog(LOG_NOTICE, "taskmgmt: LUN RESET on %s", sess->target_name);
    return send_tm_request(sess, conn, ISCSI_TM_FUNC_LOGICAL_UNIT_RESET,
                            lun, ISCSI_RSVD_TASK_TAG);
}

const char *taskmgmt_rsp_str(int rsp)
{
    switch (rsp) {
    case ISCSI_TM_RSP_COMPLETE:        return "Function Complete";
    case ISCSI_TM_RSP_NO_TASK:         return "Task Does Not Exist";
    case ISCSI_TM_RSP_NO_LUN:          return "LUN Does Not Exist";
    case ISCSI_TM_RSP_TASK_ALLEGIANT:  return "Task Still Allegiant";
    case ISCSI_TM_RSP_REASSIGN_UNSUPP: return "Reassignment Not Supported";
    case ISCSI_TM_RSP_NOT_SUPPORTED:   return "Function Not Supported";
    case ISCSI_TM_RSP_AUTH_FAILED:     return "Authorization Failed";
    case ISCSI_TM_RSP_REJECTED:        return "Function Rejected";
    default:                            return "Unknown Response";
    }
}
