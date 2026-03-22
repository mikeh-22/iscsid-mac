/*
 * taskmgmt.h - iSCSI Task Management (RFC 7143 §10.5-§10.6)
 *
 * Provides synchronous ABORT TASK and LUN RESET functions used to recover
 * from hung SCSI commands and to prepare a LUN for re-use.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "session.h"
#include "connection.h"
#include <stdint.h>

/* Task Management Function Response codes (RFC 7143 §10.6.1) */
#define ISCSI_TM_RSP_COMPLETE        0x00   /* Function complete */
#define ISCSI_TM_RSP_NO_TASK         0x01   /* Task does not exist */
#define ISCSI_TM_RSP_NO_LUN          0x02   /* LUN does not exist */
#define ISCSI_TM_RSP_TASK_ALLEGIANT  0x03   /* Task still allegiant */
#define ISCSI_TM_RSP_REASSIGN_UNSUPP 0x04   /* Task reassignment not supported */
#define ISCSI_TM_RSP_NOT_SUPPORTED   0x05   /* Function not supported */
#define ISCSI_TM_RSP_AUTH_FAILED     0x06   /* Authorization failed */
#define ISCSI_TM_RSP_REJECTED        0xFF   /* Function rejected */

/*
 * Send ABORT TASK for the command identified by task_itt.
 *
 * Sends a Task Management Request (function=1) and waits for the response.
 * Returns the target's response code (ISCSI_TM_RSP_*), or -1 on I/O error.
 */
int iscsi_task_abort(iscsi_session_t *sess, iscsi_conn_t *conn,
                      const uint8_t lun[8], uint32_t task_itt);

/*
 * Send LUN RESET (function=5).
 *
 * Aborts all tasks on the specified LUN.  Used to recover from a LUN that
 * has entered an error state.
 *
 * Returns the target's response code (ISCSI_TM_RSP_*), or -1 on I/O error.
 */
int iscsi_lun_reset(iscsi_session_t *sess, iscsi_conn_t *conn,
                     const uint8_t lun[8]);

/* Human-readable task management response string */
const char *taskmgmt_rsp_str(int rsp);
