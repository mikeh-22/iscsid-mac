/*
 * async.h - In-session PDU dispatch (NOP-In, Async Message)
 *
 * Called from the kqueue event loop when data arrives on a logged-in
 * connection FD outside of an active SCSI command.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "session.h"
#include "connection.h"
#include "pdu.h"

/*
 * Read one PDU from conn->fd and dispatch by opcode:
 *   ISCSI_OP_NOOP_IN   → send NOP-Out reply (if target solicited it)
 *   ISCSI_OP_ASYNC_MSG → call async_handle_event()
 *   anything else      → log and discard (unexpected in FFP idle state)
 *
 * Returns  0 to keep monitoring the connection.
 * Returns -1 if the connection should be closed and recovery attempted.
 */
int conn_handle_incoming(iscsi_session_t *sess, iscsi_conn_t *conn);

/*
 * Dispatch one received ASYNC_MSG.
 * Updates session/connection state for events 1-3 (logout/drop).
 * Returns  0 to keep the session alive.
 * Returns -1 if the target is dropping the connection or session.
 */
int async_handle_event(iscsi_session_t *sess, iscsi_conn_t *conn,
                        const iscsi_pdu_t *pdu);

/*
 * Send an unsolicited NOP-Out to check connection liveness.
 * Uses a real ITT so the target responds with a NOP-In (handled by the
 * kqueue loop).  Does NOT increment CmdSN (immediate command).
 * Returns 0 on success, -errno on failure.
 */
int async_send_nop_out(iscsi_session_t *sess, iscsi_conn_t *conn);
