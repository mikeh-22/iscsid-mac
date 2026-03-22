/*
 * recovery.h - iSCSI Error Recovery Level 1 (RFC 7143 §6.1.5)
 *
 * ERL-1 allows a session to survive individual connection failures.
 * When a connection fails, the initiator waits DefaultTime2Wait seconds,
 * opens a new TCP connection to the same portal, and re-logs in with the
 * existing ISID and TSIH to reinstate the connection within the session.
 *
 * Outstanding commands that were in-flight over the failed connection may
 * need to be retransmitted (tracked externally; not implemented here).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "session.h"
#include "connection.h"

/*
 * Attempt ERL-1 connection recovery after a connection failure:
 *   1. Mark failed_conn as CONN_STATE_FAILED
 *   2. Sleep sess->params.default_time2wait seconds
 *   3. Open a new TCP connection to the same portal (host extracted from
 *      sess->target_address)
 *   4. Re-login with the same ISID and non-zero TSIH (connection reinstatement)
 *   5. Replace failed_conn in the session connection list
 *
 * kq: the kqueue fd — used to deregister the old FD and register the new one
 *     (pass -1 to skip kqueue registration, e.g. in tests)
 *
 * Returns the new iscsi_conn_t on success, NULL if recovery failed (caller
 * should destroy the session).
 */
iscsi_conn_t *recovery_reconnect(iscsi_session_t *sess,
                                  iscsi_conn_t *failed_conn,
                                  int kq);

/*
 * Send a SNACK Request PDU to ask the target to retransmit a range of PDUs.
 *
 * type:      ISCSI_SNACK_DATA_ACK, _R2T_SNACK, _DATA_SNACK, or _STATUS_SNACK
 * begrun:    first DataSN / R2TSN to retransmit
 * runlength: number of PDUs to retransmit (0 = through last)
 */
int recovery_send_snack(iscsi_conn_t *conn, iscsi_session_t *sess,
                         uint32_t itt, uint32_t ttt,
                         uint8_t type, uint32_t begrun, uint32_t runlength);
