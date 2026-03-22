/*
 * login.h - iSCSI login state machine (RFC 7143 §6.3)
 *
 * Drives the complete login sequence:
 *   SecurityNegotiation → LoginOperationalNegotiation → FullFeaturePhase
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "session.h"
#include "connection.h"

/* Login result codes */
typedef enum {
    LOGIN_OK = 0,
    LOGIN_AUTH_FAILED   = -1,
    LOGIN_IO_ERROR      = -2,
    LOGIN_PROTO_ERROR   = -3,
    LOGIN_TARGET_ERROR  = -4,
    LOGIN_NO_RESOURCES  = -5,
    LOGIN_REDIRECTED    = -6,   /* internal: target sent a redirect (class 0x01) */
} login_result_t;

/* Maximum number of consecutive login redirects before giving up */
#define ISCSI_LOGIN_MAX_REDIRECTS  3

/*
 * Perform the full login sequence on conn for sess.
 *
 * On success the connection transitions to CONN_STATE_LOGGED_IN and the
 * session's TSIH / sequence numbers are updated.
 *
 * Returns LOGIN_OK on success, or a negative login_result_t on failure.
 */
login_result_t iscsi_login(iscsi_session_t *sess, iscsi_conn_t *conn);

/*
 * Send a Logout Request and wait for the Logout Response.
 * reason: one of ISCSI_LOGOUT_CLOSE_SESSION, ISCSI_LOGOUT_CLOSE_CONNECTION.
 * Returns 0 on success, -1 on error.
 */
int iscsi_logout(iscsi_session_t *sess, iscsi_conn_t *conn, uint8_t reason);

/*
 * Add a new connection to an already-logged-in session (MCS / ERL-1).
 *
 * The session must be in LOGGED_IN state with a valid non-zero TSIH.
 * conn->cid must be set to the new connection's CID before calling
 * (use session_next_cid()).
 *
 * The login PDU uses the existing ISID and TSIH so the target associates
 * the new connection with the running session instead of creating a new one.
 *
 * Returns LOGIN_OK on success, or a negative login_result_t on failure.
 */
login_result_t iscsi_login_add_conn(iscsi_session_t *sess, iscsi_conn_t *conn);

/* Human-readable login result */
const char *login_result_str(login_result_t r);
