/*
 * connection.h - iSCSI TCP connection management
 *
 * A "connection" is a single TCP stream between initiator and target.
 * One or more connections form a session.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <netinet/in.h>

#define ISCSI_CONN_RECV_BUFSIZE  (256 * 1024)

typedef enum {
    CONN_STATE_FREE = 0,
    CONN_STATE_CONNECTING,
    CONN_STATE_IN_LOGIN,
    CONN_STATE_LOGGED_IN,
    CONN_STATE_IN_LOGOUT,
    CONN_STATE_FAILED,
} conn_state_t;

typedef struct iscsi_session iscsi_session_t;  /* forward */

typedef struct iscsi_conn {
    int             fd;             /* TCP socket file descriptor */
    conn_state_t    state;
    uint16_t        cid;            /* Connection ID (assigned by us) */
    uint32_t        exp_statsn;     /* ExpStatSN we track from target */

    /* Parameters negotiated during login */
    uint32_t        max_recv_dsl;   /* MaxRecvDataSegmentLength (our limit) */
    uint32_t        max_send_dsl;   /* target's MaxRecvDataSegmentLength */
    int             header_digest;  /* 0=None, 1=CRC32C */
    int             data_digest;    /* 0=None, 1=CRC32C */
    int             if_marker;      /* IFMarker */
    int             of_marker;      /* OFMarker */

    /* Back-pointer */
    iscsi_session_t *session;

    /* Linked list (within session) */
    struct iscsi_conn *next;
} iscsi_conn_t;

/*
 * Allocate and connect a new TCP connection to host:port.
 * Returns a connected iscsi_conn_t on success, NULL on failure.
 */
iscsi_conn_t *conn_create(const char *host, uint16_t port);

/*
 * Close and free a connection.  Safe to call with conn == NULL.
 */
void conn_destroy(iscsi_conn_t *conn);

/*
 * Enable TCP keepalive on the socket.
 */
int conn_set_keepalive(iscsi_conn_t *conn, int idle_sec,
                        int interval_sec, int probe_count);

/*
 * Disable Nagle (TCP_NODELAY) for lower latency.
 */
int conn_set_nodelay(iscsi_conn_t *conn);

/*
 * Get a human-readable description of connection state.
 */
const char *conn_state_str(conn_state_t state);
