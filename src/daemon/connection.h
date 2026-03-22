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
#include <time.h>
#include <netinet/in.h>

#define ISCSI_CONN_RECV_BUFSIZE       (256 * 1024)
#define ISCSI_CONN_RECV_TIMEOUT_SEC   30    /* SO_RCVTIMEO for pdu_recv / scsi_exec */
#define ISCSI_KEEPALIVE_IDLE_SEC      25    /* send NOP-Out if conn silent this long */

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

    /* Keepalive: timestamp of last successful PDU send or receive */
    time_t          last_activity;

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
 * Close conn->fd and reconnect to a new host:port, preserving the conn struct.
 * Applies the same socket options as conn_create().  Resets connection-scoped
 * state (exp_statsn, digest settings) so the login FSM can restart cleanly.
 *
 * Returns 0 on success, -1 on failure (conn->state set to CONN_STATE_FAILED).
 */
int conn_reconnect(iscsi_conn_t *conn, const char *host, uint16_t port);

/*
 * Get a human-readable description of connection state.
 */
const char *conn_state_str(conn_state_t state);

/*
 * Parse a portal address string into host and port components.
 *
 * Handles:
 *   IPv4 / hostname:  "host:port"  or  "host"  (default port)
 *   IPv6 bracketed:   "[::1]:port" or  "[::1]" (default port)
 *   Group tag suffix: "host:port,groupTag" → stripped before parsing
 *
 * host is written as a NUL-terminated string into host_out[0..host_size-1].
 * *port_out receives the parsed port, or ISCSI_PORT if none is present.
 *
 * Returns 0 on success, -1 if the address format is unrecognisable or the
 * port is out of range [1, 65535].
 */
int iscsi_parse_portal(const char *addr,
                       char *host_out, size_t host_size,
                       uint16_t *port_out);
