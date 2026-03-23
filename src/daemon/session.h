/*
 * session.h - iSCSI session management
 *
 * An iSCSI session is uniquely identified by (InitiatorName, TargetName, TSIH).
 * It aggregates one or more TCP connections and owns the sequence number space.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "connection.h"
#include "auth.h"
#include "../shared/iscsi_protocol.h"
#include <stdint.h>
#include <pthread.h>

#define ISCSI_MAX_CONNS_PER_SESSION  32

typedef enum {
    SESS_TYPE_DISCOVERY = 0,
    SESS_TYPE_NORMAL,
} sess_type_t;

typedef enum {
    SESS_STATE_FREE = 0,
    SESS_STATE_LOGGING_IN,
    SESS_STATE_LOGGED_IN,
    SESS_STATE_LOGGING_OUT,
    SESS_STATE_FAILED,
} sess_state_t;

/* Operational parameters negotiated during login */
typedef struct {
    uint32_t    max_connections;        /* MaxConnections */
    int         initial_r2t;            /* InitialR2T */
    int         immediate_data;         /* ImmediateData */
    uint32_t    max_burst_length;       /* MaxBurstLength */
    uint32_t    first_burst_length;     /* FirstBurstLength */
    uint32_t    max_outstanding_r2t;    /* MaxOutstandingR2T */
    int         data_pdu_in_order;      /* DataPDUInOrder */
    int         data_seq_in_order;      /* DataSequenceInOrder */
    uint32_t    default_time2wait;      /* DefaultTime2Wait */
    uint32_t    default_time2retain;    /* DefaultTime2Retain */
    uint32_t    max_recv_dsl;           /* MaxRecvDataSegmentLength */
    int         error_recovery_level;   /* ErrorRecoveryLevel */

    /* TCP keepalive parameters (applied to every connection in this session) */
    int         tcp_keepalive_idle;     /* TCP_KEEPALIVE idle time (seconds) */
    int         tcp_keepalive_interval; /* TCP_KEEPINTVL (seconds) */
    int         tcp_keepalive_count;    /* TCP_KEEPCNT */
} iscsi_op_params_t;

struct iscsi_session {
    sess_type_t     type;
    sess_state_t    state;

    /* Session identifiers */
    uint8_t         isid[6];            /* Initiator Session ID */
    uint16_t        tsih;               /* Target Session Identifying Handle */
    char            target_name[ISCSI_MAX_NAME_LEN];
    char            initiator_name[ISCSI_MAX_NAME_LEN];
    char            target_alias[ISCSI_MAX_NAME_LEN];
    char            target_address[256]; /* host:port */

    /* Sequence numbers */
    uint32_t        cmd_sn;             /* next CmdSN to send */
    uint32_t        exp_cmd_sn;         /* target's ExpCmdSN */
    uint32_t        max_cmd_sn;         /* target's MaxCmdSN */
    uint32_t        exp_statsn;         /* per connection, tracked in conn */

    /* Connections */
    iscsi_conn_t   *connections;        /* linked list */
    uint32_t        num_connections;

    /* Negotiated parameters */
    iscsi_op_params_t params;

    /* Auth */
    char            chap_username[128];
    char            chap_secret[CHAP_MAX_SECRET_LEN];
    char            chap_target_secret[CHAP_MAX_SECRET_LEN];

    /* Login redirect: set by recv_login() on status_class==0x01 */
    char            redirect_addr[300];   /* "host:port" (group tag stripped) */

    /* ITT and CID allocators */
    uint32_t        next_itt;           /* wraps at 0xFFFFFFFE, never 0xFFFFFFFF */
    uint16_t        next_cid;           /* starts at 1, increments per connection */

    /* Thread safety */
    pthread_mutex_t lock;

    /* Protected by g_sessions_lock in main.c.
     *
     * recovery_in_progress: non-zero while an ERL-1 recovery thread is active.
     *   Prevents spawning duplicate recovery attempts on rapid failure events.
     *
     * busy_count: incremented by IPC handlers (luns, add_conn) before they
     *   drop g_sessions_lock to perform blocking network I/O that references
     *   this session.  Decremented (and recovery_done broadcast) when done.
     *
     * The logout handler waits (with a 5 s timeout) for both to reach zero
     * before calling session_destroy(), preventing use-after-free. */
    volatile int    recovery_in_progress;
    uint32_t        busy_count;
    pthread_cond_t  recovery_done;

    /*
     * scsi_recovery_cond: broadcast under sess->lock when recovery_in_progress
     * transitions to 0.  Used by session_wait_recovery() so that scsi_exec()
     * can block until ERL-1 reconnect finishes, then retry the command on the
     * new connection.  (recovery_done above is broadcast under g_sessions_lock
     * and is used by the logout handler in main.c; these are separate conds to
     * keep the locking domains independent.)
     */
    pthread_cond_t  scsi_recovery_cond;

    /*
     * cmd_window_cond: broadcast under sess->lock whenever max_cmd_sn advances.
     * session_next_cmdsn() waits on this when the CmdSN window is full
     * (RFC 7143 §3.6, serial arithmetic per RFC 1982).
     */
    pthread_cond_t  cmd_window_cond;

    /* Linked list */
    struct iscsi_session *next;
};

/* Default operational parameters (RFC 7143 §12) */
#define ISCSI_DEFAULT_MAX_CONNECTIONS       1
#define ISCSI_DEFAULT_INITIAL_R2T           1
#define ISCSI_DEFAULT_IMMEDIATE_DATA        1
#define ISCSI_DEFAULT_MAX_BURST_LENGTH      262144
#define ISCSI_DEFAULT_FIRST_BURST_LENGTH    65536
#define ISCSI_DEFAULT_MAX_OUTSTANDING_R2T   1
#define ISCSI_DEFAULT_DATA_PDU_IN_ORDER     1
#define ISCSI_DEFAULT_DATA_SEQ_IN_ORDER     1
#define ISCSI_DEFAULT_TIME2WAIT             2
#define ISCSI_DEFAULT_TIME2RETAIN           20
#define ISCSI_DEFAULT_MAX_RECV_DSL          262144
#define ISCSI_DEFAULT_ERROR_RECOVERY_LEVEL  0

/*
 * Allocate a new session with default parameters.
 * type: SESS_TYPE_DISCOVERY or SESS_TYPE_NORMAL
 */
iscsi_session_t *session_create(sess_type_t type,
                                 const char *initiator_name,
                                 const char *target_name,
                                 const char *target_address);

/* Free a session and all its connections. */
void session_destroy(iscsi_session_t *sess);

/* Add a connection to a session. */
void session_add_conn(iscsi_session_t *sess, iscsi_conn_t *conn);

/* Remove and return the leading connection from a session. */
iscsi_conn_t *session_take_conn(iscsi_session_t *sess);

/* Get the "lead" connection (first in list) or NULL. */
iscsi_conn_t *session_lead_conn(iscsi_session_t *sess);

/* Atomically fetch-and-increment CmdSN for a new command. */
uint32_t session_next_cmdsn(iscsi_session_t *sess);

/* Update session window from a received PDU's header fields. */
void session_update_sn(iscsi_session_t *sess,
                        uint32_t statsn, uint32_t expcmdsn, uint32_t maxcmdsn);

/* Set the ISID bytes (generates a random ISID if isid == NULL). */
void session_set_isid(iscsi_session_t *sess, const uint8_t isid[6]);

/* Allocate a unique ITT for a new command (never issues 0xFFFFFFFF). */
uint32_t session_next_itt(iscsi_session_t *sess);

/* Allocate the next connection ID (starts at 1, wraps at 65534). */
uint16_t session_next_cid(iscsi_session_t *sess);

/*
 * Wait for an in-progress ERL-1 recovery to complete.
 *
 * Blocks (releasing no external locks) until recovery_in_progress clears or
 * timeout_sec elapses.  Must NOT be called with sess->lock or g_sessions_lock
 * held.
 *
 * Returns 0 if the session is back in LOGGED_IN state, -1 otherwise
 * (timeout or recovery failed).
 */
int session_wait_recovery(iscsi_session_t *sess, unsigned timeout_sec);

/*
 * Broadcast scsi_recovery_cond to wake any session_wait_recovery() callers.
 * Called by main.c's recovery_thread after clearing recovery_in_progress.
 * Must NOT be called with sess->lock held.
 */
void session_signal_recovery(iscsi_session_t *sess);

/* String representations */
const char *sess_state_str(sess_state_t state);
const char *sess_type_str(sess_type_t type);
