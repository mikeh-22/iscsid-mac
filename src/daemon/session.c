/*
 * session.c - iSCSI session management
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "session.h"
#include "auth.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * ISID generation
 * ----------------------------------------------------------------------- */

static int isid_random(uint8_t isid[6])
{
    /* Use RANDOM qualifier type (0x80) per RFC 7143 §10.12.5.
     * Bytes: T=10b | R | R | R | R | R  (6 bytes)
     */
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        fprintf(stderr, "session: cannot open /dev/urandom: %s\n",
                strerror(errno));
        return -1;
    }
    int ok = (fread(isid, 1, 6, fp) == 6);
    fclose(fp);
    if (!ok) {
        fprintf(stderr, "session: short read from /dev/urandom\n");
        return -1;
    }
    /* Set qualifier type bits: top 2 bits of byte 0 = RANDOM (0b10) */
    isid[0] = (isid[0] & 0x3f) | ISCSI_ISID_RANDOM;
    return 0;
}

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

iscsi_session_t *session_create(sess_type_t type,
                                 const char *initiator_name,
                                 const char *target_name,
                                 const char *target_address)
{
    iscsi_session_t *sess = calloc(1, sizeof(*sess));
    if (!sess) return NULL;

    sess->type  = type;
    sess->state = SESS_STATE_FREE;
    sess->tsih  = 0;   /* assigned by target at login */

    snprintf(sess->initiator_name, sizeof(sess->initiator_name),
             "%s", initiator_name ? initiator_name : "iqn.2024-01.io.iscsid-mac:initiator");
    snprintf(sess->target_name, sizeof(sess->target_name),
             "%s", target_name ? target_name : "");
    snprintf(sess->target_address, sizeof(sess->target_address),
             "%s", target_address ? target_address : "");

    /* Defaults from RFC 7143 §12 */
    sess->params.max_connections      = ISCSI_DEFAULT_MAX_CONNECTIONS;
    sess->params.initial_r2t          = ISCSI_DEFAULT_INITIAL_R2T;
    sess->params.immediate_data       = ISCSI_DEFAULT_IMMEDIATE_DATA;
    sess->params.max_burst_length     = ISCSI_DEFAULT_MAX_BURST_LENGTH;
    sess->params.first_burst_length   = ISCSI_DEFAULT_FIRST_BURST_LENGTH;
    sess->params.max_outstanding_r2t  = ISCSI_DEFAULT_MAX_OUTSTANDING_R2T;
    sess->params.data_pdu_in_order    = ISCSI_DEFAULT_DATA_PDU_IN_ORDER;
    sess->params.data_seq_in_order    = ISCSI_DEFAULT_DATA_SEQ_IN_ORDER;
    sess->params.default_time2wait    = ISCSI_DEFAULT_TIME2WAIT;
    sess->params.default_time2retain  = ISCSI_DEFAULT_TIME2RETAIN;
    sess->params.max_recv_dsl         = ISCSI_DEFAULT_MAX_RECV_DSL;
    sess->params.error_recovery_level = ISCSI_DEFAULT_ERROR_RECOVERY_LEVEL;

    /* Start CmdSN at 1 */
    sess->cmd_sn = 1;

    pthread_mutex_init(&sess->lock, NULL);

    if (isid_random(sess->isid) != 0) {
        free(sess);
        return NULL;
    }

    return sess;
}

void session_destroy(iscsi_session_t *sess)
{
    if (!sess) return;
    /* Destroy all connections */
    iscsi_conn_t *c = sess->connections;
    while (c) {
        iscsi_conn_t *next = c->next;
        conn_destroy(c);
        c = next;
    }
    pthread_mutex_destroy(&sess->lock);
    free(sess);
}

/* -----------------------------------------------------------------------
 * Connection management
 * ----------------------------------------------------------------------- */

void session_add_conn(iscsi_session_t *sess, iscsi_conn_t *conn)
{
    pthread_mutex_lock(&sess->lock);
    conn->session = sess;
    conn->next    = sess->connections;
    sess->connections = conn;
    sess->num_connections++;
    pthread_mutex_unlock(&sess->lock);
}

iscsi_conn_t *session_take_conn(iscsi_session_t *sess)
{
    pthread_mutex_lock(&sess->lock);
    iscsi_conn_t *c = sess->connections;
    if (c) {
        sess->connections = c->next;
        c->next = NULL;
        sess->num_connections--;
    }
    pthread_mutex_unlock(&sess->lock);
    return c;
}

iscsi_conn_t *session_lead_conn(iscsi_session_t *sess)
{
    /* No lock needed for read-only peek (single-writer scenario) */
    return sess->connections;
}

/* -----------------------------------------------------------------------
 * Sequence numbers
 * ----------------------------------------------------------------------- */

uint32_t session_next_cmdsn(iscsi_session_t *sess)
{
    pthread_mutex_lock(&sess->lock);
    uint32_t sn = sess->cmd_sn++;
    pthread_mutex_unlock(&sess->lock);
    return sn;
}

void session_update_sn(iscsi_session_t *sess,
                        uint32_t statsn __attribute__((unused)),
                        uint32_t expcmdsn, uint32_t maxcmdsn)
{
    pthread_mutex_lock(&sess->lock);
    sess->exp_cmd_sn = expcmdsn;
    sess->max_cmd_sn = maxcmdsn;
    pthread_mutex_unlock(&sess->lock);
}

void session_set_isid(iscsi_session_t *sess, const uint8_t isid[6])
{
    if (isid) {
        memcpy(sess->isid, isid, 6);
    } else {
        (void)isid_random(sess->isid);   /* best-effort; session already up */
    }
}

/* -----------------------------------------------------------------------
 * String representations
 * ----------------------------------------------------------------------- */

const char *sess_state_str(sess_state_t state)
{
    switch (state) {
    case SESS_STATE_FREE:        return "FREE";
    case SESS_STATE_LOGGING_IN:  return "LOGGING_IN";
    case SESS_STATE_LOGGED_IN:   return "LOGGED_IN";
    case SESS_STATE_LOGGING_OUT: return "LOGGING_OUT";
    case SESS_STATE_FAILED:      return "FAILED";
    default:                     return "UNKNOWN";
    }
}

const char *sess_type_str(sess_type_t type)
{
    switch (type) {
    case SESS_TYPE_DISCOVERY: return "Discovery";
    case SESS_TYPE_NORMAL:    return "Normal";
    default:                  return "Unknown";
    }
}
