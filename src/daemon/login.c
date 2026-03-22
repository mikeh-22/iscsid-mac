/*
 * login.c - iSCSI login state machine (RFC 7143 §6.3)
 *
 * Login sequence (RFC 7143 §6.3.3):
 *   A stage transition occurs when BOTH sides set T=1 with the same NSG.
 *
 * No-auth flow (2 round-trips):
 *   I→T  CSG=Sec,  T=0: AuthMethod=None, InitiatorName, SessionType
 *   T→I  CSG=Sec,  T=1, NSG=OpNeg: AuthMethod=None
 *   I→T  CSG=Sec,  T=1, NSG=OpNeg: (confirm transit)
 *   T→I  CSG=OpNeg,T=1, NSG=FFP:   (operational params negotiated)
 *   -- OR target may respond to the T=1 confirm with its own OpNeg params,
 *      requiring one more round-trip --
 *
 * CHAP flow: adds 2 extra round-trips between the two security PDUs.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "login.h"
#include "auth.h"
#include "connection.h"
#include "pdu.h"
#include "../shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static void build_login_req(iscsi_login_req_t *req,
                             const iscsi_session_t *sess,
                             const iscsi_conn_t    *conn,
                             uint8_t csg, uint8_t nsg, int transit,
                             uint32_t data_len)
{
    memset(req, 0, sizeof(*req));
    req->opcode      = ISCSI_OP_LOGIN_REQ | ISCSI_OP_IMMEDIATE;
    req->flags       = iscsi_login_flags(transit, 0, csg, nsg);
    req->max_version = ISCSI_DRAFT20_VERSION;
    req->min_version = ISCSI_DRAFT20_VERSION;
    iscsi_dlength_set(req->dlength, data_len);
    memcpy(req->isid, sess->isid, 6);
    req->tsih      = htons(sess->tsih);
    req->itt       = htonl(1);
    req->cid       = htons(conn->cid);
    req->cmdsn     = htonl(sess->cmd_sn);
    req->expstatsn = htonl(conn->exp_statsn);
}

static int send_login(iscsi_conn_t *conn, iscsi_session_t *sess,
                      uint8_t csg, uint8_t nsg, int transit,
                      const char *kv, uint32_t kv_len)
{
    iscsi_pdu_t pdu;
    pdu_init(&pdu, ISCSI_OP_LOGIN_REQ | ISCSI_OP_IMMEDIATE, 0);
    build_login_req((iscsi_login_req_t *)&pdu.hdr,
                    sess, conn, csg, nsg, transit, kv_len);
    if (kv_len > 0) pdu_set_data_ref(&pdu, kv, kv_len);
    /* Digests are negotiated during login but take effect only in FFP */
    return pdu_send(conn->fd, &pdu, 0, 0);
}

/* Receive one login response.  Updates conn->exp_statsn and session SN window.
 * Returns 0 on success, or a negative login_result_t on failure. */
static int recv_login(iscsi_conn_t *conn, iscsi_session_t *sess,
                      iscsi_pdu_t *pdu_out)
{
    /* Digests not yet active during login phase */
    int rc = pdu_recv(conn->fd, pdu_out, 0, 0);
    if (rc) return LOGIN_IO_ERROR;

    iscsi_login_rsp_t *rsp = (iscsi_login_rsp_t *)&pdu_out->hdr;
    if ((rsp->opcode & 0x3f) != ISCSI_OP_LOGIN_RSP) {
        syslog(LOG_ERR, "login: expected login response opcode, got 0x%02x",
               rsp->opcode & 0x3f);
        pdu_free_data(pdu_out);
        return LOGIN_PROTO_ERROR;
    }

    if (rsp->status_class != 0) {
        if (rsp->status_class == 0x01) {
            /*
             * Login redirect (RFC 7143 §10.13.5, status class 0x01).
             * Extract TargetAddress="host:port[,groupTag]", strip the
             * optional group tag, and store in sess->redirect_addr so the
             * caller can reconnect and retry.
             */
            if (pdu_out->data_len > 0) {
                const char *ta = pdu_kv_get((char *)pdu_out->data,
                                             pdu_out->data_len, "TargetAddress");
                if (ta) {
                    snprintf(sess->redirect_addr, sizeof(sess->redirect_addr),
                             "%s", ta);
                    /* Strip ",groupTag" suffix */
                    char *comma = strrchr(sess->redirect_addr, ',');
                    if (comma) *comma = '\0';
                }
            }
            syslog(LOG_NOTICE, "login: redirect to %s", sess->redirect_addr);
            pdu_free_data(pdu_out);
            return LOGIN_REDIRECTED;
        }
        syslog(LOG_WARNING, "login: failed status 0x%02x%02x (class=%u detail=%u)",
               rsp->status_class, rsp->status_detail,
               rsp->status_class, rsp->status_detail);
        pdu_free_data(pdu_out);
        switch (rsp->status_class) {
        case 0x02: return LOGIN_AUTH_FAILED;
        case 0x03: return LOGIN_NO_RESOURCES;
        default:   return LOGIN_TARGET_ERROR;
        }
    }

    /*
     * sess->tsih is written here without sess->lock.  This is safe because
     * login is always called from a single IPC worker thread before the
     * session is registered in g_sessions (and thus before the kqueue thread
     * can observe it).  No concurrent access is possible at this point.
     */
    if (sess->tsih == 0 && rsp->tsih != 0)
        sess->tsih = ntohs(rsp->tsih);

    conn->exp_statsn = ntohl(rsp->statsn) + 1;
    session_update_sn(sess, ntohl(rsp->statsn),
                      ntohl(rsp->expcmdsn), ntohl(rsp->maxcmdsn));
    return 0;
}

/* -----------------------------------------------------------------------
 * Security phase — No authentication
 * ----------------------------------------------------------------------- */

static int login_auth_none(iscsi_session_t *sess, iscsi_conn_t *conn)
{
    char kv[4096];
    int  used = 0;
    int  rc;

    /*
     * RFC 7143 §6.3.3: the target can only set T=1 in its response if the
     * initiator set T=1 in the request.  For AuthMethod=None we know we are
     * ready to transit immediately, so set T=1 and NSG=OpNeg in the very
     * first security PDU.  The target echoes T=1 to confirm the transition
     * and we proceed directly to operational negotiation.
     */
    used = pdu_kv_append(kv, sizeof(kv), used, "AuthMethod", "None");
    used = pdu_kv_append(kv, sizeof(kv), used, "InitiatorName", sess->initiator_name);
    if (sess->target_name[0])
        used = pdu_kv_append(kv, sizeof(kv), used, "TargetName", sess->target_name);
    used = pdu_kv_append(kv, sizeof(kv), used, "SessionType",
                         sess->type == SESS_TYPE_DISCOVERY ? "Discovery" : "Normal");

    rc = send_login(conn, sess,
                    ISCSI_SECURITY_NEGOTIATION,
                    ISCSI_LOGIN_OPERATIONAL_NEG,
                    1 /* transit */, kv, (uint32_t)used);
    if (rc) return LOGIN_IO_ERROR;

    iscsi_pdu_t rsp1;
    rc = recv_login(conn, sess, &rsp1);
    if (rc) return rc;

    iscsi_login_rsp_t *r1 = (iscsi_login_rsp_t *)&rsp1.hdr;

    if (rsp1.data_len)
        pdu_kv_get_str((char *)rsp1.data, rsp1.data_len, "TargetAlias",
                       sess->target_alias, sizeof(sess->target_alias));

    /* Check if the target jumped all the way to FFP in one shot */
    uint8_t r1_csg = iscsi_login_csg(r1->flags);
    int r1_transit = (r1->flags & ISCSI_LOGIN_TRANSIT) != 0;
    uint8_t r1_nsg = iscsi_login_nsg(r1->flags);

    pdu_free_data(&rsp1);

    if (r1_transit && r1_nsg == ISCSI_FULL_FEATURE_PHASE) {
        /* Target combined OpNeg and FFP — login complete, skip OpNeg phase */
        return 0;
    }

    (void)r1_csg;   /* we are now in OpNeg regardless */
    return 0;
}

/* -----------------------------------------------------------------------
 * Security phase — CHAP
 * ----------------------------------------------------------------------- */

static int login_auth_chap(iscsi_session_t *sess, iscsi_conn_t *conn)
{
    char kv[4096];
    int  used, rc;

    chap_ctx_t chap;
    memset(&chap, 0, sizeof(chap));   /* initialized after algorithm is negotiated */

    /* Round 1: propose CHAP, get target's algorithm selection */
    used = 0;
    used = pdu_kv_append(kv, sizeof(kv), used, "AuthMethod", "CHAP");
    used = pdu_kv_append(kv, sizeof(kv), used, "InitiatorName", sess->initiator_name);
    if (sess->target_name[0])
        used = pdu_kv_append(kv, sizeof(kv), used, "TargetName", sess->target_name);
    used = pdu_kv_append(kv, sizeof(kv), used, "SessionType",
                         sess->type == SESS_TYPE_DISCOVERY ? "Discovery" : "Normal");

    rc = send_login(conn, sess, ISCSI_SECURITY_NEGOTIATION,
                    ISCSI_SECURITY_NEGOTIATION, 0, kv, (uint32_t)used);
    if (rc) return LOGIN_IO_ERROR;

    iscsi_pdu_t rsp1;
    rc = recv_login(conn, sess, &rsp1);
    if (rc) return rc;
    pdu_free_data(&rsp1);

    /* Round 2: offer SHA-256 (preferred) and MD5 (mandatory fallback) per RFC 7143 */
    used = 0;
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_A", "7,5");
    rc = send_login(conn, sess, ISCSI_SECURITY_NEGOTIATION,
                    ISCSI_SECURITY_NEGOTIATION, 0, kv, (uint32_t)used);
    if (rc) return LOGIN_IO_ERROR;

    iscsi_pdu_t rsp2;
    rc = recv_login(conn, sess, &rsp2);
    if (rc) return rc;

    /* Determine which algorithm the target selected and initialise context */
    uint32_t selected_alg = (uint32_t)CHAP_ALG_MD5;   /* default if not echoed */
    pdu_kv_get_int((char *)rsp2.data, rsp2.data_len, "CHAP_A", &selected_alg);

    chap_alg_t alg;
    if (selected_alg == (uint32_t)CHAP_ALG_SHA256) {
        alg = CHAP_ALG_SHA256;
    } else if (selected_alg == (uint32_t)CHAP_ALG_MD5) {
        alg = CHAP_ALG_MD5;
    } else {
        syslog(LOG_WARNING, "login: target selected unknown CHAP algorithm %u",
               selected_alg);
        pdu_free_data(&rsp2);
        return LOGIN_AUTH_FAILED;
    }
    chap_init(&chap, alg, sess->chap_secret,
              sess->chap_target_secret[0] ? sess->chap_target_secret : NULL);

    /* Parse target's CHAP challenge (context now has the correct algorithm) */
    rc = chap_parse_challenge(&chap, (char *)rsp2.data, rsp2.data_len);
    pdu_free_data(&rsp2);
    if (rc) return LOGIN_AUTH_FAILED;

    /* Round 3: send CHAP response, transit to OpNeg */
    char resp_hex[CHAP_MAX_RESPONSE_LEN * 2 + 4];
    if (chap_compute_response(&chap, resp_hex, sizeof(resp_hex)) != 0)
        return LOGIN_AUTH_FAILED;

    used = 0;
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_N",
                         sess->chap_username[0] ? sess->chap_username
                                                : sess->initiator_name);
    used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_R", resp_hex);

    int mutual = (sess->chap_target_secret[0] != '\0');
    char mutual_i[16] = {0}, mutual_c[CHAP_MAX_CHALLENGE_LEN * 2 + 4] = {0};
    if (mutual) {
        if (chap_generate_mutual_challenge(&chap,
                                            mutual_i, sizeof(mutual_i),
                                            mutual_c, sizeof(mutual_c)) == 0) {
            used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_I", mutual_i);
            used = pdu_kv_append(kv, sizeof(kv), used, "CHAP_C", mutual_c);
        }
    }

    rc = send_login(conn, sess, ISCSI_SECURITY_NEGOTIATION,
                    ISCSI_LOGIN_OPERATIONAL_NEG, 1, kv, (uint32_t)used);
    if (rc) return LOGIN_IO_ERROR;

    iscsi_pdu_t rsp3;
    rc = recv_login(conn, sess, &rsp3);
    if (rc) return rc;

    if (mutual) {
        const char *tr = pdu_kv_get((char *)rsp3.data, rsp3.data_len, "CHAP_R");
        uint32_t tid = 0;
        pdu_kv_get_int((char *)rsp3.data, rsp3.data_len, "CHAP_I", &tid);
        if (!tr || chap_verify_mutual(&chap, (uint8_t)tid, tr) != 0) {
            syslog(LOG_WARNING, "login: mutual CHAP verification failed");
            pdu_free_data(&rsp3);
            return LOGIN_AUTH_FAILED;
        }
    }

    pdu_kv_get_str((char *)rsp3.data, rsp3.data_len, "TargetAlias",
                   sess->target_alias, sizeof(sess->target_alias));
    pdu_free_data(&rsp3);

    /* Wipe CHAP secrets from the stack now that authentication is done */
    chap_clear(&chap);
    return 0;
}

/* -----------------------------------------------------------------------
 * Operational Negotiation phase
 * ----------------------------------------------------------------------- */

static int login_operational(iscsi_session_t *sess, iscsi_conn_t *conn)
{
    char kv[8192];
    int  used = 0;
    char tmp[32];
    int  rc;

    snprintf(tmp, sizeof(tmp), "%u", conn->max_recv_dsl);
    used = pdu_kv_append(kv, sizeof(kv), used, "MaxRecvDataSegmentLength", tmp);

    snprintf(tmp, sizeof(tmp), "%u", sess->params.max_burst_length);
    used = pdu_kv_append(kv, sizeof(kv), used, "MaxBurstLength", tmp);

    snprintf(tmp, sizeof(tmp), "%u", sess->params.first_burst_length);
    used = pdu_kv_append(kv, sizeof(kv), used, "FirstBurstLength", tmp);

    used = pdu_kv_append(kv, sizeof(kv), used, "InitialR2T",
                         sess->params.initial_r2t ? "Yes" : "No");
    used = pdu_kv_append(kv, sizeof(kv), used, "ImmediateData",
                         sess->params.immediate_data ? "Yes" : "No");
    used = pdu_kv_append(kv, sizeof(kv), used, "DataPDUInOrder",
                         sess->params.data_pdu_in_order ? "Yes" : "No");
    used = pdu_kv_append(kv, sizeof(kv), used, "DataSequenceInOrder",
                         sess->params.data_seq_in_order ? "Yes" : "No");

    snprintf(tmp, sizeof(tmp), "%u", sess->params.max_outstanding_r2t);
    used = pdu_kv_append(kv, sizeof(kv), used, "MaxOutstandingR2T", tmp);

    snprintf(tmp, sizeof(tmp), "%u", sess->params.error_recovery_level);
    used = pdu_kv_append(kv, sizeof(kv), used, "ErrorRecoveryLevel", tmp);

    /* Offer CRC32C as preferred; fall back to None if target declines */
    used = pdu_kv_append(kv, sizeof(kv), used, "HeaderDigest", "CRC32C,None");
    used = pdu_kv_append(kv, sizeof(kv), used, "DataDigest",   "CRC32C,None");

    if (sess->type == SESS_TYPE_NORMAL) {
        /* Offer our maximum; the negotiated minimum wins.
         * This enables MCS when the target supports it. */
        snprintf(tmp, sizeof(tmp), "%u", ISCSI_MAX_CONNS_PER_SESSION);
        used = pdu_kv_append(kv, sizeof(kv), used, "MaxConnections", tmp);
    }

    rc = send_login(conn, sess,
                    ISCSI_LOGIN_OPERATIONAL_NEG,
                    ISCSI_FULL_FEATURE_PHASE,
                    1, kv, (uint32_t)used);
    if (rc) return LOGIN_IO_ERROR;

    iscsi_pdu_t rsp;
    rc = recv_login(conn, sess, &rsp);
    if (rc) return rc;

    /* Parse and validate negotiated values from target's response.
     * All numeric parameters from the network are bounds-checked to prevent
     * a malicious target from inducing oversized allocations or arithmetic
     * overflows when the values are later used as buffer sizes. */
    uint32_t ival;
    if (rsp.data_len) {
        /* RFC 7143 §12: MaxRecvDataSegmentLength 512..2^24-1 */
        if (pdu_kv_get_int((char *)rsp.data, rsp.data_len,
                           "MaxRecvDataSegmentLength", &ival) == 0) {
            if (ival < 512 || ival > ISCSI_MAX_RECV_SEG_LEN) {
                syslog(LOG_WARNING, "login: target MaxRecvDataSegmentLength %u "
                       "out of range [512, %u]", ival, ISCSI_MAX_RECV_SEG_LEN);
                pdu_free_data(&rsp);
                return LOGIN_PROTO_ERROR;
            }
            conn->max_send_dsl = ival;
        }
        /* RFC 7143 §12: MaxBurstLength 512..2^24-1 */
        if (pdu_kv_get_int((char *)rsp.data, rsp.data_len,
                           "MaxBurstLength", &ival) == 0) {
            if (ival < 512 || ival > ISCSI_MAX_RECV_SEG_LEN) {
                syslog(LOG_WARNING, "login: target MaxBurstLength %u "
                       "out of range", ival);
                pdu_free_data(&rsp);
                return LOGIN_PROTO_ERROR;
            }
            sess->params.max_burst_length = ival;
        }
        /* RFC 7143 §12: FirstBurstLength 512..MaxBurstLength */
        if (pdu_kv_get_int((char *)rsp.data, rsp.data_len,
                           "FirstBurstLength", &ival) == 0) {
            if (ival < 512 || ival > sess->params.max_burst_length) {
                syslog(LOG_WARNING, "login: target FirstBurstLength %u "
                       "out of range", ival);
                pdu_free_data(&rsp);
                return LOGIN_PROTO_ERROR;
            }
            sess->params.first_burst_length = ival;
        }

        uint32_t ival2;
        if (pdu_kv_get_int((char *)rsp.data, rsp.data_len,
                           "MaxConnections", &ival2) == 0) {
            if (ival2 >= 1 && ival2 <= ISCSI_MAX_CONNS_PER_SESSION)
                sess->params.max_connections = ival2;
        }

        const char *v;
        if ((v = pdu_kv_get((char *)rsp.data, rsp.data_len, "InitialR2T")))
            sess->params.initial_r2t = (strcmp(v, "Yes") == 0);
        if ((v = pdu_kv_get((char *)rsp.data, rsp.data_len, "ImmediateData")))
            sess->params.immediate_data = (strcmp(v, "Yes") == 0);

        /* Digest selection: target echoes back a single value from our list */
        if ((v = pdu_kv_get((char *)rsp.data, rsp.data_len, "HeaderDigest")))
            conn->header_digest = (strcmp(v, "CRC32C") == 0) ? 1 : 0;
        if ((v = pdu_kv_get((char *)rsp.data, rsp.data_len, "DataDigest")))
            conn->data_digest   = (strcmp(v, "CRC32C") == 0) ? 1 : 0;
    }

    if (conn->header_digest || conn->data_digest) {
        printf("login: digests active —%s%s\n",
               conn->header_digest ? " HeaderDigest=CRC32C" : "",
               conn->data_digest   ? " DataDigest=CRC32C"   : "");
    }

    pdu_free_data(&rsp);
    return 0;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

login_result_t iscsi_login(iscsi_session_t *sess, iscsi_conn_t *conn)
{
    int rc;
    int redirects = 0;

retry:
    conn->state = CONN_STATE_IN_LOGIN;

    /* Security phase */
    if (sess->chap_secret[0]) {
        rc = login_auth_chap(sess, conn);
    } else {
        rc = login_auth_none(sess, conn);
    }

    if (rc == LOGIN_REDIRECTED) {
        if (redirects >= ISCSI_LOGIN_MAX_REDIRECTS) {
            syslog(LOG_WARNING, "login: too many redirects (%d), giving up",
                   ISCSI_LOGIN_MAX_REDIRECTS);
            conn->state = CONN_STATE_FAILED;
            return LOGIN_TARGET_ERROR;
        }
        char rhost[256];
        uint16_t rport;
        if (iscsi_parse_portal(sess->redirect_addr, rhost, sizeof(rhost), &rport) != 0) {
            syslog(LOG_ERR, "login: cannot parse redirect address '%s'",
                   sess->redirect_addr);
            conn->state = CONN_STATE_FAILED;
            return LOGIN_TARGET_ERROR;
        }
        if (conn_reconnect(conn, rhost, rport) != 0) {
            return LOGIN_TARGET_ERROR;   /* conn->state already set to FAILED */
        }
        /* New session on the redirected target — reset TSIH and all SN state */
        sess->tsih       = 0;
        sess->cmd_sn     = 1;
        sess->exp_cmd_sn = 0;
        sess->max_cmd_sn = 0;
        redirects++;
        goto retry;
    }

    if (rc) {
        conn->state = CONN_STATE_FAILED;
        return (login_result_t)rc;
    }

    /* Operational negotiation phase */
    rc = login_operational(sess, conn);
    if (rc) {
        conn->state = CONN_STATE_FAILED;
        return (login_result_t)rc;
    }

    /* sess->state written without sess->lock: see recv_login() comment above */
    conn->state = CONN_STATE_LOGGED_IN;
    sess->state = SESS_STATE_LOGGED_IN;

    printf("login: session to '%s' (%s) established  TSIH=0x%04x\n",
           sess->target_name[0] ? sess->target_name : "(discovery)",
           sess->target_address, sess->tsih);

    return LOGIN_OK;
}

int iscsi_logout(iscsi_session_t *sess, iscsi_conn_t *conn, uint8_t reason)
{
    iscsi_pdu_t pdu;
    pdu_init(&pdu, ISCSI_OP_LOGOUT_REQ | ISCSI_OP_IMMEDIATE,
             ISCSI_FLAG_FINAL | (reason & 0x7f));

    iscsi_logout_req_t *req = (iscsi_logout_req_t *)&pdu.hdr;
    req->itt       = htonl(ISCSI_RSVD_TASK_TAG);
    req->cid       = htons(conn->cid);
    req->cmdsn     = htonl(session_next_cmdsn(sess));
    req->expstatsn = htonl(conn->exp_statsn);

    conn->state = CONN_STATE_IN_LOGOUT;

    /* Logout runs in Full Feature Phase — use negotiated digest settings */
    int rc = pdu_send(conn->fd, &pdu, conn->header_digest, conn->data_digest);
    if (rc) return rc;

    iscsi_pdu_t rsp;
    rc = pdu_recv(conn->fd, &rsp, conn->header_digest, conn->data_digest);
    if (rc) return rc;

    if ((rsp.hdr.opcode & 0x3f) != ISCSI_OP_LOGOUT_RSP) {
        syslog(LOG_WARNING, "logout: unexpected opcode 0x%02x",
               rsp.hdr.opcode & 0x3f);
        pdu_free_data(&rsp);
        return -1;
    }

    iscsi_logout_rsp_t *lr = (iscsi_logout_rsp_t *)&rsp.hdr;
    if (lr->response != 0)
        syslog(LOG_WARNING, "logout: target returned response code %u", lr->response);

    pdu_free_data(&rsp);
    conn->state = CONN_STATE_FREE;
    return 0;
}

/* -----------------------------------------------------------------------
 * Add-connection login (MCS / ERL-1 reinstatement)
 * ----------------------------------------------------------------------- */

login_result_t iscsi_login_add_conn(iscsi_session_t *sess, iscsi_conn_t *conn)
{
    /*
     * Adding a connection to an existing session follows the same Login FSM
     * as initial login, with one critical difference: sess->tsih is non-zero.
     * The target uses (ISID, TSIH) to match the incoming login to the existing
     * session and assigns the new connection to it instead of creating a new
     * session.  See RFC 7143 §6.3.6.
     */
    int rc;

    if (sess->tsih == 0) {
        syslog(LOG_ERR, "login_add_conn: session has no TSIH");
        return LOGIN_PROTO_ERROR;
    }

    conn->state = CONN_STATE_IN_LOGIN;

    /* Security phase: use same credentials as the original login */
    if (sess->chap_secret[0]) {
        rc = login_auth_chap(sess, conn);
    } else {
        rc = login_auth_none(sess, conn);
    }
    if (rc) {
        conn->state = CONN_STATE_FAILED;
        return (login_result_t)rc;
    }

    /* Operational negotiation — only connection-scoped params need renegotiation */
    rc = login_operational(sess, conn);
    if (rc) {
        conn->state = CONN_STATE_FAILED;
        return (login_result_t)rc;
    }

    conn->state = CONN_STATE_LOGGED_IN;

    printf("login: added connection CID %u to session '%s'\n",
           conn->cid, sess->target_name);
    return LOGIN_OK;
}

const char *login_result_str(login_result_t r)
{
    switch (r) {
    case LOGIN_OK:           return "OK";
    case LOGIN_AUTH_FAILED:  return "Authentication failed";
    case LOGIN_IO_ERROR:     return "I/O error";
    case LOGIN_PROTO_ERROR:  return "Protocol error";
    case LOGIN_TARGET_ERROR: return "Target error";
    case LOGIN_NO_RESOURCES: return "No resources";
    case LOGIN_REDIRECTED:   return "Redirected";
    default:                 return "Unknown error";
    }
}
