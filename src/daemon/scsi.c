/*
 * scsi.c - Synchronous iSCSI SCSI command execution
 *
 * Execution model (single-threaded, no command queue):
 *
 *   1. Send SCSI Command PDU.
 *   2. For writes with ImmediateData: attach first-burst data to command PDU.
 *   3. If write and !InitialR2T: send unsolicited Data-Out up to FirstBurstLength.
 *   4. Poll for incoming PDUs until SCSI Response:
 *        R2T      → send the requested Data-Out burst
 *        Data-In  → copy into the read buffer at the given offset
 *        SCSI Rsp → extract status and return
 *
 * DataPDUInOrder=Yes is required (default); out-of-order Data-In is not
 * supported here (ERL-1 SNACK for reordering is a future extension).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "scsi.h"
#include "pdu.h"
#include "recovery.h"
#include "../shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* -----------------------------------------------------------------------
 * Sense data decoding
 * ----------------------------------------------------------------------- */

static const char *const sense_key_names[16] = {
    "NO SENSE",        "RECOVERED ERROR", "NOT READY",       "MEDIUM ERROR",
    "HARDWARE ERROR",  "ILLEGAL REQUEST", "UNIT ATTENTION",  "DATA PROTECT",
    "BLANK CHECK",     "VENDOR SPECIFIC", "COPY ABORTED",    "ABORTED COMMAND",
    "OBSOLETE",        "VOLUME OVERFLOW",  "MISCOMPARE",      "COMPLETED",
};

const char *scsi_sense_key_str(uint8_t sense_key)
{
    return sense_key_names[sense_key & 0x0f];
}

int scsi_decode_sense(const uint8_t *data, uint32_t data_len,
                      scsi_sense_t *out)
{
    /* iSCSI wraps sense data with a 2-byte big-endian Sense Length prefix */
    if (data_len < 2) return -1;
    uint16_t sense_len = ((uint16_t)data[0] << 8) | data[1];
    if (sense_len == 0 || data_len < (uint32_t)(2 + sense_len)) return -1;

    const uint8_t *s = data + 2;
    uint8_t rc = s[0] & 0x7f;
    out->response_code = rc;

    if (rc == 0x70 || rc == 0x71) {
        /* Fixed format: sense key at byte 2 bits [3:0], ASC at 12, ASCQ at 13 */
        out->sense_key = (sense_len >= 3) ? (s[2] & 0x0f) : 0;
        out->asc       = (sense_len >= 13) ? s[12] : 0;
        out->ascq      = (sense_len >= 14) ? s[13] : 0;
    } else if (rc == 0x72 || rc == 0x73) {
        /* Descriptor format: sense key at byte 1, ASC at 2, ASCQ at 3 */
        out->sense_key = (sense_len >= 2) ? (s[1] & 0x0f) : 0;
        out->asc       = (sense_len >= 3) ? s[2] : 0;
        out->ascq      = (sense_len >= 4) ? s[3] : 0;
    } else {
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * scsi_report_luns — enumerate LUNs on the target
 * ----------------------------------------------------------------------- */

int scsi_report_luns(iscsi_session_t *sess, iscsi_conn_t *conn,
                      iscsi_lun_t *luns, int max_luns)
{
    /*
     * REPORT LUNS CDB (SPC-4 §6.33):
     *   [0]    = 0xA0 (REPORT LUNS)
     *   [2]    = SELECT REPORT = 0x02 (all LUNs including well-known)
     *   [6..9] = ALLOCATION LENGTH (big-endian 4 bytes)
     */
    uint32_t alloc_len = (uint32_t)(max_luns * 8 + 8);   /* 8-byte header + entries */
    uint8_t cdb[12] = {
        0xA0, 0x00, 0x02, 0x00,
        0x00, 0x00,
        (uint8_t)(alloc_len >> 24), (uint8_t)(alloc_len >> 16),
        (uint8_t)(alloc_len >>  8), (uint8_t)(alloc_len & 0xFF),
        0x00, 0x00
    };

    uint8_t lun_zero[8] = {0};   /* always address LUN 0 for REPORT LUNS */

    uint8_t *buf = malloc(alloc_len);
    if (!buf) return -1;

    uint32_t inlen = alloc_len;
    int rc = scsi_exec(sess, conn, lun_zero, cdb, 12,
                        SCSI_DIR_READ, NULL, 0, buf, &inlen);
    if (rc != 0) {
        syslog(LOG_WARNING, "scsi: REPORT LUNS failed (status=%d)", rc);
        free(buf);
        return -1;
    }
    if (inlen < 8) {
        free(buf);
        return 0;
    }

    /* Parse response header: bytes 0-3 = LUN LIST LENGTH (excludes these 4 + next 4) */
    uint32_t list_len = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                        ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
    uint32_t num_luns = list_len / 8;
    if (num_luns > (uint32_t)max_luns) num_luns = (uint32_t)max_luns;
    if (inlen < 8 + list_len) num_luns = (inlen - 8) / 8;

    for (uint32_t i = 0; i < num_luns; i++) {
        const uint8_t *entry = buf + 8 + i * 8;
        memcpy(luns[i].raw, entry, 8);

        /*
         * Decode LUN number from the first two bytes of the 8-byte descriptor.
         * Address method in bits [7:6] of byte 0:
         *   00 = peripheral device (single-level), LUN = byte 1
         *   01 = flat space,                        LUN = (byte 0 & 0x3f) << 8 | byte 1
         */
        uint8_t addr_method = (entry[0] >> 6) & 0x03;
        if (addr_method == 0) {
            luns[i].id = entry[1];
        } else if (addr_method == 1) {
            luns[i].id = (uint16_t)(((entry[0] & 0x3F) << 8) | entry[1]);
        } else {
            luns[i].id = 0xFFFF;   /* unsupported addressing method */
        }
    }

    free(buf);
    return (int)num_luns;
}

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

/*
 * Send a burst of SCSI Data-Out PDUs covering [offset, offset+burst_len).
 * Splits into chunks of at most conn->max_send_dsl bytes each.
 * ttt: the Target Transfer Tag from the R2T (or 0xFFFFFFFF for unsolicited).
 * datasn: starting DataSN for this burst (increments per PDU sent).
 */
static int send_data_out(iscsi_conn_t *conn, iscsi_session_t *sess,
                          uint32_t itt, uint32_t ttt,
                          const uint8_t *data, uint32_t data_total_len,
                          uint32_t offset, uint32_t burst_len,
                          uint32_t *datasn_inout)
{
    uint32_t sent = 0;
    uint32_t max_chunk = conn->max_send_dsl;
    if (max_chunk == 0) max_chunk = 8192;   /* safety fallback */

    while (sent < burst_len) {
        uint32_t chunk = burst_len - sent;
        if (chunk > max_chunk) chunk = max_chunk;
        int is_last = (sent + chunk >= burst_len);

        iscsi_pdu_t pdu;
        pdu_init(&pdu, ISCSI_OP_SCSI_DATA_OUT,
                 is_last ? ISCSI_FLAG_FINAL : 0);
        iscsi_data_out_t *hdr = (iscsi_data_out_t *)&pdu.hdr;
        hdr->itt       = htonl(itt);
        hdr->ttt       = htonl(ttt);
        hdr->expstatsn = htonl(conn->exp_statsn);
        hdr->datasn    = htonl((*datasn_inout)++);
        hdr->bufoffset = htonl(offset + sent);
        iscsi_dlength_set(hdr->dlength, chunk);
        pdu_set_data_ref(&pdu, data + offset + sent, chunk);

        int rc = pdu_send(conn->fd, &pdu, conn->header_digest, conn->data_digest);
        if (rc) {
            syslog(LOG_ERR, "scsi: data-out send failed: %d", rc);
            return rc;
        }
        sent += chunk;
    }
    (void)sess;
    return 0;
}

/* -----------------------------------------------------------------------
 * scsi_exec_once — single attempt, no retry
 * ----------------------------------------------------------------------- */

static int scsi_exec_once(iscsi_session_t *sess, iscsi_conn_t *conn,
              const uint8_t lun[8],
              const uint8_t *cdb, size_t cdb_len,
              int dir,
              const void *data_out, uint32_t data_out_len,
              void *data_in, uint32_t *data_in_len)
{
    if (cdb_len > 16) return -1;

    uint32_t itt    = session_next_itt(sess);
    uint32_t cmdsn  = session_next_cmdsn(sess);
    uint32_t datasn = 0;

    /* ---- Build the SCSI Command PDU ---- */
    iscsi_pdu_t cmd_pdu;
    pdu_init(&cmd_pdu, ISCSI_OP_SCSI_CMD, ISCSI_FLAG_FINAL);
    iscsi_scsi_cmd_t *cmd = (iscsi_scsi_cmd_t *)&cmd_pdu.hdr;

    cmd->flags = ISCSI_SCSI_FLAG_FINAL;
    if (dir == SCSI_DIR_READ)  cmd->flags |= ISCSI_SCSI_FLAG_READ;
    if (dir == SCSI_DIR_WRITE) cmd->flags |= ISCSI_SCSI_FLAG_WRITE;

    memcpy(cmd->lun, lun, 8);
    cmd->itt           = htonl(itt);
    cmd->cmdsn         = htonl(cmdsn);
    cmd->expstatsn     = htonl(conn->exp_statsn);
    cmd->expected_datasn = htonl(dir == SCSI_DIR_READ
                                  ? (data_in_len ? *data_in_len : 0)
                                  : data_out_len);
    memcpy(cmd->cdb, cdb, cdb_len);

    /*
     * ImmediateData: attach first-burst data to the command PDU.
     * We send up to min(FirstBurstLength, MaxSendDSL) bytes immediately.
     */
    uint32_t imm_len = 0;
    if (dir == SCSI_DIR_WRITE && data_out_len > 0 &&
        sess->params.immediate_data && data_out != NULL) {
        imm_len = data_out_len;
        if (imm_len > sess->params.first_burst_length)
            imm_len = sess->params.first_burst_length;
        if (imm_len > conn->max_send_dsl)
            imm_len = conn->max_send_dsl;
        iscsi_dlength_set(cmd->dlength, imm_len);
        pdu_set_data_ref(&cmd_pdu, data_out, imm_len);
    }

    int rc = pdu_send(conn->fd, &cmd_pdu, conn->header_digest, conn->data_digest);
    if (rc) {
        syslog(LOG_ERR, "scsi: command send failed: %d", rc);
        return -1;
    }

    /*
     * Unsolicited Data-Out: if InitialR2T=No, send more data immediately
     * without waiting for R2T (up to FirstBurstLength total, minus imm_len).
     */
    uint32_t bytes_sent = imm_len;
    if (dir == SCSI_DIR_WRITE && data_out != NULL && data_out_len > 0 &&
        !sess->params.initial_r2t && bytes_sent < data_out_len) {
        uint32_t unsol_max = sess->params.first_burst_length;
        uint32_t unsol_len = data_out_len - bytes_sent;
        if (unsol_len > unsol_max - bytes_sent)
            unsol_len = unsol_max - bytes_sent;

        rc = send_data_out(conn, sess, itt, ISCSI_RSVD_TASK_TAG,
                           (const uint8_t *)data_out, data_out_len,
                           bytes_sent, unsol_len, &datasn);
        if (rc) return -1;
        bytes_sent += unsol_len;
    }

    /* ---- Receive loop: process R2T, Data-In, SCSI Response ---- */
    uint32_t data_in_received = 0;
    uint32_t expected_datasn  = 0;   /* DataPDUInOrder=Yes: must be strictly sequential */

    for (;;) {
        iscsi_pdu_t rsp;
        rc = pdu_recv(conn->fd, &rsp, conn->header_digest, conn->data_digest);
        if (rc) {
            syslog(LOG_ERR, "scsi: recv failed: %d", rc);
            return -1;
        }

        uint8_t op = rsp.hdr.opcode & 0x3f;

        /* ---- R2T: target solicits a write data burst ---- */
        if (op == ISCSI_OP_R2T) {
            const iscsi_r2t_t *r2t = (const iscsi_r2t_t *)&rsp.hdr;
            uint32_t ttt       = ntohl(r2t->ttt);
            uint32_t bufoffset = ntohl(r2t->bufoffset);
            uint32_t desired   = ntohl(r2t->desired_datasn);

            session_update_sn(sess, ntohl(r2t->statsn),
                              ntohl(r2t->expcmdsn), ntohl(r2t->maxcmdsn));
            conn->exp_statsn = ntohl(r2t->statsn) + 1;

            if (data_out == NULL || bufoffset + desired > data_out_len) {
                syslog(LOG_ERR, "scsi: R2T out of range "
                       "(offset=%u desired=%u total=%u)",
                       bufoffset, desired, data_out_len);
                pdu_free_data(&rsp);
                return -1;
            }

            uint32_t burst_datasn = 0;
            rc = send_data_out(conn, sess, itt, ttt,
                               (const uint8_t *)data_out, data_out_len,
                               bufoffset, desired, &burst_datasn);
            pdu_free_data(&rsp);
            if (rc) return -1;
            bytes_sent += desired;
            continue;
        }

        /* ---- Data-In: target sends read data ---- */
        if (op == ISCSI_OP_SCSI_DATA_IN) {
            const iscsi_data_in_t *din = (const iscsi_data_in_t *)&rsp.hdr;
            uint32_t bufoffset = ntohl(din->bufoffset);
            int      final     = (din->flags & ISCSI_FLAG_FINAL) != 0;
            int      has_status = (din->flags & 0x01) != 0;  /* S bit */

            /* DataPDUInOrder=Yes: DataSN must increment by 1 per PDU */
            uint32_t got_datasn = ntohl(din->datasn);
            if (got_datasn != expected_datasn) {
                syslog(LOG_ERR, "scsi: DataSN gap: expected %u got %u",
                       expected_datasn, got_datasn);
                pdu_free_data(&rsp);
                return -1;
            }
            expected_datasn++;

            session_update_sn(sess, ntohl(din->statsn),
                              ntohl(din->expcmdsn), ntohl(din->maxcmdsn));
            conn->exp_statsn = ntohl(din->statsn) + 1;

            /* Copy data into caller's buffer at the correct offset */
            if (data_in != NULL && rsp.data_len > 0 && data_in_len != NULL) {
                if (bufoffset + rsp.data_len > *data_in_len) {
                    syslog(LOG_ERR, "scsi: data-in overflow "
                           "(offset=%u len=%u cap=%u)",
                           bufoffset, rsp.data_len, *data_in_len);
                    pdu_free_data(&rsp);
                    return -1;
                }
                memcpy((uint8_t *)data_in + bufoffset, rsp.data, rsp.data_len);
                if (bufoffset + rsp.data_len > data_in_received)
                    data_in_received = bufoffset + rsp.data_len;
            }
            pdu_free_data(&rsp);

            if (has_status) {
                /* Status is embedded in this Data-In PDU */
                if (data_in_len) *data_in_len = data_in_received;
                return din->status;
            }
            if (final) {
                /* Final Data-In without status: SCSI Response follows */
                if (data_in_len) *data_in_len = data_in_received;
                /* Fall through to read the SCSI Response */
                for (;;) {
                    iscsi_pdu_t rsp2;
                    rc = pdu_recv(conn->fd, &rsp2, conn->header_digest,
                                  conn->data_digest);
                    if (rc) return -1;
                    if ((rsp2.hdr.opcode & 0x3f) == ISCSI_OP_SCSI_RSP) {
                        const iscsi_scsi_rsp_t *srsp =
                            (const iscsi_scsi_rsp_t *)&rsp2.hdr;
                        conn->exp_statsn = ntohl(srsp->statsn) + 1;
                        session_update_sn(sess, ntohl(srsp->statsn),
                                          ntohl(srsp->expcmdsn),
                                          ntohl(srsp->maxcmdsn));
                        uint8_t status = srsp->status;
                        pdu_free_data(&rsp2);
                        return status;
                    }
                    pdu_free_data(&rsp2);
                }
            }
            continue;
        }

        /* ---- SCSI Response ---- */
        if (op == ISCSI_OP_SCSI_RSP) {
            const iscsi_scsi_rsp_t *srsp = (const iscsi_scsi_rsp_t *)&rsp.hdr;
            conn->exp_statsn = ntohl(srsp->statsn) + 1;
            session_update_sn(sess, ntohl(srsp->statsn),
                              ntohl(srsp->expcmdsn), ntohl(srsp->maxcmdsn));

            if (srsp->response != 0) {
                syslog(LOG_ERR, "scsi: target response error 0x%02x",
                       srsp->response);
                pdu_free_data(&rsp);
                return -1;
            }

            uint8_t status = srsp->status;

            if (status == SCSI_STATUS_CHECK_CONDITION && rsp.data_len > 0) {
                scsi_sense_t sense = {0};
                if (scsi_decode_sense(rsp.data, rsp.data_len, &sense) == 0) {
                    syslog(LOG_WARNING,
                           "scsi: CHECK CONDITION key=0x%02x(%s) "
                           "asc=0x%02x ascq=0x%02x",
                           sense.sense_key, scsi_sense_key_str(sense.sense_key),
                           sense.asc, sense.ascq);
                }
            }

            if (dir == SCSI_DIR_READ && data_in_len)
                *data_in_len = data_in_received;

            pdu_free_data(&rsp);
            return status;
        }

        /* Unexpected opcode — log and continue */
        syslog(LOG_WARNING, "scsi: unexpected opcode 0x%02x during command", op);
        pdu_free_data(&rsp);
    }
}

/* -----------------------------------------------------------------------
 * scsi_exec — public API with ERL-1 retry
 *
 * On I/O failure (-1) with ErrorRecoveryLevel >= 1, waits up to
 * (DefaultTime2Wait + DefaultTime2Retain + 5) seconds for the recovery
 * thread to reinstate the connection, then retries the command once on the
 * new connection.  SCSI errors (non-zero status) are returned as-is without
 * retry since the target successfully processed the command.
 * ----------------------------------------------------------------------- */

int scsi_exec(iscsi_session_t *sess, iscsi_conn_t *conn,
              const uint8_t lun[8],
              const uint8_t *cdb, size_t cdb_len,
              int dir,
              const void *data_out, uint32_t data_out_len,
              void *data_in, uint32_t *data_in_len)
{
    /* Save original read-buffer capacity so retry starts with a clean slate. */
    uint32_t orig_data_in_len = data_in_len ? *data_in_len : 0;

    int rc = scsi_exec_once(sess, conn, lun, cdb, cdb_len, dir,
                             data_out, data_out_len, data_in, data_in_len);
    if (rc != -1 || sess->params.error_recovery_level < 1)
        return rc;

    /*
     * I/O error with ERL-1 active.  The kqueue event loop in main.c detects
     * connection failure (EV_EOF) and spawns a recovery thread that sleeps
     * DefaultTime2Wait seconds then reconnects.  Give it a short head-start
     * before we start waiting on the recovery cond.
     */
    syslog(LOG_NOTICE, "scsi: I/O error on %s — waiting for ERL-1 recovery",
           sess->target_name);

    struct timespec ts = {0, 200000000};   /* 200 ms */
    nanosleep(&ts, NULL);

    unsigned timeout = sess->params.default_time2wait +
                       sess->params.default_time2retain + 5;
    if (session_wait_recovery(sess, timeout) != 0) {
        syslog(LOG_ERR, "scsi: recovery did not succeed for %s, giving up",
               sess->target_name);
        return -1;
    }

    iscsi_conn_t *new_conn = session_lead_conn(sess);
    if (!new_conn) return -1;

    /* Reset the read buffer capacity for a clean retry. */
    if (data_in_len) *data_in_len = orig_data_in_len;

    syslog(LOG_NOTICE, "scsi: retrying command on new connection for %s",
           sess->target_name);
    return scsi_exec_once(sess, new_conn, lun, cdb, cdb_len, dir,
                           data_out, data_out_len, data_in, data_in_len);
}

/* -----------------------------------------------------------------------
 * scsi_read_capacity10 — get LUN geometry
 * ----------------------------------------------------------------------- */

int scsi_read_capacity10(iscsi_session_t *sess, iscsi_conn_t *conn,
                          const uint8_t lun[8],
                          uint32_t *num_blocks, uint32_t *block_size)
{
    /*
     * READ CAPACITY(10) CDB (SBC-4 §5.16):
     *   [0] = 0x25 (READ CAPACITY(10)), all other bytes zero.
     */
    uint8_t cdb[10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t buf[8];
    uint32_t inlen = sizeof(buf);

    int rc = scsi_exec(sess, conn, lun, cdb, 10, SCSI_DIR_READ,
                        NULL, 0, buf, &inlen);
    if (rc != 0 || inlen < 8) {
        syslog(LOG_WARNING, "scsi: READ CAPACITY(10) failed (rc=%d inlen=%u)",
               rc, inlen);
        return -1;
    }

    /* Response: RETURNED LOGICAL BLOCK ADDRESS (4 bytes) + BLOCK LENGTH (4 bytes) */
    uint32_t last_lba = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                         ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
    uint32_t blen     = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                         ((uint32_t)buf[6] <<  8) |  (uint32_t)buf[7];

    *num_blocks = last_lba + 1;   /* last LBA is inclusive */
    *block_size = blen;
    return 0;
}

/* -----------------------------------------------------------------------
 * scsi_read10 — read up to 65535 blocks
 * ----------------------------------------------------------------------- */

int scsi_read10(iscsi_session_t *sess, iscsi_conn_t *conn,
                const uint8_t lun[8],
                uint32_t lba, uint16_t nblocks, uint32_t block_size,
                void *buf)
{
    /*
     * READ(10) CDB (SBC-4 §5.14):
     *   [0]    = 0x28 (READ(10))
     *   [1]    = 0x00 (no DPO, no FUA, no RARC)
     *   [2..5] = LOGICAL BLOCK ADDRESS (big-endian 4 bytes)
     *   [6]    = 0x00 (GROUP NUMBER)
     *   [7..8] = TRANSFER LENGTH in blocks (big-endian 2 bytes)
     *   [9]    = 0x00 (CONTROL)
     */
    uint8_t cdb[10] = {
        0x28, 0x00,
        (uint8_t)(lba >> 24), (uint8_t)(lba >> 16),
        (uint8_t)(lba >>  8), (uint8_t)(lba & 0xFF),
        0x00,
        (uint8_t)(nblocks >> 8), (uint8_t)(nblocks & 0xFF),
        0x00
    };
    uint32_t inlen = (uint32_t)nblocks * block_size;
    int rc = scsi_exec(sess, conn, lun, cdb, 10, SCSI_DIR_READ,
                        NULL, 0, buf, &inlen);
    return (rc == 0) ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * scsi_write10 — write up to 65535 blocks
 * ----------------------------------------------------------------------- */

int scsi_write10(iscsi_session_t *sess, iscsi_conn_t *conn,
                 const uint8_t lun[8],
                 uint32_t lba, uint16_t nblocks, uint32_t block_size,
                 const void *buf)
{
    /*
     * WRITE(10) CDB (SBC-4 §5.49):
     *   [0]    = 0x2A (WRITE(10))
     *   [1]    = 0x00 (no DPO, no FUA, no EBP)
     *   [2..5] = LOGICAL BLOCK ADDRESS (big-endian 4 bytes)
     *   [6]    = 0x00 (GROUP NUMBER)
     *   [7..8] = TRANSFER LENGTH in blocks (big-endian 2 bytes)
     *   [9]    = 0x00 (CONTROL)
     */
    uint8_t cdb[10] = {
        0x2A, 0x00,
        (uint8_t)(lba >> 24), (uint8_t)(lba >> 16),
        (uint8_t)(lba >>  8), (uint8_t)(lba & 0xFF),
        0x00,
        (uint8_t)(nblocks >> 8), (uint8_t)(nblocks & 0xFF),
        0x00
    };
    uint32_t datalen = (uint32_t)nblocks * block_size;
    int rc = scsi_exec(sess, conn, lun, cdb, 10, SCSI_DIR_WRITE,
                        buf, datalen, NULL, NULL);
    return (rc == 0) ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * scsi_sync_cache10 — flush target write cache to stable storage
 * ----------------------------------------------------------------------- */

int scsi_sync_cache10(iscsi_session_t *sess, iscsi_conn_t *conn,
                      const uint8_t lun[8])
{
    /*
     * SYNCHRONIZE CACHE(10) CDB (SBC-4 §5.24):
     *   [0] = 0x35 (SYNCHRONIZE CACHE(10))
     *   [1] = 0x00 (IMMED=0, SYNC_NV=0: wait for completion, non-volatile)
     *   [2..5] = LOGICAL BLOCK ADDRESS = 0 (start from beginning)
     *   [6] = 0x00 (GROUP NUMBER)
     *   [7..8] = NUMBER OF LOGICAL BLOCKS = 0 (flush entire cache)
     *   [9] = 0x00 (CONTROL)
     */
    uint8_t cdb[10] = {0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int rc = scsi_exec(sess, conn, lun, cdb, 10,
                        SCSI_DIR_NONE, NULL, 0, NULL, NULL);
    return (rc == 0) ? 0 : -1;
}
