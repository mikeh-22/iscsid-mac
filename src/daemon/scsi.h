/*
 * scsi.h - iSCSI SCSI command execution (RFC 7143 §10.3 - §10.8)
 *
 * Provides a synchronous scsi_exec() that sends a SCSI command over an
 * iSCSI connection and collects the response, handling ImmediateData,
 * R2T-solicited writes, and Data-In reads.
 *
 * This is the building block for block I/O once the DriverKit IOUserClient
 * path is available.  Until then it can be exercised via the IPC layer or
 * integration tests against a real iSCSI target.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "session.h"
#include "connection.h"
#include <stdint.h>
#include <stddef.h>

/* SCSI status codes */
#define SCSI_STATUS_GOOD            0x00
#define SCSI_STATUS_CHECK_CONDITION 0x02
#define SCSI_STATUS_BUSY            0x08
#define SCSI_STATUS_TASK_ABORTED    0x40

/* Transfer direction */
#define SCSI_DIR_NONE   0
#define SCSI_DIR_READ   1
#define SCSI_DIR_WRITE  2

/* Decoded LUN descriptor from REPORT LUNS response */
typedef struct {
    uint8_t  raw[8];    /* raw 8-byte LUN as received */
    uint16_t id;        /* decoded LUN number (0-based, flat address space) */
} iscsi_lun_t;

/*
 * Issue REPORT LUNS to enumerate all LUNs on the target.
 *
 * luns     : caller-allocated array to receive LUN descriptors
 * max_luns : capacity of the luns array
 *
 * Returns number of LUNs discovered (>= 0), or -1 on error.
 */
int scsi_report_luns(iscsi_session_t *sess, iscsi_conn_t *conn,
                      iscsi_lun_t *luns, int max_luns);

/*
 * Execute a SCSI command synchronously.
 *
 * sess / conn : the session and connection to use
 * lun         : 8-byte LUN in network byte order (RFC 7143 §10.3)
 * cdb / cdb_len : SCSI Command Descriptor Block (up to 16 bytes)
 *
 * For read commands (dir = SCSI_DIR_READ):
 *   data_in     : caller-allocated buffer to receive data
 *   data_in_len : in = buffer capacity; out = bytes actually received
 *
 * For write commands (dir = SCSI_DIR_WRITE):
 *   data_out     : data to write
 *   data_out_len : length of data_out
 *
 * Pass NULL / 0 for unused data buffers.
 *
 * Returns: SCSI status byte (0 = GOOD) on success
 *          -1 on iSCSI protocol error (connection state is undefined)
 */
int scsi_exec(iscsi_session_t *sess, iscsi_conn_t *conn,
              const uint8_t lun[8],
              const uint8_t *cdb, size_t cdb_len,
              int dir,
              const void *data_out, uint32_t data_out_len,
              void *data_in, uint32_t *data_in_len);

/*
 * READ CAPACITY(10) — fetch block count and block size for a LUN.
 *
 * Fills *num_blocks with the total number of logical blocks and
 * *block_size with the bytes per block.
 *
 * Returns 0 on success, -1 on SCSI or iSCSI error.
 */
int scsi_read_capacity10(iscsi_session_t *sess, iscsi_conn_t *conn,
                          const uint8_t lun[8],
                          uint32_t *num_blocks, uint32_t *block_size);

/*
 * READ(10) — read nblocks blocks starting at lba into buf.
 * buf must be at least nblocks * block_size bytes.
 * nblocks must be > 0 and <= 65535.
 *
 * Returns 0 on success (SCSI status GOOD), -1 on error.
 */
int scsi_read10(iscsi_session_t *sess, iscsi_conn_t *conn,
                const uint8_t lun[8],
                uint32_t lba, uint16_t nblocks, uint32_t block_size,
                void *buf);

/*
 * WRITE(10) — write nblocks blocks starting at lba from buf.
 * buf must be at least nblocks * block_size bytes.
 * nblocks must be > 0 and <= 65535.
 *
 * Returns 0 on success (SCSI status GOOD), -1 on error.
 */
int scsi_write10(iscsi_session_t *sess, iscsi_conn_t *conn,
                 const uint8_t lun[8],
                 uint32_t lba, uint16_t nblocks, uint32_t block_size,
                 const void *buf);

/*
 * SYNCHRONIZE CACHE(10) — flush the target's write cache to stable storage.
 *
 * Sends SYNCHRONIZE CACHE(10) with LBA=0 and NBLOCKS=0 (flush entire cache),
 * IMMED=0 (wait for completion before responding).
 *
 * Returns 0 on success (SCSI status GOOD), -1 on error.
 */
int scsi_sync_cache10(iscsi_session_t *sess, iscsi_conn_t *conn,
                      const uint8_t lun[8]);
