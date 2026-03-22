/*
 * nbd.h - NBD (Network Block Device) protocol server over iSCSI
 *
 * Bridges an iSCSI LUN to the NBD protocol (newstyle fixed handshake,
 * RFC-like specification at https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md),
 * allowing any NBD client (Linux nbd-client, macOS nbdfuse via libnbd)
 * to access iSCSI block storage without DriverKit entitlements.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "session.h"
#include "connection.h"
#include <stdint.h>

/*
 * Bind a TCP socket for the NBD server on localhost (127.0.0.1).
 * The OS assigns the port; fills *port_out with the assigned port number.
 *
 * Returns the listening fd (with listen() already called), or -1 on error.
 */
int nbd_bind(int *port_out);

/*
 * Run the NBD server on the bound listen_fd.
 *
 * Accepts one NBD client, performs the NBD newstyle fixed handshake
 * (supports NBD_OPT_EXPORT_NAME and NBD_OPT_GO), then serves
 * READ / WRITE / FLUSH / DISC requests by issuing iSCSI SCSI commands
 * on sess/conn.
 *
 * lun_raw   : 8-byte LUN descriptor (raw bytes from REPORT LUNS)
 * listen_fd : bound listening socket from nbd_bind(); taken over and
 *             closed before this function returns
 *
 * Blocks until the NBD client sends NBD_CMD_DISC or disconnects.
 * Returns 0 on clean exit, -1 on protocol or I/O error.
 */
int nbd_serve(iscsi_session_t *sess, iscsi_conn_t *conn,
              const uint8_t lun_raw[8], int listen_fd);
