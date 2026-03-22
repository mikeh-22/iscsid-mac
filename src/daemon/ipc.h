/*
 * ipc.h - Unix domain socket IPC between iscsid and iscsictl
 *
 * Wire protocol: length-prefixed JSON messages.
 *   [uint32_t length (big-endian)] [JSON payload, 'length' bytes]
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#define ISCSID_SOCK_PATH    "/var/run/iscsid.sock"
#define IPC_MAX_MSG_LEN     (64 * 1024)

/* IPC message types (string field "cmd" in JSON) */
#define IPC_CMD_DISCOVER        "discover"
#define IPC_CMD_ISNS_DISCOVER   "isns-discover"
#define IPC_CMD_LOGIN           "login"
#define IPC_CMD_LOGOUT          "logout"
#define IPC_CMD_ADD_CONN        "add-connection"
#define IPC_CMD_LUNS            "luns"
#define IPC_CMD_NBD_SERVE       "nbd-serve"
#define IPC_CMD_LIST            "list"
#define IPC_CMD_STATUS          "status"
#define IPC_CMD_PING            "ping"

/* -----------------------------------------------------------------------
 * Server side
 * ----------------------------------------------------------------------- */

/*
 * Create and bind the Unix domain socket at path.
 * Returns a listening fd, or -1 on error.
 */
int ipc_server_create(const char *path);

/*
 * Accept one client connection.  Returns the client fd, or -1.
 */
int ipc_server_accept(int listen_fd);

/* -----------------------------------------------------------------------
 * Client side
 * ----------------------------------------------------------------------- */

/*
 * Connect to iscsid at path.
 * Returns a connected fd, or -1 on error.
 */
int ipc_client_connect(const char *path);

/* -----------------------------------------------------------------------
 * Message I/O (used by both sides)
 * ----------------------------------------------------------------------- */

/*
 * Send a NUL-terminated JSON string over fd.
 * Returns 0 on success, -errno on error.
 */
int ipc_send(int fd, const char *json);

/*
 * Receive a message into buf (max buf_size bytes, NUL-terminated).
 * Returns length on success, -errno on error, 0 on peer close.
 */
int ipc_recv(int fd, char *buf, size_t buf_size);
