/*
 * connection.c - iSCSI TCP connection management
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "connection.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

iscsi_conn_t *conn_create(const char *host, uint16_t port)
{
    struct addrinfo hints, *res, *rp;
    char port_str[8];
    int fd = -1;

    snprintf(port_str, sizeof(port_str), "%u", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;   /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "conn: getaddrinfo(%s:%u): %s\n",
                host, port, gai_strerror(rc));
        return NULL;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        fprintf(stderr, "conn: could not connect to %s:%u\n", host, port);
        return NULL;
    }

    /*
     * Size the socket buffers to match MaxRecvDataSegmentLength (256 KiB).
     * The kernel default on macOS is ~128 KiB, which falls below the PDU
     * data segment limit and causes receiver-side flow control stalls under
     * sustained workloads.  The kernel may round up to the next power of two.
     */
    int bufsize = ISCSI_CONN_RECV_BUFSIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0)
        fprintf(stderr, "conn: SO_RCVBUF: %s\n", strerror(errno));
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0)
        fprintf(stderr, "conn: SO_SNDBUF: %s\n", strerror(errno));

    /*
     * Disable Nagle: iSCSI PDUs are complete messages; we never want the
     * kernel to hold a partially-filled segment waiting for more data.
     * Set here rather than during login so it applies to the full connection
     * lifetime, including any future SCSI I/O path.
     */
    int nodelay = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0)
        fprintf(stderr, "conn: TCP_NODELAY: %s\n", strerror(errno));

    iscsi_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        close(fd);
        return NULL;
    }

    conn->fd            = fd;
    conn->state         = CONN_STATE_CONNECTING;
    conn->max_recv_dsl  = 262144;    /* 256 KiB default */
    conn->max_send_dsl  = 8192;      /* conservative initial value */

    return conn;
}

void conn_destroy(iscsi_conn_t *conn)
{
    if (!conn) return;
    if (conn->fd >= 0) close(conn->fd);
    free(conn);
}

int conn_set_keepalive(iscsi_conn_t *conn, int idle_sec,
                        int interval_sec, int probe_count)
{
    int val = 1;
    if (setsockopt(conn->fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) < 0)
        return -errno;
    if (setsockopt(conn->fd, IPPROTO_TCP, TCP_KEEPALIVE,
                   &idle_sec, sizeof(idle_sec)) < 0)
        return -errno;
    if (setsockopt(conn->fd, IPPROTO_TCP, TCP_KEEPINTVL,
                   &interval_sec, sizeof(interval_sec)) < 0)
        return -errno;
    if (setsockopt(conn->fd, IPPROTO_TCP, TCP_KEEPCNT,
                   &probe_count, sizeof(probe_count)) < 0)
        return -errno;
    return 0;
}

int conn_set_nodelay(iscsi_conn_t *conn)
{
    int val = 1;
    if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) < 0)
        return -errno;
    return 0;
}

const char *conn_state_str(conn_state_t state)
{
    switch (state) {
    case CONN_STATE_FREE:        return "FREE";
    case CONN_STATE_CONNECTING:  return "CONNECTING";
    case CONN_STATE_IN_LOGIN:    return "IN_LOGIN";
    case CONN_STATE_LOGGED_IN:   return "LOGGED_IN";
    case CONN_STATE_IN_LOGOUT:   return "IN_LOGOUT";
    case CONN_STATE_FAILED:      return "FAILED";
    default:                     return "UNKNOWN";
    }
}
