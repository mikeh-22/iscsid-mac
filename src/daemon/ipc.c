/*
 * ipc.c - Unix domain socket IPC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ipc.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Internal send/recv for length-prefixed messages
 * ----------------------------------------------------------------------- */

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return -EIO;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return 0;   /* peer close */
        p += n; len -= (size_t)n;
    }
    return (int)len == 0 ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * Server
 * ----------------------------------------------------------------------- */

int ipc_server_create(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    unlink(path);   /* remove stale socket */
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "ipc: bind %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    /* Restrict socket access to the daemon's owner only.
     * This prevents unprivileged users from issuing login/logout commands. */
    if (chmod(path, 0600) < 0) {
        syslog(LOG_ERR, "ipc: chmod %s: %s", path, strerror(errno));
        unlink(path);
        close(fd);
        return -1;
    }

    if (listen(fd, 8) < 0) {
        syslog(LOG_ERR, "ipc: listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

int ipc_server_accept(int listen_fd)
{
    int fd;
    do {
        fd = accept(listen_fd, NULL, NULL);
    } while (fd < 0 && errno == EINTR);
    return fd;
}

/* -----------------------------------------------------------------------
 * Client
 * ----------------------------------------------------------------------- */

int ipc_client_connect(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "ipc: connect %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/* -----------------------------------------------------------------------
 * Message I/O
 * ----------------------------------------------------------------------- */

int ipc_send(int fd, const char *json)
{
    uint32_t len  = (uint32_t)strlen(json);
    uint32_t nlen = htonl(len);
    int rc = write_all(fd, &nlen, 4);
    if (rc) return rc;
    return write_all(fd, json, len);
}

int ipc_recv(int fd, char *buf, size_t buf_size)
{
    uint32_t nlen;
    int rc = read_all(fd, &nlen, 4);
    if (rc <= 0) return rc;

    uint32_t len = ntohl(nlen);
    if (len >= buf_size) {
        syslog(LOG_WARNING, "ipc: message too large (%u bytes)", len);
        return -EMSGSIZE;
    }

    rc = read_all(fd, buf, len);
    if (rc <= 0) return rc;
    buf[len] = '\0';
    return (int)len;
}
