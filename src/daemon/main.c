/*
 * main.c - iscsid-mac: Open-source iSCSI initiator daemon for macOS
 *
 * Architecture:
 *   - This daemon manages iSCSI sessions, connections, and discovery.
 *   - A Unix domain socket (IPC) accepts commands from iscsictl.
 *   - A future DriverKit DEXT communicates via IOUserClient to expose
 *     iSCSI LUNs as macOS block devices.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "config.h"
#include "connection.h"
#include "discovery.h"
#include "ipc.h"
#include "login.h"
#include "pdu.h"
#include "session.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <syslog.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Global state
 * ----------------------------------------------------------------------- */

static iscsid_config_t  g_config;
static iscsi_session_t *g_sessions = NULL;     /* linked list */
static int              g_ipc_fd   = -1;
static volatile sig_atomic_t g_running = 1;

/* -----------------------------------------------------------------------
 * Signal handling
 * ----------------------------------------------------------------------- */

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* -----------------------------------------------------------------------
 * Simple JSON helpers (no external library dependency)
 * ----------------------------------------------------------------------- */

/*
 * Escape a string for safe embedding in a JSON string value.
 * Only characters that are valid in iSCSI names / addresses should appear,
 * but we escape defensively anyway so that a malicious target cannot inject
 * into the IPC JSON and confuse the CLI.
 *
 * dst must be at least (src_len * 6 + 1) bytes to be safe.
 * Returns the number of bytes written (not including NUL).
 */
static int json_escape(char *dst, size_t dst_size, const char *src)
{
    size_t out = 0;
    for (const char *p = src; *p && out + 7 < dst_size; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"':  dst[out++] = '\\'; dst[out++] = '"';  break;
        case '\\': dst[out++] = '\\'; dst[out++] = '\\'; break;
        case '\n': dst[out++] = '\\'; dst[out++] = 'n';  break;
        case '\r': dst[out++] = '\\'; dst[out++] = 'r';  break;
        case '\t': dst[out++] = '\\'; dst[out++] = 't';  break;
        default:
            if (c < 0x20) {
                /* Control character: \uXXXX */
                out += (size_t)snprintf(dst + out, dst_size - out,
                                        "\\u%04x", c);
            } else {
                dst[out++] = (char)c;
            }
            break;
        }
    }
    dst[out] = '\0';
    return (int)out;
}

/* Helper: append a JSON key:string pair into buf at offset *off.
 * Returns 0 on success, -1 if the buffer would overflow. */
static int json_append_str(char *buf, size_t buf_size, int *off,
                            const char *key, const char *val)
{
    char escaped[1024];
    json_escape(escaped, sizeof(escaped), val);
    int n = snprintf(buf + *off, buf_size - (size_t)*off,
                     "\"%s\":\"%s\"", key, escaped);
    if (n < 0 || (size_t)(*off + n) >= buf_size) return -1;
    *off += n;
    return 0;
}

/* Extract string value for "key" from a flat JSON object.
 * Writes into dst (size dst_size).  Returns 0 on success. */
static int json_get_str(const char *json, const char *key,
                         char *dst, size_t dst_size)
{
    /* Construct '"key":"' pattern */
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) {
        /* Try without quotes around value: "key": value */
        snprintf(pat, sizeof(pat), "\"%s\":", key);
        p = strstr(json, pat);
        if (!p) return -1;
        p += strlen(pat);
        while (*p == ' ') p++;
        /* Value is a bare integer or token */
        size_t i = 0;
        while (*p && *p != ',' && *p != '}' && i + 1 < dst_size)
            dst[i++] = *p++;
        dst[i] = '\0';
        return 0;
    }
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < dst_size)
        dst[i++] = *p++;
    dst[i] = '\0';
    return 0;
}

/* -----------------------------------------------------------------------
 * IPC request handler
 * ----------------------------------------------------------------------- */

static void handle_ipc_client(int client_fd)
{
    char req[IPC_MAX_MSG_LEN];
    char resp[IPC_MAX_MSG_LEN];
    int  rc;

    while ((rc = ipc_recv(client_fd, req, sizeof(req))) > 0) {
        char cmd[64] = {0};
        json_get_str(req, "cmd", cmd, sizeof(cmd));

        if (strcmp(cmd, IPC_CMD_PING) == 0) {
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"msg\":\"pong\"}");

        } else if (strcmp(cmd, IPC_CMD_DISCOVER) == 0) {
            char host[256] = "127.0.0.1";
            char port_str[16] = "3260";
            json_get_str(req, "host", host, sizeof(host));
            json_get_str(req, "port", port_str, sizeof(port_str));
            uint16_t port = (uint16_t)atoi(port_str);

            iscsi_target_info_t targets[ISCSI_MAX_DISCOVERY_TARGETS];
            int count = iscsi_discover(host, port,
                                        g_config.initiator_name,
                                        g_config.chap_username,
                                        g_config.chap_secret,
                                        targets, ISCSI_MAX_DISCOVERY_TARGETS);

            if (count < 0) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"discovery failed\"}");
            } else {
                /* Build JSON array of targets with all strings escaped */
                int off = snprintf(resp, sizeof(resp),
                                   "{\"status\":\"ok\",\"count\":%d,\"targets\":[", count);
                for (int i = 0; i < count; i++) {
                    int n = snprintf(resp + off, sizeof(resp) - (size_t)off,
                                     "%s{", i ? "," : "");
                    if (n < 0 || (size_t)(off + n) >= sizeof(resp)) break;
                    off += n;
                    if (json_append_str(resp, sizeof(resp), &off,
                                        "name", targets[i].target_name) < 0) break;
                    n = snprintf(resp + off, sizeof(resp) - (size_t)off, ",");
                    if (n < 0 || (size_t)(off + n) >= sizeof(resp)) break;
                    off += n;
                    if (json_append_str(resp, sizeof(resp), &off,
                                        "address", targets[i].host) < 0) break;
                    n = snprintf(resp + off, sizeof(resp) - (size_t)off,
                                 ",\"port\":%u}", targets[i].port);
                    if (n < 0 || (size_t)(off + n) >= sizeof(resp)) break;
                    off += n;
                }
                snprintf(resp + off, sizeof(resp) - (size_t)off, "]}");
            }

        } else if (strcmp(cmd, IPC_CMD_LOGIN) == 0) {
            char host[256] = {0};
            char port_str[16] = "3260";
            char target[ISCSI_MAX_NAME_LEN] = {0};
            json_get_str(req, "host",   host,      sizeof(host));
            json_get_str(req, "port",   port_str,  sizeof(port_str));
            json_get_str(req, "target", target,    sizeof(target));
            uint16_t port = (uint16_t)atoi(port_str);

            if (!host[0] || !target[0]) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"missing host or target\"}");
                goto send_resp;
            }

            char addr[300];
            snprintf(addr, sizeof(addr), "%s:%u", host, port);

            iscsi_session_t *sess = session_create(SESS_TYPE_NORMAL,
                                                    g_config.initiator_name,
                                                    target, addr);
            if (!sess) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"out of memory\"}");
                goto send_resp;
            }
            config_apply_session(&g_config, sess);

            iscsi_conn_t *conn = conn_create(host, port);
            if (!conn) {
                session_destroy(sess);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"connection failed\"}");
                goto send_resp;
            }
            conn->cid = 1;
            session_add_conn(sess, conn);

            login_result_t lr = iscsi_login(sess, conn);
            if (lr != LOGIN_OK) {
                session_destroy(sess);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"%s\"}",
                         login_result_str(lr));
                goto send_resp;
            }

            /* Add to global session list */
            sess->next  = g_sessions;
            g_sessions  = sess;

            {
                char esc_target[512];
                json_escape(esc_target, sizeof(esc_target), target);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"ok\",\"msg\":\"logged in\","
                         "\"target\":\"%s\",\"tsih\":%u}",
                         esc_target, sess->tsih);
            }

        } else if (strcmp(cmd, IPC_CMD_LOGOUT) == 0) {
            char target[ISCSI_MAX_NAME_LEN] = {0};
            json_get_str(req, "target", target, sizeof(target));

            iscsi_session_t *prev = NULL, *s = g_sessions;
            while (s) {
                if (strcmp(s->target_name, target) == 0) {
                    iscsi_conn_t *c = session_lead_conn(s);
                    if (c) iscsi_logout(s, c, ISCSI_LOGOUT_CLOSE_SESSION);
                    if (prev) prev->next = s->next;
                    else      g_sessions = s->next;
                    session_destroy(s);
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"ok\",\"msg\":\"logged out\"}");
                    goto send_resp;
                }
                prev = s;
                s    = s->next;
            }
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"error\",\"msg\":\"session not found\"}");

        } else if (strcmp(cmd, IPC_CMD_LIST) == 0) {
            int off = snprintf(resp, sizeof(resp),
                               "{\"status\":\"ok\",\"sessions\":[");
            int first = 1;
            for (iscsi_session_t *s = g_sessions; s; s = s->next) {
                int n2 = snprintf(resp + off, sizeof(resp) - (size_t)off,
                                  "%s{", first ? "" : ",");
                if (n2 < 0 || (size_t)(off + n2) >= sizeof(resp)) break;
                off += n2;
                if (json_append_str(resp, sizeof(resp), &off,
                                    "target", s->target_name) < 0) break;
                n2 = snprintf(resp + off, sizeof(resp) - (size_t)off, ",");
                if (n2 < 0 || (size_t)(off + n2) >= sizeof(resp)) break;
                off += n2;
                if (json_append_str(resp, sizeof(resp), &off,
                                    "address", s->target_address) < 0) break;
                n2 = snprintf(resp + off, sizeof(resp) - (size_t)off,
                              ",\"state\":\"%s\",\"tsih\":%u}",
                              sess_state_str(s->state), s->tsih);
                if (n2 < 0 || (size_t)(off + n2) >= sizeof(resp)) break;
                off += n2;
                first = 0;
            }
            snprintf(resp + off, sizeof(resp) - (size_t)off, "]}");

        } else if (strcmp(cmd, IPC_CMD_STATUS) == 0) {
            int n = 0;
            for (iscsi_session_t *s = g_sessions; s; s = s->next) n++;
            char esc_init[512];
            json_escape(esc_init, sizeof(esc_init), g_config.initiator_name);
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"ok\",\"sessions\":%d,"
                     "\"initiator\":\"%s\"}",
                     n, esc_init);

        } else {
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"error\",\"msg\":\"unknown command\"}");
        }

send_resp:
        ipc_send(client_fd, resp);
    }

    close(client_fd);
}

/* -----------------------------------------------------------------------
 * PID file management
 * ----------------------------------------------------------------------- */

static void write_pid_file(const char *path)
{
    /* O_EXCL makes creation atomic: fails if a stale PID file already exists
     * from a previous crash, which surfaces as a diagnostic rather than
     * silently overwriting it and confusing process management tools. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        if (errno == EEXIST) {
            /* Stale PID file: read the old PID for a better error message */
            FILE *old = fopen(path, "r");
            if (old) {
                int old_pid = 0;
                if (fscanf(old, "%d", &old_pid) == 1 && old_pid > 0) {
                    fprintf(stderr,
                            "iscsid: PID file %s exists (pid %d). "
                            "Remove it if no other instance is running.\n",
                            path, old_pid);
                }
                fclose(old);
            }
        } else {
            fprintf(stderr, "iscsid: cannot create PID file %s: %s\n",
                    path, strerror(errno));
        }
        return;
    }
    dprintf(fd, "%d\n", (int)getpid());
    close(fd);
}

static void remove_pid_file(const char *path)
{
    unlink(path);
}

/* -----------------------------------------------------------------------
 * Daemonise
 * ----------------------------------------------------------------------- */

static void daemonise(void)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);   /* parent exits */

    setsid();

    /* Redirect stdio to /dev/null */
    int null = open("/dev/null", O_RDWR);
    if (null >= 0) {
        dup2(null, STDIN_FILENO);
        dup2(null, STDOUT_FILENO);
        dup2(null, STDERR_FILENO);
        if (null > 2) close(null);
    }
}

/* -----------------------------------------------------------------------
 * Usage / main
 * ----------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "Options:\n"
            "  -c <config>   Configuration file (default: /etc/iscsid.conf)\n"
            "  -s <path>     Unix socket path (default: /var/run/iscsid.sock)\n"
            "  -f            Foreground (do not daemonise)\n"
            "  -d            Enable debug logging\n"
            "  -h            Show this help\n",
            prog);
}

int main(int argc, char *argv[])
{
    int  foreground  = 0;
    int  debug       = 0;
    const char *config_path  = NULL;
    const char *socket_path  = NULL;
    int  opt;

    while ((opt = getopt(argc, argv, "c:s:fdh")) != -1) {
        switch (opt) {
        case 'c': config_path = optarg; break;
        case 's': socket_path = optarg; break;
        case 'f': foreground  = 1;      break;
        case 'd': debug       = 1;      break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    /* Load configuration */
    config_defaults(&g_config);
    config_load_initiator_name(&g_config);
    if (config_load(&g_config, config_path) != 0) {
        fprintf(stderr, "iscsid: failed to load configuration\n");
        return 1;
    }
    if (debug)       g_config.log_debug = 1;
    if (socket_path) snprintf(g_config.socket_path, sizeof(g_config.socket_path),
                              "%s", socket_path);

    openlog("iscsid", LOG_PID | LOG_NDELAY,
            foreground ? LOG_USER : LOG_DAEMON);

    if (!foreground) daemonise();

    write_pid_file(g_config.pid_file);

    syslog(LOG_INFO, "iscsid-mac starting (initiator: %s)",
           g_config.initiator_name);
    if (foreground) {
        printf("iscsid-mac started  initiator=%s  socket=%s\n",
               g_config.initiator_name, g_config.socket_path);
        if (g_config.log_debug) config_print(&g_config);
    }

    /* Set up signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* Create IPC socket */
    g_ipc_fd = ipc_server_create(g_config.socket_path);
    if (g_ipc_fd < 0) {
        syslog(LOG_ERR, "failed to create IPC socket at %s",
               g_config.socket_path);
        remove_pid_file(g_config.pid_file);
        return 1;
    }

    /* Main event loop: accept and handle IPC clients sequentially.
     *
     * A production implementation would use a thread pool or kqueue,
     * but for clarity we keep this single-threaded with select(2).
     */
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_ipc_fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int nfds = select(g_ipc_fd + 1, &rfds, NULL, NULL, &tv);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "select: %s", strerror(errno));
            break;
        }
        if (nfds == 0) continue;   /* timeout */

        if (FD_ISSET(g_ipc_fd, &rfds)) {
            int client = ipc_server_accept(g_ipc_fd);
            if (client >= 0) {
                handle_ipc_client(client);
            }
        }
    }

    /* Cleanup: logout all sessions */
    syslog(LOG_INFO, "iscsid-mac shutting down");
    iscsi_session_t *s = g_sessions;
    while (s) {
        iscsi_session_t *next = s->next;
        iscsi_conn_t *c = session_lead_conn(s);
        if (c && c->state == CONN_STATE_LOGGED_IN) {
            iscsi_logout(s, c, ISCSI_LOGOUT_CLOSE_SESSION);
        }
        session_destroy(s);
        s = next;
    }

    close(g_ipc_fd);
    unlink(g_config.socket_path);
    remove_pid_file(g_config.pid_file);
    closelog();
    return 0;
}
