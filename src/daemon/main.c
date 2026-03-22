/*
 * main.c - iscsid-mac: Open-source iSCSI initiator daemon for macOS
 *
 * Architecture:
 *   - This daemon manages iSCSI sessions, connections, and discovery.
 *   - A Unix domain socket (IPC) accepts commands from iscsictl.
 *   - Session connection FDs are monitored for NOP-In pings and
 *     ASYNC_MSG events via kqueue.
 *   - A future DriverKit DEXT communicates via IOUserClient to expose
 *     iSCSI LUNs as macOS block devices.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "async.h"
#include "config.h"
#include "connection.h"
#include "discovery.h"
#include "ipc.h"
#include "isns.h"
#include "login.h"
#include "nbd.h"
#include "pdu.h"
#include "persist.h"
#include "recovery.h"
#include "scsi.h"
#include "session.h"
#include "taskmgmt.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Global state
 * ----------------------------------------------------------------------- */

static iscsid_config_t  g_config;
static iscsi_session_t *g_sessions = NULL;     /* linked list */
static int              g_ipc_fd   = -1;
static int              g_kq       = -1;        /* kqueue fd */
static volatile sig_atomic_t g_running = 1;

/*
 * Protects g_sessions list pointer and all session/conn state fields that
 * are accessed from both the kqueue thread and IPC worker threads.
 * Rule: never hold this lock while performing blocking network I/O.
 */
static pthread_mutex_t  g_sessions_lock = PTHREAD_MUTEX_INITIALIZER;

/* Maximum concurrent IPC operations; prevents resource exhaustion */
#define IPC_MAX_CLIENTS  8
static volatile int     g_ipc_clients  = 0;
static pthread_mutex_t  g_ipc_clients_lock = PTHREAD_MUTEX_INITIALIZER;

/* -----------------------------------------------------------------------
 * Signal handling
 * ----------------------------------------------------------------------- */

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* -----------------------------------------------------------------------
 * kqueue registration helpers
 * ----------------------------------------------------------------------- */

static void kq_add_conn(iscsi_conn_t *conn)
{
    if (g_kq < 0 || conn->fd < 0) return;
    struct kevent kev;
    EV_SET(&kev, (uintptr_t)conn->fd,
           EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)conn);
    kevent(g_kq, &kev, 1, NULL, 0, NULL);
}

static void kq_del_conn(iscsi_conn_t *conn)
{
    if (g_kq < 0 || conn->fd < 0) return;
    struct kevent kev;
    EV_SET(&kev, (uintptr_t)conn->fd,
           EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(g_kq, &kev, 1, NULL, 0, NULL);
}

/* -----------------------------------------------------------------------
 * Simple JSON helpers (no external library dependency)
 * ----------------------------------------------------------------------- */

/*
 * Escape a string for safe embedding in a JSON string value.
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

static int json_get_str(const char *json, const char *key,
                         char *dst, size_t dst_size)
{
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) {
        snprintf(pat, sizeof(pat), "\"%s\":", key);
        p = strstr(json, pat);
        if (!p) return -1;
        p += strlen(pat);
        while (*p == ' ') p++;
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
 * Port number parsing with bounds checking
 * ----------------------------------------------------------------------- */

/*
 * Parse a decimal port string.  Returns the port on success.
 * Returns 0 if the string is empty, non-numeric, or out of [1, 65535].
 */
static uint16_t parse_port(const char *str)
{
    if (!str || !str[0]) return 0;
    char *end;
    long v = strtol(str, &end, 10);
    if (end == str || *end != '\0' || v < 1 || v > 65535) return 0;
    return (uint16_t)v;
}

/* -----------------------------------------------------------------------
 * Lookup: find a session by target name
 * ----------------------------------------------------------------------- */

static iscsi_session_t *find_session(const char *target)
{
    for (iscsi_session_t *s = g_sessions; s; s = s->next) {
        if (strcmp(s->target_name, target) == 0)
            return s;
    }
    return NULL;
}


/* -----------------------------------------------------------------------
 * NBD server thread
 *
 * Spawned by the nbd-serve IPC handler.  Runs nbd_serve() then releases
 * the session busy_count pin and re-arms the kqueue filter for the
 * iSCSI connection it was given exclusive use of.
 * ----------------------------------------------------------------------- */

typedef struct {
    iscsi_session_t *sess;
    iscsi_conn_t    *conn;
    uint8_t          lun_raw[8];
    int              listen_fd;
} nbd_thread_arg_t;

static void *nbd_thread(void *arg)
{
    nbd_thread_arg_t *a = arg;
    nbd_serve(a->sess, a->conn, a->lun_raw, a->listen_fd);

    /* Re-arm kqueue and release the busy pin so logout can proceed. */
    pthread_mutex_lock(&g_sessions_lock);
    kq_add_conn(a->conn);
    if (--a->sess->busy_count == 0)
        pthread_cond_broadcast(&a->sess->recovery_done);
    pthread_mutex_unlock(&g_sessions_lock);

    free(a);
    return NULL;
}

/* -----------------------------------------------------------------------
 * IPC request handler (runs in a dedicated pthread per client)
 * ----------------------------------------------------------------------- */

static void handle_ipc_client(int client_fd);   /* forward declaration */

static void *ipc_client_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;

    pthread_mutex_lock(&g_ipc_clients_lock);
    int over_limit = (g_ipc_clients >= IPC_MAX_CLIENTS);
    if (!over_limit) g_ipc_clients++;
    pthread_mutex_unlock(&g_ipc_clients_lock);

    if (over_limit) {
        ipc_send(fd, "{\"status\":\"error\",\"msg\":\"too many concurrent requests\"}");
        close(fd);
        return NULL;
    }

    handle_ipc_client(fd);

    pthread_mutex_lock(&g_ipc_clients_lock);
    g_ipc_clients--;
    pthread_mutex_unlock(&g_ipc_clients_lock);
    return NULL;
}

static void handle_ipc_client(int client_fd)
{
    char req[IPC_MAX_MSG_LEN];
    char resp[IPC_MAX_MSG_LEN];
    int  rc;
    int  done = 0;  /* set to 1 by nbd-serve to exit after sending response */

    while (!done && (rc = ipc_recv(client_fd, req, sizeof(req))) > 0) {
        char cmd[64] = {0};
        json_get_str(req, "cmd", cmd, sizeof(cmd));

        /* ---- ping ---- */
        if (strcmp(cmd, IPC_CMD_PING) == 0) {
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"msg\":\"pong\"}");

        /* ---- SendTargets discover ---- */
        } else if (strcmp(cmd, IPC_CMD_DISCOVER) == 0) {
            char host[256] = "127.0.0.1";
            char port_str[16] = "3260";
            json_get_str(req, "host", host, sizeof(host));
            json_get_str(req, "port", port_str, sizeof(port_str));
            uint16_t port = parse_port(port_str);
            if (!port) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"invalid port\"}");
                goto send_resp;
            }

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
                int off = snprintf(resp, sizeof(resp),
                                   "{\"status\":\"ok\",\"count\":%d,\"targets\":[",
                                   count);
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

        /* ---- iSNS discover ---- */
        } else if (strcmp(cmd, IPC_CMD_ISNS_DISCOVER) == 0) {
            char host[256] = "127.0.0.1";
            char port_str[16] = "3205";
            json_get_str(req, "host", host, sizeof(host));
            json_get_str(req, "port", port_str, sizeof(port_str));
            uint16_t port = parse_port(port_str);
            if (!port) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"invalid port\"}");
                goto send_resp;
            }

            iscsi_target_info_t targets[ISCSI_MAX_DISCOVERY_TARGETS];
            int count = isns_discover(host, port, g_config.initiator_name,
                                       targets, ISCSI_MAX_DISCOVERY_TARGETS);
            if (count < 0) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"iSNS discovery failed\"}");
            } else {
                int off = snprintf(resp, sizeof(resp),
                                   "{\"status\":\"ok\",\"count\":%d,\"targets\":[",
                                   count);
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

        /* ---- login ---- */
        } else if (strcmp(cmd, IPC_CMD_LOGIN) == 0) {
            char host[256] = {0};
            char port_str[16] = "3260";
            char target[ISCSI_MAX_NAME_LEN] = {0};
            json_get_str(req, "host",   host,      sizeof(host));
            json_get_str(req, "port",   port_str,  sizeof(port_str));
            json_get_str(req, "target", target,    sizeof(target));
            uint16_t port = parse_port(port_str);

            if (!host[0] || !target[0]) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"missing host or target\"}");
                goto send_resp;
            }
            if (!port) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"invalid port\"}");
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
            config_apply_session_target(&g_config, target, sess);

            iscsi_conn_t *conn = conn_create(host, port);
            if (!conn) {
                session_destroy(sess);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"connection failed\"}");
                goto send_resp;
            }
            conn->cid = session_next_cid(sess);
            session_add_conn(sess, conn);
            conn_set_keepalive(conn, g_config.tcp_keepalive_idle,
                               g_config.tcp_keepalive_interval,
                               g_config.tcp_keepalive_count);

            login_result_t lr = iscsi_login(sess, conn);  /* blocking I/O — no lock */
            if (lr != LOGIN_OK) {
                session_destroy(sess);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"%s\"}",
                         login_result_str(lr));
                goto send_resp;
            }

            pthread_mutex_lock(&g_sessions_lock);
            kq_add_conn(conn);
            sess->next = g_sessions;
            g_sessions = sess;
            pthread_mutex_unlock(&g_sessions_lock);

            /* Persist session so it survives daemon restarts */
            persist_add(g_config.persist_path, target, host, port);

            {
                char esc_target[512];
                json_escape(esc_target, sizeof(esc_target), target);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"ok\",\"msg\":\"logged in\","
                         "\"target\":\"%s\",\"tsih\":%u}",
                         esc_target, sess->tsih);
            }

        /* ---- logout ---- */
        } else if (strcmp(cmd, IPC_CMD_LOGOUT) == 0) {
            char target[ISCSI_MAX_NAME_LEN] = {0};
            json_get_str(req, "target", target, sizeof(target));

            iscsi_session_t *prev = NULL, *s;
            iscsi_conn_t    *lead = NULL;

            pthread_mutex_lock(&g_sessions_lock);
            s = g_sessions;
            while (s) {
                if (strcmp(s->target_name, target) == 0) {
                    /*
                     * If a recovery thread is running for this session, wait
                     * for it to finish before proceeding.  The recovery thread
                     * broadcasts recovery_done (under g_sessions_lock) when it
                     * clears recovery_in_progress, so pthread_cond_timedwait is
                     * safe here.  A 5-second timeout guards against a hung thread.
                     */
                    if (s->recovery_in_progress || s->busy_count > 0) {
                        struct timespec deadline;
                        clock_gettime(CLOCK_REALTIME, &deadline);
                        deadline.tv_sec += 5;
                        while (s->recovery_in_progress || s->busy_count > 0) {
                            int wrc = pthread_cond_timedwait(
                                &s->recovery_done, &g_sessions_lock, &deadline);
                            if (wrc == ETIMEDOUT) {
                                syslog(LOG_WARNING,
                                       "logout: timed out waiting for "
                                       "in-progress operations on %s; "
                                       "proceeding anyway",
                                       s->target_name);
                                break;
                            }
                        }
                    }
                    for (iscsi_conn_t *c = s->connections; c; c = c->next)
                        kq_del_conn(c);
                    lead = session_lead_conn(s);
                    if (prev) prev->next = s->next;
                    else      g_sessions = s->next;
                    break;
                }
                prev = s; s = s->next;
            }
            pthread_mutex_unlock(&g_sessions_lock);

            if (s) {
                /* Blocking logout I/O happens outside the lock */
                if (lead) iscsi_logout(s, lead, ISCSI_LOGOUT_CLOSE_SESSION);
                persist_remove(g_config.persist_path, target);
                session_destroy(s);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"ok\",\"msg\":\"logged out\"}");
            } else {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"session not found\"}");
            }

        /* ---- add-connection (MCS) ---- */
        } else if (strcmp(cmd, IPC_CMD_ADD_CONN) == 0) {
            char host[256] = {0};
            char port_str[16] = "3260";
            char target[ISCSI_MAX_NAME_LEN] = {0};
            json_get_str(req, "host",   host,     sizeof(host));
            json_get_str(req, "port",   port_str, sizeof(port_str));
            json_get_str(req, "target", target,   sizeof(target));
            uint16_t port = parse_port(port_str);
            if (!port) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"invalid port\"}");
                goto send_resp;
            }

            pthread_mutex_lock(&g_sessions_lock);
            iscsi_session_t *sess = find_session(target);
            unsigned int max_c = sess ? sess->params.max_connections : 0;
            unsigned int cur_c = sess ? sess->num_connections : 0;
            /* Pin the session and remove the lead conn from kqueue before
             * dropping the lock; iscsi_login_add_conn() does blocking I/O
             * that must not race with the kqueue event loop. */
            iscsi_conn_t *lead_for_kq = NULL;
            if (sess && cur_c < max_c) {
                sess->busy_count++;
                lead_for_kq = session_lead_conn(sess);
                if (lead_for_kq) kq_del_conn(lead_for_kq);
            }
            pthread_mutex_unlock(&g_sessions_lock);

            if (!sess) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"session not found\"}");
                goto send_resp;
            }
            if (cur_c >= max_c) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\","
                         "\"msg\":\"MaxConnections limit reached\"}");
                goto send_resp;
            }

            iscsi_conn_t *new_conn = conn_create(host[0] ? host : "127.0.0.1",
                                                  port);
            if (!new_conn) {
                pthread_mutex_lock(&g_sessions_lock);
                if (lead_for_kq) kq_add_conn(lead_for_kq);
                if (--sess->busy_count == 0)
                    pthread_cond_broadcast(&sess->recovery_done);
                pthread_mutex_unlock(&g_sessions_lock);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"connection failed\"}");
                goto send_resp;
            }
            new_conn->cid = session_next_cid(sess);
            conn_set_keepalive(new_conn, g_config.tcp_keepalive_idle,
                               g_config.tcp_keepalive_interval,
                               g_config.tcp_keepalive_count);

            login_result_t lr = iscsi_login_add_conn(sess, new_conn); /* blocking */
            if (lr != LOGIN_OK) {
                conn_destroy(new_conn);
                pthread_mutex_lock(&g_sessions_lock);
                if (lead_for_kq) kq_add_conn(lead_for_kq);
                if (--sess->busy_count == 0)
                    pthread_cond_broadcast(&sess->recovery_done);
                pthread_mutex_unlock(&g_sessions_lock);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"%s\"}",
                         login_result_str(lr));
                goto send_resp;
            }

            pthread_mutex_lock(&g_sessions_lock);
            session_add_conn(sess, new_conn);
            if (lead_for_kq) kq_add_conn(lead_for_kq);
            kq_add_conn(new_conn);
            if (--sess->busy_count == 0)
                pthread_cond_broadcast(&sess->recovery_done);
            pthread_mutex_unlock(&g_sessions_lock);

            snprintf(resp, sizeof(resp),
                     "{\"status\":\"ok\",\"msg\":\"connection added\","
                     "\"cid\":%u,\"total_connections\":%u}",
                     new_conn->cid, sess->num_connections);

        /* ---- luns ---- */
        } else if (strcmp(cmd, IPC_CMD_LUNS) == 0) {
            char target[ISCSI_MAX_NAME_LEN] = {0};
            json_get_str(req, "target", target, sizeof(target));

            pthread_mutex_lock(&g_sessions_lock);
            iscsi_session_t *sess = find_session(target);
            iscsi_conn_t    *lead = sess ? session_lead_conn(sess) : NULL;
            if (sess && lead) {
                sess->busy_count++;
                /*
                 * Deregister the conn from kqueue before sending the SCSI
                 * command.  The kqueue event loop runs on the main thread and
                 * calls conn_handle_incoming() → pdu_recv() on conn->fd; if it
                 * fires while scsi_exec() is also waiting in pdu_recv(), it can
                 * steal the SCSI response, causing scsi_exec() to hang until
                 * the recv timeout.  Removing the filter here (before the CMD
                 * is sent) eliminates the race: no SCSI response can arrive
                 * before the command is on the wire.  kq_add_conn() below
                 * re-arms the filter; if data accumulated during the I/O it
                 * fires immediately on the next kevent() iteration.
                 */
                kq_del_conn(lead);
            }
            pthread_mutex_unlock(&g_sessions_lock);

            if (!sess) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"session not found\"}");
                goto send_resp;
            }
            if (!lead) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"no active connection\"}");
                goto send_resp;
            }

            iscsi_lun_t luns[256];
            int nluns = scsi_report_luns(sess, lead, luns, 256);

            pthread_mutex_lock(&g_sessions_lock);
            kq_add_conn(lead);
            if (--sess->busy_count == 0)
                pthread_cond_broadcast(&sess->recovery_done);
            pthread_mutex_unlock(&g_sessions_lock);

            if (nluns < 0) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"REPORT LUNS failed\"}");
                goto send_resp;
            }
            {
                int off = snprintf(resp, sizeof(resp),
                                   "{\"status\":\"ok\",\"count\":%d,\"luns\":[",
                                   nluns);
                for (int i = 0; i < nluns; i++) {
                    int n = snprintf(resp + off, sizeof(resp) - (size_t)off,
                                     "%s%u", i ? "," : "", luns[i].id);
                    if (n < 0 || (size_t)(off + n) >= sizeof(resp)) break;
                    off += n;
                }
                snprintf(resp + off, sizeof(resp) - (size_t)off, "]}");
            }

        /* ---- list ---- */
        } else if (strcmp(cmd, IPC_CMD_LIST) == 0) {
            int off = snprintf(resp, sizeof(resp),
                               "{\"status\":\"ok\",\"sessions\":[");
            int first = 1;
            pthread_mutex_lock(&g_sessions_lock);
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
                              ",\"state\":\"%s\",\"tsih\":%u"
                              ",\"connections\":%u}",
                              sess_state_str(s->state), s->tsih,
                              s->num_connections);
                if (n2 < 0 || (size_t)(off + n2) >= sizeof(resp)) break;
                off += n2;
                first = 0;
            }
            pthread_mutex_unlock(&g_sessions_lock);
            snprintf(resp + off, sizeof(resp) - (size_t)off, "]}");

        /* ---- status ---- */
        } else if (strcmp(cmd, IPC_CMD_STATUS) == 0) {
            int n = 0;
            pthread_mutex_lock(&g_sessions_lock);
            for (iscsi_session_t *s = g_sessions; s; s = s->next) n++;
            pthread_mutex_unlock(&g_sessions_lock);
            char esc_init[512];
            json_escape(esc_init, sizeof(esc_init), g_config.initiator_name);
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"ok\",\"sessions\":%d,"
                     "\"initiator\":\"%s\"}",
                     n, esc_init);

        /* ---- nbd-serve: expose a LUN as an NBD block device ---- */
        } else if (strcmp(cmd, IPC_CMD_NBD_SERVE) == 0) {
            char target[ISCSI_MAX_NAME_LEN] = {0};
            char lun_str[32] = "0";
            json_get_str(req, "target", target, sizeof(target));
            json_get_str(req, "lun",    lun_str, sizeof(lun_str));

            unsigned long lv = strtoul(lun_str, NULL, 10);
            if (lv > 65535u) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"invalid LUN number\"}");
                goto send_resp;
            }
            uint16_t lun_id = (uint16_t)lv;

            /* Pin the session and remove the lead conn from kqueue so the
             * NBD server thread has exclusive use of the iSCSI connection. */
            pthread_mutex_lock(&g_sessions_lock);
            iscsi_session_t *nbd_sess = find_session(target);
            iscsi_conn_t    *nbd_lead = nbd_sess
                                         ? session_lead_conn(nbd_sess) : NULL;
            if (nbd_sess && nbd_lead) {
                nbd_sess->busy_count++;
                kq_del_conn(nbd_lead);
            }
            pthread_mutex_unlock(&g_sessions_lock);

            if (!nbd_sess) {
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"session not found\"}");
                goto send_resp;
            }
            if (!nbd_lead) {
                pthread_mutex_lock(&g_sessions_lock);
                if (--nbd_sess->busy_count == 0)
                    pthread_cond_broadcast(&nbd_sess->recovery_done);
                pthread_mutex_unlock(&g_sessions_lock);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\","
                         "\"msg\":\"no active connection\"}");
                goto send_resp;
            }

            /* Enumerate LUNs (kqueue already deregistered — no race). */
            iscsi_lun_t luns[256];
            int nluns = scsi_report_luns(nbd_sess, nbd_lead, luns, 256);
            uint8_t lun_raw[8] = {0};
            int found_lun = 0;
            for (int i = 0; i < nluns; i++) {
                if (luns[i].id == lun_id) {
                    memcpy(lun_raw, luns[i].raw, 8);
                    found_lun = 1;
                    break;
                }
            }
            if (!found_lun) {
                pthread_mutex_lock(&g_sessions_lock);
                kq_add_conn(nbd_lead);
                if (--nbd_sess->busy_count == 0)
                    pthread_cond_broadcast(&nbd_sess->recovery_done);
                pthread_mutex_unlock(&g_sessions_lock);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\","
                         "\"msg\":\"LUN not found\"}");
                goto send_resp;
            }

            int nbd_port = 0;
            int listen_fd = nbd_bind(&nbd_port);
            if (listen_fd < 0) {
                pthread_mutex_lock(&g_sessions_lock);
                kq_add_conn(nbd_lead);
                if (--nbd_sess->busy_count == 0)
                    pthread_cond_broadcast(&nbd_sess->recovery_done);
                pthread_mutex_unlock(&g_sessions_lock);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\","
                         "\"msg\":\"NBD bind failed\"}");
                goto send_resp;
            }

            nbd_thread_arg_t *na = malloc(sizeof(*na));
            if (!na) {
                close(listen_fd);
                pthread_mutex_lock(&g_sessions_lock);
                kq_add_conn(nbd_lead);
                if (--nbd_sess->busy_count == 0)
                    pthread_cond_broadcast(&nbd_sess->recovery_done);
                pthread_mutex_unlock(&g_sessions_lock);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\",\"msg\":\"out of memory\"}");
                goto send_resp;
            }
            na->sess      = nbd_sess;
            na->conn      = nbd_lead;
            memcpy(na->lun_raw, lun_raw, 8);
            na->listen_fd = listen_fd;

            pthread_t      nbd_tid;
            pthread_attr_t nbd_attr;
            pthread_attr_init(&nbd_attr);
            pthread_attr_setdetachstate(&nbd_attr, PTHREAD_CREATE_DETACHED);
            int trc = pthread_create(&nbd_tid, &nbd_attr, nbd_thread, na);
            pthread_attr_destroy(&nbd_attr);

            if (trc != 0) {
                free(na);
                close(listen_fd);
                pthread_mutex_lock(&g_sessions_lock);
                kq_add_conn(nbd_lead);
                if (--nbd_sess->busy_count == 0)
                    pthread_cond_broadcast(&nbd_sess->recovery_done);
                pthread_mutex_unlock(&g_sessions_lock);
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"error\","
                         "\"msg\":\"thread create failed\"}");
                goto send_resp;
            }

            /* Exit the IPC loop after this response; the NBD thread owns
             * the session and connection from here on. */
            done = 1;
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"ok\",\"port\":%d}", nbd_port);

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
 * ERL-1 recovery thread
 *
 * recovery_reconnect() sleeps for DefaultTime2Wait and then performs a
 * blocking TCP connect + login exchange.  Running this inline in the kqueue
 * thread would stall all IPC and keepalive processing.  Instead we spawn a
 * short-lived detached thread per failed connection.
 *
 * Locking discipline: g_sessions_lock is held when spawn_recovery() is
 * called (non-blocking pthread_create).  The thread re-acquires the lock
 * only at the very end to clear recovery_in_progress and update sess->state.
 * ----------------------------------------------------------------------- */

typedef struct {
    iscsi_session_t *sess;
    iscsi_conn_t    *failed_conn;
    int              kq;
} recovery_arg_t;

static void *recovery_thread(void *arg)
{
    recovery_arg_t  *ra       = arg;
    iscsi_conn_t    *new_conn = recovery_reconnect(ra->sess, ra->failed_conn,
                                                    ra->kq);
    pthread_mutex_lock(&g_sessions_lock);
    ra->sess->recovery_in_progress = 0;
    pthread_cond_broadcast(&ra->sess->recovery_done);
    if (!new_conn) {
        ra->sess->state = SESS_STATE_FAILED;
        syslog(LOG_ERR, "recovery: session %s permanently lost",
               ra->sess->target_name);
    }
    pthread_mutex_unlock(&g_sessions_lock);

    /* Wake any scsi_exec() callers that are waiting for recovery to finish. */
    session_signal_recovery(ra->sess);

    free(ra);
    return NULL;
}

/*
 * Spawn a detached ERL-1 recovery thread for sess/failed_conn.
 * Must be called with g_sessions_lock held.
 * Returns immediately (non-blocking).
 */
static void spawn_recovery(iscsi_session_t *sess, iscsi_conn_t *failed_conn,
                            int kq)
{
    if (sess->recovery_in_progress) {
        syslog(LOG_DEBUG, "recovery: already in progress for %s, skipping",
               sess->target_name);
        return;
    }

    recovery_arg_t *ra = malloc(sizeof(*ra));
    if (!ra) {
        sess->state = SESS_STATE_FAILED;
        syslog(LOG_ERR, "recovery: malloc failed for %s", sess->target_name);
        return;
    }
    ra->sess        = sess;
    ra->failed_conn = failed_conn;
    ra->kq          = kq;

    sess->recovery_in_progress = 1;

    pthread_t      tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, recovery_thread, ra) != 0) {
        syslog(LOG_ERR, "recovery: pthread_create failed for %s: %s",
               sess->target_name, strerror(errno));
        sess->recovery_in_progress = 0;
        sess->state = SESS_STATE_FAILED;
        free(ra);
    }
    pthread_attr_destroy(&attr);
}

/* -----------------------------------------------------------------------
 * Session connection event handler (kqueue callback)
 * ----------------------------------------------------------------------- */

static void handle_conn_event(iscsi_conn_t *conn, uint32_t kq_flags)
{
    pthread_mutex_lock(&g_sessions_lock);
    iscsi_session_t *sess = conn->session;
    if (!sess) { pthread_mutex_unlock(&g_sessions_lock); return; }

    if (kq_flags & EV_EOF) {
        syslog(LOG_WARNING, "event: connection to %s (CID %u) closed by target",
               sess->target_name, conn->cid);
        kq_del_conn(conn);
        conn->state = CONN_STATE_FAILED;
        if (sess->params.error_recovery_level >= 1) {
            spawn_recovery(sess, conn, g_kq);   /* non-blocking; lock still held */
        } else {
            sess->state = SESS_STATE_FAILED;
        }
        pthread_mutex_unlock(&g_sessions_lock);
        return;
    }
    pthread_mutex_unlock(&g_sessions_lock);

    /* Data available: read one PDU and dispatch (no lock — I/O path) */
    int rc = conn_handle_incoming(sess, conn);
    if (rc < 0) {
        pthread_mutex_lock(&g_sessions_lock);
        kq_del_conn(conn);
        if (sess->state == SESS_STATE_FAILED) {
            /* Target-initiated drop (ASYNC_MSG drop-session) */
            syslog(LOG_NOTICE, "event: session %s dropped by target",
                   sess->target_name);
        } else if (sess->params.error_recovery_level >= 1) {
            spawn_recovery(sess, conn, g_kq);   /* non-blocking; lock still held */
        } else {
            conn->state = CONN_STATE_FAILED;
            sess->state = SESS_STATE_FAILED;
        }
        pthread_mutex_unlock(&g_sessions_lock);
    }
}

/* -----------------------------------------------------------------------
 * PID file management
 * ----------------------------------------------------------------------- */

static void write_pid_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        if (errno == EEXIST) {
            FILE *old = fopen(path, "r");
            if (old) {
                char pidbuf[32] = {0};
                if (fgets(pidbuf, sizeof(pidbuf), old)) {
                    char *end;
                    long old_pid = strtol(pidbuf, &end, 10);
                    if (end != pidbuf && old_pid > 0)
                        syslog(LOG_WARNING,
                               "iscsid: PID file %s exists (pid %ld). "
                               "Remove it if no other instance is running.",
                               path, old_pid);
                }
                fclose(old);
            }
        } else {
            syslog(LOG_ERR, "iscsid: cannot create PID file %s: %s",
                   path, strerror(errno));
        }
        return;
    }
    dprintf(fd, "%d\n", (int)getpid());
    close(fd);
}

static void remove_pid_file(const char *path) { unlink(path); }

/* -----------------------------------------------------------------------
 * Daemonise
 * ----------------------------------------------------------------------- */

static void daemonise(void)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);

    setsid();

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

    /* Signal handling */
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

    /* Create kqueue and register the IPC listen socket */
    g_kq = kqueue();
    if (g_kq < 0) {
        syslog(LOG_ERR, "kqueue: %s", strerror(errno));
        remove_pid_file(g_config.pid_file);
        return 1;
    }

    {
        struct kevent kev;
        EV_SET(&kev, (uintptr_t)g_ipc_fd,
               EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
        kevent(g_kq, &kev, 1, NULL, 0, NULL);

        /* Keepalive timer: fire every keepalive_timer_sec seconds */
        EV_SET(&kev, 1, EVFILT_TIMER, EV_ADD, NOTE_SECONDS,
               g_config.keepalive_timer_sec, NULL);
        kevent(g_kq, &kev, 1, NULL, 0, NULL);
    }

    /* Re-establish persisted sessions from a previous run */
    {
        iscsi_persist_entry_t pentries[ISCSI_PERSIST_MAX_SESSIONS];
        int npe = persist_load(g_config.persist_path, pentries,
                                ISCSI_PERSIST_MAX_SESSIONS);
        if (npe < 0)
            syslog(LOG_WARNING, "persist: could not read %s — starting fresh",
                   g_config.persist_path);
        for (int pi = 0; pi < npe; pi++) {
            syslog(LOG_NOTICE, "persist: restoring session to %s at %s:%u",
                   pentries[pi].target, pentries[pi].host, pentries[pi].port);

            char addr[300];
            snprintf(addr, sizeof(addr), "%s:%u",
                     pentries[pi].host, pentries[pi].port);

            iscsi_session_t *sess = session_create(SESS_TYPE_NORMAL,
                                                    g_config.initiator_name,
                                                    pentries[pi].target, addr);
            if (!sess) continue;
            config_apply_session_target(&g_config, pentries[pi].target, sess);

            iscsi_conn_t *conn = conn_create(pentries[pi].host, pentries[pi].port);
            if (!conn) { session_destroy(sess); continue; }

            conn->cid = session_next_cid(sess);
            session_add_conn(sess, conn);
            conn_set_keepalive(conn, g_config.tcp_keepalive_idle,
                               g_config.tcp_keepalive_interval,
                               g_config.tcp_keepalive_count);

            if (iscsi_login(sess, conn) != LOGIN_OK) {
                syslog(LOG_WARNING, "persist: re-login failed for %s",
                       pentries[pi].target);
                session_destroy(sess);
                continue;
            }

            kq_add_conn(conn);
            sess->next = g_sessions;
            g_sessions = sess;
            syslog(LOG_NOTICE, "persist: restored session %s", pentries[pi].target);
        }
    }

    /* Main event loop */
    struct kevent events[64];
    while (g_running) {
        struct timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
        int nev = kevent(g_kq, NULL, 0, events, 64, &ts);
        if (nev < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "kevent: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nev; i++) {
            if (events[i].filter == EVFILT_TIMER) {
                /*
                 * Keepalive: send NOP-Out to idle logged-in connections.
                 *
                 * Rule: never hold g_sessions_lock during blocking I/O.
                 * Snapshot the (sess, conn) pairs under the lock, release it,
                 * then call async_send_nop_out() without the lock.
                 * Only connections that have been silent for ISCSI_KEEPALIVE_IDLE_SEC
                 * or more get a NOP-Out — active SCSI traffic keeps last_activity
                 * current so we don't spam busy connections.
                 */
                typedef struct { iscsi_session_t *s; iscsi_conn_t *c; } kap_t;
                kap_t  kap[64];
                int    nkap = 0;
                time_t now  = time(NULL);

                pthread_mutex_lock(&g_sessions_lock);
                for (iscsi_session_t *s = g_sessions; s && nkap < 64; s = s->next) {
                    if (s->state != SESS_STATE_LOGGED_IN) continue;
                    for (iscsi_conn_t *c = s->connections; c && nkap < 64;
                         c = c->next) {
                        if (c->state == CONN_STATE_LOGGED_IN &&
                            now - c->last_activity >= g_config.keepalive_idle_sec)
                            kap[nkap++] = (kap_t){ s, c };
                    }
                }
                pthread_mutex_unlock(&g_sessions_lock);

                for (int j = 0; j < nkap; j++)
                    async_send_nop_out(kap[j].s, kap[j].c);
                continue;
            }

            int fd = (int)events[i].ident;

            if (fd == g_ipc_fd) {
                /* New IPC client — hand off to a detached worker thread */
                int client = ipc_server_accept(g_ipc_fd);
                if (client >= 0) {
                    pthread_t tid;
                    pthread_attr_t attr;
                    pthread_attr_init(&attr);
                    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                    if (pthread_create(&tid, &attr, ipc_client_thread,
                                       (void *)(intptr_t)client) != 0) {
                        syslog(LOG_ERR, "pthread_create: %s", strerror(errno));
                        close(client);
                    }
                    pthread_attr_destroy(&attr);
                }

            } else {
                /* Session connection event — ident is the conn FD */
                iscsi_conn_t *conn = (iscsi_conn_t *)events[i].udata;
                if (conn && conn->state == CONN_STATE_LOGGED_IN)
                    handle_conn_event(conn, (uint32_t)events[i].flags);
            }
        }
    }

    /* Cleanup: logout all sessions */
    syslog(LOG_INFO, "iscsid-mac shutting down");
    iscsi_session_t *s = g_sessions;
    while (s) {
        iscsi_session_t *next = s->next;
        for (iscsi_conn_t *c = s->connections; c; c = c->next)
            kq_del_conn(c);
        iscsi_conn_t *lead = session_lead_conn(s);
        if (lead && lead->state == CONN_STATE_LOGGED_IN)
            iscsi_logout(s, lead, ISCSI_LOGOUT_CLOSE_SESSION);
        session_destroy(s);
        s = next;
    }

    close(g_ipc_fd);
    close(g_kq);
    unlink(g_config.socket_path);
    remove_pid_file(g_config.pid_file);
    closelog();
    return 0;
}
