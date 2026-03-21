/*
 * main.c - iscsictl: command-line interface for iscsid-mac
 *
 * Usage:
 *   iscsictl discover -h <host> [-p <port>]
 *   iscsictl login    -h <host> [-p <port>] -t <target>
 *   iscsictl logout   -t <target>
 *   iscsictl list
 *   iscsictl status
 *   iscsictl ping
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../daemon/ipc.h"
#include "../daemon/discovery.h"
#include "../shared/iscsi_protocol.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SOCK_PATH   ISCSID_SOCK_PATH

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <command> [options]\n\n"
        "Commands:\n"
        "  discover  -h <host> [-p <port>]          Discover iSCSI targets\n"
        "  login     -h <host> [-p <port>] -t <iqn> Login to a target\n"
        "  logout    -t <iqn>                        Logout from a target\n"
        "  list                                      List active sessions\n"
        "  status                                    Show daemon status\n"
        "  ping                                      Ping the daemon\n\n"
        "Options:\n"
        "  -h <host>   Target host (IP or hostname)\n"
        "  -p <port>   Target port (default: 3260)\n"
        "  -t <iqn>    Target IQN\n"
        "  -s <path>   Daemon socket path (default: %s)\n\n",
        prog, SOCK_PATH);
}

/* Send a request to iscsid and print the response */
static int send_command(const char *sock_path, const char *json)
{
    int fd = ipc_client_connect(sock_path);
    if (fd < 0) {
        fprintf(stderr, "iscsictl: cannot connect to iscsid at %s\n"
                        "          Is iscsid running?\n", sock_path);
        return 1;
    }

    if (ipc_send(fd, json) < 0) {
        fprintf(stderr, "iscsictl: send failed\n");
        close(fd);
        return 1;
    }

    char resp[IPC_MAX_MSG_LEN];
    int len = ipc_recv(fd, resp, sizeof(resp));
    close(fd);

    if (len <= 0) {
        fprintf(stderr, "iscsictl: no response from daemon\n");
        return 1;
    }

    /* Check status field */
    if (strstr(resp, "\"status\":\"error\"")) {
        /* Extract and print the message */
        char msg[512] = "(no message)";
        /* Simple extraction between "msg":" and next " */
        const char *p = strstr(resp, "\"msg\":\"");
        if (p) {
            p += 7;
            int i = 0;
            while (*p && *p != '"' && i + 1 < (int)sizeof(msg))
                msg[i++] = *p++;
            msg[i] = '\0';
        }
        fprintf(stderr, "Error: %s\n", msg);
        return 1;
    }

    /* Pretty-print certain responses */
    if (strstr(resp, "\"sessions\":[")) {
        /* List sessions */
        const char *p = strstr(resp, "\"sessions\":[");
        if (p) {
            p += 12;
            if (*p == ']') {
                printf("No active sessions.\n");
            } else {
                printf("Active sessions:\n");
                /* Very simple: just dump the raw array content */
                while (*p && *p != ']') {
                    if (*p == '{') {
                        /* Extract target and state */
                        char target[ISCSI_MAX_NAME_LEN] = {0};
                        char addr[256] = {0};
                        char state[32] = {0};
                        const char *t, *q;
                        t = strstr(p, "\"target\":\"");
                        if (t) {
                            t += 10;
                            for (int i = 0; *t && *t != '"' &&
                                 i < (int)sizeof(target)-1; i++, t++)
                                target[i] = *t;
                        }
                        t = strstr(p, "\"address\":\"");
                        if (t) {
                            t += 11;
                            for (int i = 0; *t && *t != '"' &&
                                 i < (int)sizeof(addr)-1; i++, t++)
                                addr[i] = *t;
                        }
                        t = strstr(p, "\"state\":\"");
                        if (t) {
                            t += 9;
                            for (int i = 0; *t && *t != '"' &&
                                 i < (int)sizeof(state)-1; i++, t++)
                                state[i] = *t;
                        }
                        printf("  %-50s  %-20s  %s\n", target, addr, state);
                        q = strchr(p, '}');
                        if (q) p = q + 1;
                        else break;
                    } else {
                        p++;
                    }
                }
            }
        }
    } else if (strstr(resp, "\"targets\":[")) {
        /* Discovery results */
        const char *p = strstr(resp, "\"count\":");
        if (p) {
            int count = atoi(p + 8);
            printf("Discovered %d target(s):\n", count);
        }
        p = strstr(resp, "\"targets\":[");
        if (p) {
            p += 11;
            int idx = 1;
            while (*p && *p != ']') {
                if (*p == '{') {
                    char name[ISCSI_MAX_NAME_LEN] = {0};
                    char addr[128] = {0};
                    char port[16]  = {0};
                    const char *t;
                    t = strstr(p, "\"name\":\"");
                    if (t) {
                        t += 8;
                        for (int i = 0; *t && *t != '"' &&
                             i < (int)sizeof(name)-1; i++, t++)
                            name[i] = *t;
                    }
                    t = strstr(p, "\"address\":\"");
                    if (t) {
                        t += 11;
                        for (int i = 0; *t && *t != '"' &&
                             i < (int)sizeof(addr)-1; i++, t++)
                            addr[i] = *t;
                    }
                    t = strstr(p, "\"port\":");
                    if (t) {
                        t += 7;
                        for (int i = 0; *t && *t != ',' && *t != '}' &&
                             i < (int)sizeof(port)-1; i++, t++)
                            port[i] = *t;
                    }
                    printf("  %d: %s\n     Address: %s:%s\n",
                           idx++, name, addr, port);
                    const char *q = strchr(p, '}');
                    if (q) p = q + 1;
                    else break;
                } else {
                    p++;
                }
            }
        }
    } else {
        /* Generic: extract and show "msg" if present */
        const char *p = strstr(resp, "\"msg\":\"");
        if (p) {
            p += 7;
            char msg[512] = {0};
            int i = 0;
            while (*p && *p != '"' && i + 1 < (int)sizeof(msg))
                msg[i++] = *p++;
            printf("%s\n", msg);
        } else {
            /* Print raw JSON as fallback */
            printf("%s\n", resp);
        }
    }

    return 0;
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }


    const char *host      = NULL;
    const char *port_str  = "3260";
    const char *target    = NULL;
    const char *sock_path = SOCK_PATH;
    const char *cmd       = NULL;

    /*
     * Manual argument scan: flags with values (-h, -p, -t, -s) can appear
     * anywhere; the first bare word (not a flag, not a flag's value) is the
     * subcommand.  BSD getopt(3) stops at the first non-option, so we do
     * this ourselves to support both orderings:
     *   iscsictl -s /tmp/foo discover -h host
     *   iscsictl discover -h host -s /tmp/foo
     */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            char flag = argv[i][1];
            const char *val = (argv[i][2] != '\0') ? argv[i] + 2
                            : (i + 1 < argc)       ? argv[++i]
                            : NULL;
            if (!val) { fprintf(stderr, "iscsictl: -%c requires an argument\n", flag); return 1; }
            switch (flag) {
            case 'h': host      = val; break;
            case 'p': port_str  = val; break;
            case 't': target    = val; break;
            case 's': sock_path = val; break;
            default:
                fprintf(stderr, "iscsictl: unknown option -%c\n", flag);
                usage(argv[0]);
                return 1;
            }
        } else if (!cmd) {
            cmd = argv[i];   /* first bare word = subcommand */
        }
    }

    char json[2048];

    if (!cmd) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(cmd, "discover") == 0) {
        if (!host) {
            fprintf(stderr, "iscsictl: -h <host> required for discover\n");
            return 1;
        }
        snprintf(json, sizeof(json),
                 "{\"cmd\":\"discover\",\"host\":\"%s\",\"port\":\"%s\"}",
                 host, port_str);
        return send_command(sock_path, json);

    } else if (strcmp(cmd, "login") == 0) {
        if (!host || !target) {
            fprintf(stderr, "iscsictl: -h <host> and -t <target> required\n");
            return 1;
        }
        snprintf(json, sizeof(json),
                 "{\"cmd\":\"login\",\"host\":\"%s\",\"port\":\"%s\","
                 "\"target\":\"%s\"}",
                 host, port_str, target);
        return send_command(sock_path, json);

    } else if (strcmp(cmd, "logout") == 0) {
        if (!target) {
            fprintf(stderr, "iscsictl: -t <target> required for logout\n");
            return 1;
        }
        snprintf(json, sizeof(json),
                 "{\"cmd\":\"logout\",\"target\":\"%s\"}", target);
        return send_command(sock_path, json);

    } else if (strcmp(cmd, "list") == 0) {
        snprintf(json, sizeof(json), "{\"cmd\":\"list\"}");
        return send_command(sock_path, json);

    } else if (strcmp(cmd, "status") == 0) {
        snprintf(json, sizeof(json), "{\"cmd\":\"status\"}");
        return send_command(sock_path, json);

    } else if (strcmp(cmd, "ping") == 0) {
        snprintf(json, sizeof(json), "{\"cmd\":\"ping\"}");
        return send_command(sock_path, json);

    } else {
        fprintf(stderr, "iscsictl: unknown command '%s'\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
