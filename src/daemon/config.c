/*
 * config.c - iscsid configuration file parser
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

/* -----------------------------------------------------------------------
 * Defaults
 * ----------------------------------------------------------------------- */

void config_defaults(iscsid_config_t *cfg)
{
    snprintf(cfg->initiator_name, sizeof(cfg->initiator_name),
             "iqn.2024-01.io.iscsid-mac:%s", "initiator");
    cfg->auth_method[0]        = '\0';
    cfg->max_burst_length      = ISCSI_DEFAULT_MAX_BURST_LENGTH;
    cfg->first_burst_length    = ISCSI_DEFAULT_FIRST_BURST_LENGTH;
    cfg->max_recv_dsl          = ISCSI_DEFAULT_MAX_RECV_DSL;
    cfg->initial_r2t           = ISCSI_DEFAULT_INITIAL_R2T;
    cfg->immediate_data        = ISCSI_DEFAULT_IMMEDIATE_DATA;
    cfg->error_recovery_level  = ISCSI_DEFAULT_ERROR_RECOVERY_LEVEL;
    cfg->max_connections       = ISCSI_DEFAULT_MAX_CONNECTIONS;
    snprintf(cfg->pid_file,    sizeof(cfg->pid_file),
             "/var/run/iscsid.pid");
    snprintf(cfg->socket_path, sizeof(cfg->socket_path),
             "/var/run/iscsid.sock");
    cfg->log_debug = 0;
}

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

/* Trim leading/trailing whitespace in-place; return start pointer */
static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)*(e-1))) e--;
    *e = '\0';
    return s;
}

/* -----------------------------------------------------------------------
 * Config file parser
 * ----------------------------------------------------------------------- */

int config_load(iscsid_config_t *cfg, const char *path)
{
    const char *p = path ? path : ISCSID_DEFAULT_CONFIG_PATH;
    FILE *fp = fopen(p, "r");
    if (!fp) {
        if (errno == ENOENT) return 0;   /* no file is OK — use defaults */
        fprintf(stderr, "config: cannot open %s: %s\n", p, strerror(errno));
        return -1;
    }

    char line[1024];
    int lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char *l = trim(line);

        /* Skip comments and blank lines */
        if (*l == '#' || *l == '\0') continue;

        /* Split on first '=' */
        char *eq = strchr(l, '=');
        if (!eq) {
            fprintf(stderr, "config:%d: syntax error (no '=')\n", lineno);
            continue;
        }
        *eq = '\0';
        char *key = trim(l);
        char *val = trim(eq + 1);

#define MATCH(k)  (strcmp(key, (k)) == 0)
#define STR(dst)  snprintf((dst), sizeof(dst), "%s", val)

        if      (MATCH("node.session.auth.username"))
            STR(cfg->chap_username);
        else if (MATCH("node.session.auth.password"))
            STR(cfg->chap_secret);
        else if (MATCH("node.session.auth.username_in"))
            STR(cfg->chap_target_username);
        else if (MATCH("node.session.auth.password_in"))
            STR(cfg->chap_target_secret);
        else if (MATCH("node.session.auth.authmethod"))
            STR(cfg->auth_method);
        else if (MATCH("node.session.iscsi.MaxBurstLength"))
            cfg->max_burst_length = (uint32_t)atol(val);
        else if (MATCH("node.session.iscsi.FirstBurstLength"))
            cfg->first_burst_length = (uint32_t)atol(val);
        else if (MATCH("node.session.iscsi.MaxRecvDataSegmentLength"))
            cfg->max_recv_dsl = (uint32_t)atol(val);
        else if (MATCH("node.session.iscsi.InitialR2T"))
            cfg->initial_r2t = (strcmp(val, "Yes") == 0 || strcmp(val, "1") == 0);
        else if (MATCH("node.session.iscsi.ImmediateData"))
            cfg->immediate_data = (strcmp(val, "Yes") == 0 || strcmp(val, "1") == 0);
        else if (MATCH("node.session.iscsi.ErrorRecoveryLevel"))
            cfg->error_recovery_level = atoi(val);
        else if (MATCH("node.session.iscsi.MaxConnections"))
            cfg->max_connections = (uint32_t)atol(val);
        else if (MATCH("iscsid.pid_file"))
            STR(cfg->pid_file);
        else if (MATCH("iscsid.socket_path"))
            STR(cfg->socket_path);
        else if (MATCH("iscsid.debug"))
            cfg->log_debug = atoi(val);

#undef MATCH
#undef STR
    }
    fclose(fp);
    return 0;
}

/* -----------------------------------------------------------------------
 * Initiator name
 * ----------------------------------------------------------------------- */

void config_load_initiator_name(iscsid_config_t *cfg)
{
    FILE *fp = fopen(ISCSID_INITIATOR_NAME_PATH, "r");
    if (!fp) {
        /* Generate a unique IQN based on hostname + random suffix */
        char hostname[128] = "localhost";
        gethostname(hostname, sizeof(hostname));

        /* Sanitise hostname (remove chars not valid in IQN) */
        for (char *c = hostname; *c; c++) {
            if (!isalnum((unsigned char)*c) && *c != '-' && *c != '.') {
                *c = '-';
            }
        }

        /* Get current year/month for IQN date */
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char date[8];
        strftime(date, sizeof(date), "%Y-%m", t);

        /* Random 4-byte suffix */
        uint32_t rnd = 0;
        FILE *rp = fopen("/dev/urandom", "rb");
        if (rp) {
            if (fread(&rnd, sizeof(rnd), 1, rp) != 1) rnd = (uint32_t)now;
            fclose(rp);
        }

        snprintf(cfg->initiator_name, sizeof(cfg->initiator_name),
                 "iqn.%s.io.iscsid-mac:%s:%08x", date, hostname, rnd);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *l = trim(line);
        if (*l == '#' || *l == '\0') continue;
        if (strncmp(l, "InitiatorName=", 14) == 0) {
            snprintf(cfg->initiator_name, sizeof(cfg->initiator_name),
                     "%s", trim(l + 14));
            break;
        }
    }
    fclose(fp);
}

/* -----------------------------------------------------------------------
 * Apply to session
 * ----------------------------------------------------------------------- */

void config_apply_session(const iscsid_config_t *cfg, iscsi_session_t *sess)
{
    snprintf(sess->initiator_name, sizeof(sess->initiator_name),
             "%s", cfg->initiator_name);

    if (cfg->chap_secret[0]) {
        snprintf(sess->chap_username,     sizeof(sess->chap_username),
                 "%s", cfg->chap_username);
        snprintf(sess->chap_secret,       sizeof(sess->chap_secret),
                 "%s", cfg->chap_secret);
        snprintf(sess->chap_target_secret, sizeof(sess->chap_target_secret),
                 "%s", cfg->chap_target_secret);
    }

    sess->params.max_burst_length     = cfg->max_burst_length;
    sess->params.first_burst_length   = cfg->first_burst_length;
    sess->params.max_recv_dsl         = cfg->max_recv_dsl;
    sess->params.initial_r2t          = cfg->initial_r2t;
    sess->params.immediate_data       = cfg->immediate_data;
    sess->params.error_recovery_level = cfg->error_recovery_level;
    sess->params.max_connections      = cfg->max_connections;
}

/* -----------------------------------------------------------------------
 * Debug print
 * ----------------------------------------------------------------------- */

void config_print(const iscsid_config_t *cfg)
{
    printf("iscsid configuration:\n");
    printf("  InitiatorName = %s\n", cfg->initiator_name);
    printf("  AuthMethod    = %s\n", cfg->auth_method[0] ? cfg->auth_method : "(default)");
    if (cfg->chap_username[0])
        printf("  CHAP username = %s\n", cfg->chap_username);
    printf("  MaxBurstLength     = %u\n", cfg->max_burst_length);
    printf("  FirstBurstLength   = %u\n", cfg->first_burst_length);
    printf("  MaxRecvDataSeg     = %u\n", cfg->max_recv_dsl);
    printf("  InitialR2T         = %s\n", cfg->initial_r2t ? "Yes" : "No");
    printf("  ImmediateData      = %s\n", cfg->immediate_data ? "Yes" : "No");
    printf("  ErrorRecoveryLevel = %d\n", cfg->error_recovery_level);
    printf("  Socket             = %s\n", cfg->socket_path);
    printf("  PidFile            = %s\n", cfg->pid_file);
}
