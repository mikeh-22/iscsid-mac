/*
 * config.c - iscsid configuration file parser
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "config.h"
#include "persist.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

/* -----------------------------------------------------------------------
 * Defaults
 * ----------------------------------------------------------------------- */

void config_defaults(iscsid_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));   /* zero all fields including target_configs */
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
    snprintf(cfg->pid_file,     sizeof(cfg->pid_file),
             "/var/run/iscsid.pid");
    snprintf(cfg->socket_path,  sizeof(cfg->socket_path),
             "/var/run/iscsid.sock");
    snprintf(cfg->persist_path, sizeof(cfg->persist_path),
             ISCSI_PERSIST_DEFAULT_PATH);
    cfg->log_debug = 0;

    cfg->keepalive_timer_sec    = 30;
    cfg->keepalive_idle_sec     = 25;
    cfg->tcp_keepalive_idle     = 60;
    cfg->tcp_keepalive_interval = 10;
    cfg->tcp_keepalive_count    = 3;
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
        syslog(LOG_ERR, "config: cannot open %s: %s", p, strerror(errno));
        return -1;
    }

    char line[1024];
    int  lineno = 0;
    iscsi_target_config_t *cur_target = NULL;   /* NULL = global section */

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char *l = trim(line);

        /* Skip comments and blank lines */
        if (*l == '#' || *l == '\0') continue;

        /* Section header: [iqn.YYYY-MM.domain:name] */
        if (*l == '[') {
            char *end = strchr(l, ']');
            if (!end) {
                syslog(LOG_WARNING, "config:%d: unterminated '['", lineno);
                continue;
            }
            *end = '\0';
            const char *iqn = trim(l + 1);
            cur_target = NULL;
            if (cfg->num_target_configs < ISCSID_MAX_TARGET_CONFIGS) {
                cur_target = &cfg->target_configs[cfg->num_target_configs++];
                memset(cur_target, 0, sizeof(*cur_target));
                snprintf(cur_target->target, sizeof(cur_target->target), "%s", iqn);
            } else {
                syslog(LOG_WARNING, "config: too many target sections (max %d)",
                       ISCSID_MAX_TARGET_CONFIGS);
            }
            continue;
        }

        /* Split on first '=' */
        char *eq = strchr(l, '=');
        if (!eq) {
            syslog(LOG_WARNING, "config:%d: syntax error (no '=')", lineno);
            continue;
        }
        *eq = '\0';
        char *key = trim(l);
        char *val = trim(eq + 1);

#define MATCH(k)  (strcmp(key, (k)) == 0)
#define GSTR(dst) snprintf((dst), sizeof(dst), "%s", val)
#define TSTR(dst) snprintf((dst), sizeof(dst), "%s", val)  /* cur_target non-null in this branch */

        if (cur_target) {
            /* Per-target keys */
            if      (MATCH("node.session.auth.username"))
                TSTR(cur_target->chap_username);
            else if (MATCH("node.session.auth.password"))
                TSTR(cur_target->chap_secret);
            else if (MATCH("node.session.auth.password_in"))
                TSTR(cur_target->chap_target_secret);
            else if (MATCH("node.session.auth.authmethod"))
                TSTR(cur_target->auth_method);
        } else {
            /* Global keys */
            if      (MATCH("node.session.auth.username"))
                GSTR(cfg->chap_username);
            else if (MATCH("node.session.auth.password"))
                GSTR(cfg->chap_secret);
            else if (MATCH("node.session.auth.username_in"))
                GSTR(cfg->chap_target_username);
            else if (MATCH("node.session.auth.password_in"))
                GSTR(cfg->chap_target_secret);
            else if (MATCH("node.session.auth.authmethod"))
                GSTR(cfg->auth_method);
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
            else if (MATCH("node.session.iscsi.ErrorRecoveryLevel")) {
                char *end; long v = strtol(val, &end, 10);
                if (end != val && v >= 0 && v <= 2) cfg->error_recovery_level = (int)v;
            }
            else if (MATCH("node.session.iscsi.MaxConnections"))
                cfg->max_connections = (uint32_t)atol(val);
            else if (MATCH("iscsid.pid_file"))
                GSTR(cfg->pid_file);
            else if (MATCH("iscsid.socket_path"))
                GSTR(cfg->socket_path);
            else if (MATCH("iscsid.debug")) {
                char *end; long v = strtol(val, &end, 10);
                if (end != val) cfg->log_debug = (v != 0);
            }
            else if (MATCH("iscsid.keepalive_timer")) {
                char *end; long v = strtol(val, &end, 10);
                if (end != val && v >= 1 && v <= 3600) cfg->keepalive_timer_sec = (int)v;
            }
            else if (MATCH("iscsid.keepalive_idle")) {
                char *end; long v = strtol(val, &end, 10);
                if (end != val && v >= 1 && v <= 3600) cfg->keepalive_idle_sec = (int)v;
            }
            else if (MATCH("iscsid.tcp_keepalive_idle")) {
                char *end; long v = strtol(val, &end, 10);
                if (end != val && v >= 1 && v <= 7200) cfg->tcp_keepalive_idle = (int)v;
            }
            else if (MATCH("iscsid.tcp_keepalive_interval")) {
                char *end; long v = strtol(val, &end, 10);
                if (end != val && v >= 1 && v <= 300) cfg->tcp_keepalive_interval = (int)v;
            }
            else if (MATCH("iscsid.tcp_keepalive_count")) {
                char *end; long v = strtol(val, &end, 10);
                if (end != val && v >= 1 && v <= 20) cfg->tcp_keepalive_count = (int)v;
            }
        }

#undef MATCH
#undef GSTR
#undef TSTR
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
    sess->params.tcp_keepalive_idle     = cfg->tcp_keepalive_idle;
    sess->params.tcp_keepalive_interval = cfg->tcp_keepalive_interval;
    sess->params.tcp_keepalive_count    = cfg->tcp_keepalive_count;
}

/* -----------------------------------------------------------------------
 * Per-target apply
 * ----------------------------------------------------------------------- */

void config_apply_session_target(const iscsid_config_t *cfg,
                                  const char *target,
                                  iscsi_session_t *sess)
{
    config_apply_session(cfg, sess);   /* global defaults first */

    for (int i = 0; i < cfg->num_target_configs; i++) {
        const iscsi_target_config_t *tc = &cfg->target_configs[i];
        if (strcmp(tc->target, target) != 0) continue;

        if (tc->auth_method[0]) {
            if (strcmp(tc->auth_method, "None") == 0) {
                /* Explicitly disable CHAP for this target */
                sess->chap_secret[0]        = '\0';
                sess->chap_username[0]      = '\0';
                sess->chap_target_secret[0] = '\0';
            } else if (strcmp(tc->auth_method, "CHAP") == 0 && tc->chap_secret[0]) {
                /* Use per-target credentials */
                snprintf(sess->chap_username, sizeof(sess->chap_username),
                         "%s", tc->chap_username);
                snprintf(sess->chap_secret, sizeof(sess->chap_secret),
                         "%s", tc->chap_secret);
                snprintf(sess->chap_target_secret, sizeof(sess->chap_target_secret),
                         "%s", tc->chap_target_secret);
            }
        } else if (tc->chap_secret[0]) {
            /* Credentials provided with no explicit authmethod: apply them */
            snprintf(sess->chap_username, sizeof(sess->chap_username),
                     "%s", tc->chap_username);
            snprintf(sess->chap_secret, sizeof(sess->chap_secret),
                     "%s", tc->chap_secret);
            snprintf(sess->chap_target_secret, sizeof(sess->chap_target_secret),
                     "%s", tc->chap_target_secret);
        }
        break;
    }
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
    if (cfg->num_target_configs > 0) {
        printf("  Per-target sections: %d\n", cfg->num_target_configs);
        for (int i = 0; i < cfg->num_target_configs; i++) {
            const iscsi_target_config_t *tc = &cfg->target_configs[i];
            printf("    [%s] authmethod=%s username=%s\n",
                   tc->target,
                   tc->auth_method[0] ? tc->auth_method : "(inherit)",
                   tc->chap_username[0] ? tc->chap_username : "(inherit)");
        }
    }
}
