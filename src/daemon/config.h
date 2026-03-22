/*
 * config.h - iscsid configuration file parser
 *
 * Configuration file format (similar to open-iscsi iscsid.conf):
 *
 *   # comment
 *   node.startup = automatic
 *   node.session.auth.authmethod = CHAP
 *   node.session.auth.username = iqn.2024-01.io.example:initiator
 *   node.session.auth.password = secret
 *   node.session.auth.username_in = iqn.2024-01.io.example:target
 *   node.session.auth.password_in = target-secret
 *   discovery.sendtargets.auth.authmethod = None
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "session.h"
#include <stdint.h>

#define ISCSID_DEFAULT_CONFIG_PATH  "/etc/iscsid.conf"
#define ISCSID_INITIATOR_NAME_PATH  "/etc/iscsi/initiatorname.iscsi"
#define ISCSID_MAX_TARGET_CONFIGS   32

/*
 * Per-target configuration override.
 * Fields left empty ("") mean "inherit from the global config".
 * Stanza in iscsid.conf:
 *
 *   [iqn.2024-01.io.storage:disk0]
 *   node.session.auth.authmethod = CHAP
 *   node.session.auth.username   = user0
 *   node.session.auth.password   = pass0
 */
typedef struct {
    char  target[ISCSI_MAX_NAME_LEN];
    char  auth_method[32];
    char  chap_username[128];
    char  chap_secret[CHAP_MAX_SECRET_LEN];
    char  chap_target_secret[CHAP_MAX_SECRET_LEN];
} iscsi_target_config_t;

/* Global daemon configuration */
typedef struct {
    char    initiator_name[ISCSI_MAX_NAME_LEN];
    char    initiator_alias[ISCSI_MAX_NAME_LEN];

    /* Default auth settings */
    char    auth_method[32];         /* "None" or "CHAP" */
    char    chap_username[128];
    char    chap_secret[CHAP_MAX_SECRET_LEN];
    char    chap_target_username[128];
    char    chap_target_secret[CHAP_MAX_SECRET_LEN];

    /* Session defaults */
    uint32_t    max_burst_length;
    uint32_t    first_burst_length;
    uint32_t    max_recv_dsl;
    int         initial_r2t;
    int         immediate_data;
    int         error_recovery_level;
    uint32_t    max_connections;

    /* Daemon settings */
    char    pid_file[256];
    char    socket_path[256];
    char    persist_path[256];   /* session persistence file */
    int     log_debug;

    /* Keepalive tuning */
    int     keepalive_timer_sec;    /* EVFILT_TIMER interval (default 30) */
    int     keepalive_idle_sec;     /* NOP-Out when silent this long (default 25) */
    int     tcp_keepalive_idle;     /* TCP_KEEPALIVE idle time (default 60) */
    int     tcp_keepalive_interval; /* TCP_KEEPINTVL (default 10) */
    int     tcp_keepalive_count;    /* TCP_KEEPCNT (default 3) */

    /* Per-target overrides (parsed from [iqn...] sections) */
    iscsi_target_config_t  target_configs[ISCSID_MAX_TARGET_CONFIGS];
    int                    num_target_configs;
} iscsid_config_t;

/*
 * Load configuration from path (NULL → default path).
 * Returns 0 on success, -1 on error.
 */
int config_load(iscsid_config_t *cfg, const char *path);

/*
 * Fill in defaults for any unset fields.
 */
void config_defaults(iscsid_config_t *cfg);

/*
 * Read the IQN from /etc/iscsi/initiatorname.iscsi (or generate one).
 * Writes the result into cfg->initiator_name.
 */
void config_load_initiator_name(iscsid_config_t *cfg);

/*
 * Apply config settings to a session (global defaults only).
 */
void config_apply_session(const iscsid_config_t *cfg, iscsi_session_t *sess);

/*
 * Apply global defaults then overlay any per-target overrides for `target`.
 * This is the preferred call site for all login paths.
 */
void config_apply_session_target(const iscsid_config_t *cfg,
                                  const char *target,
                                  iscsi_session_t *sess);

/*
 * Print current configuration to stdout (for debugging).
 */
void config_print(const iscsid_config_t *cfg);
