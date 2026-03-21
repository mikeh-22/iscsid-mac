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
    int     log_debug;
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
 * Apply config settings to a session.
 */
void config_apply_session(const iscsid_config_t *cfg, iscsi_session_t *sess);

/*
 * Print current configuration to stdout (for debugging).
 */
void config_print(const iscsid_config_t *cfg);
