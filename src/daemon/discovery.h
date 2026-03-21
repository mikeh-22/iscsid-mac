/*
 * discovery.h - iSCSI target discovery (SendTargets)
 *
 * Implements RFC 7143 §6.2 — SendTargets discovery session.
 * Also provides iSNS (Internet Storage Name Service) hooks (RFC 4171)
 * for future extension.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

/* Maximum number of targets returned from a single discovery */
#define ISCSI_MAX_DISCOVERY_TARGETS 64

/* A discovered iSCSI target */
typedef struct {
    char    target_name[224];   /* IQN */
    char    address[256];       /* "host:port,portal-group-tag" */
    char    host[128];
    uint16_t port;
    int     portal_group;
} iscsi_target_info_t;

/*
 * Run a SendTargets discovery session against host:port.
 * Fills targets[] with up to max_targets discovered entries.
 * Returns the number of targets found, or < 0 on error.
 *
 * initiator_name: IQN of this initiator
 * chap_user / chap_secret: optional CHAP credentials (NULL to skip auth)
 */
int iscsi_discover(const char *host, uint16_t port,
                   const char *initiator_name,
                   const char *chap_user,
                   const char *chap_secret,
                   iscsi_target_info_t *targets,
                   int max_targets);

/*
 * Print a list of discovered targets to stdout.
 */
void iscsi_print_targets(const iscsi_target_info_t *targets, int count);
