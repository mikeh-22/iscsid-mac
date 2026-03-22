/*
 * isns.h - iSNS (Internet Storage Name Service) discovery client
 *
 * Implements RFC 4171 DevAttrQry to enumerate iSCSI targets from an iSNS
 * server.  The iSNS server maintains a registry of storage nodes and their
 * portals; the initiator queries it as an alternative to per-target
 * SendTargets discovery.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "discovery.h"   /* reuse iscsi_target_info_t */
#include <stddef.h>
#include <stdint.h>

/* Default iSNS TCP port (RFC 4171 §4.1) */
#define ISNS_PORT   3205

/*
 * Discover iSCSI targets via an iSNS server.
 *
 * Connects to host:port via TCP, sends a DevAttrQry requesting all iSCSI
 * target nodes, and parses the TLV response into targets[].
 *
 * Returns number of discovered targets (>= 0) or -1 on error.
 */
int isns_discover(const char *host, uint16_t port,
                  const char *initiator_name,
                  iscsi_target_info_t *targets, int max_targets);

/*
 * Parse a raw iSNS DevAttrQryRsp payload into targets[].
 * Exposed for unit testing without a live server.
 *
 * payload / payload_len: the iSNS PDU payload (after the 12-byte header)
 * Returns number of targets extracted.
 */
int isns_parse_response(const uint8_t *payload, size_t payload_len,
                         iscsi_target_info_t *targets, int max_targets);
