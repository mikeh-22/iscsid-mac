/*
 * persist.h - Session state persistence across daemon restarts
 *
 * On login, the target info is written to a JSON file.  On startup, the
 * daemon reads the file and re-establishes each session.  On logout, the
 * entry is removed.
 *
 * File format (UTF-8 JSON):
 *   {"sessions":[{"target":"iqn...","host":"192.168.1.1","port":3260}, ...]}
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "../shared/iscsi_protocol.h"
#include <stdint.h>

#define ISCSI_PERSIST_MAX_SESSIONS  64
#define ISCSI_PERSIST_DEFAULT_PATH  "/var/run/iscsid-sessions.json"

typedef struct {
    char     target[ISCSI_MAX_NAME_LEN];
    char     host[256];
    uint16_t port;
} iscsi_persist_entry_t;

/*
 * Load persisted sessions from path.
 * Returns the number of entries read (>= 0), or -1 on error.
 */
int persist_load(const char *path,
                  iscsi_persist_entry_t *entries, int max_entries);

/*
 * Write the current entries array to path (atomic: write to temp then rename).
 * Returns 0 on success, -1 on error.
 */
int persist_save(const char *path,
                  const iscsi_persist_entry_t *entries, int count);

/*
 * Add or update a session entry in the persistence file.
 * Idempotent: if a session with the same target already exists, it is updated.
 * Returns 0 on success, -1 on error.
 */
int persist_add(const char *path,
                 const char *target, const char *host, uint16_t port);

/*
 * Remove a session entry from the persistence file.
 * Returns 0 on success (including "not found"), -1 on I/O error.
 */
int persist_remove(const char *path, const char *target);
