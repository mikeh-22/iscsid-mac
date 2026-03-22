/*
 * persist.c - Session state persistence across daemon restarts
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "persist.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Simple JSON helpers (no external library)
 * ----------------------------------------------------------------------- */

/*
 * Copy a JSON string value for key from buf into dst.
 * Returns 0 on success, -1 if key not found.
 */
static int json_extract_str(const char *buf, const char *key,
                              char *dst, size_t dst_size)
{
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(buf, pat);
    if (!p) return -1;
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < dst_size)
        dst[i++] = *p++;
    dst[i] = '\0';
    return 0;
}

/*
 * Copy an integer JSON value for key into *out.
 */
static int json_extract_int(const char *buf, const char *key, int *out)
{
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(buf, pat);
    if (!p) return -1;
    p += strlen(pat);
    *out = atoi(p);
    return 0;
}

/*
 * Escape a string for safe embedding in a JSON string value.
 */
static void json_escape(char *dst, size_t dst_size, const char *src)
{
    size_t out = 0;
    for (const char *p = src; *p && out + 7 < dst_size; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            dst[out++] = '\\';
            dst[out++] = (char)c;
        } else if (c < 0x20) {
            out += (size_t)snprintf(dst + out, dst_size - out, "\\u%04x", c);
        } else {
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
}

/* -----------------------------------------------------------------------
 * Load
 * ----------------------------------------------------------------------- */

int persist_load(const char *path,
                  iscsi_persist_entry_t *entries, int max_entries)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        /* File doesn't exist yet: not an error */
        if (errno == ENOENT) return 0;
        syslog(LOG_WARNING, "persist: cannot open %s: %m", path);
        return -1;
    }

    /* Read entire file */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024 * 1024) {
        fclose(f);
        return 0;
    }

    char *buf = malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return -1; }

    size_t nread = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    buf[nread] = '\0';

    int count = 0;
    const char *p = buf;

    /* Walk through each "{...}" object in "sessions":[...] */
    const char *arr = strstr(p, "\"sessions\":[");
    if (!arr) { free(buf); return 0; }
    arr += strlen("\"sessions\":[");

    while (count < max_entries) {
        const char *obj_start = strchr(arr, '{');
        if (!obj_start) break;
        const char *obj_end = strchr(obj_start, '}');
        if (!obj_end) break;

        /* Null-terminate the object temporarily */
        size_t obj_len = (size_t)(obj_end - obj_start + 1);
        char *obj = malloc(obj_len + 1);
        if (!obj) break;
        memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        iscsi_persist_entry_t *e = &entries[count];
        memset(e, 0, sizeof(*e));
        e->port = 3260;

        if (json_extract_str(obj, "target", e->target, sizeof(e->target)) == 0 &&
            json_extract_str(obj, "host",   e->host,   sizeof(e->host))   == 0) {
            int port = 3260;
            json_extract_int(obj, "port", &port);
            e->port = (uint16_t)port;
            count++;
        }

        free(obj);
        arr = obj_end + 1;
    }

    free(buf);
    return count;
}

/* -----------------------------------------------------------------------
 * Save
 * ----------------------------------------------------------------------- */

int persist_save(const char *path,
                  const iscsi_persist_entry_t *entries, int count)
{
    /* Write to a temp file, then rename for atomicity */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());

    FILE *f = fopen(tmp, "w");
    if (!f) {
        syslog(LOG_WARNING, "persist: cannot write %s: %m", tmp);
        return -1;
    }

    fprintf(f, "{\"sessions\":[");
    for (int i = 0; i < count; i++) {
        char esc_target[ISCSI_MAX_NAME_LEN * 6 + 2];
        char esc_host[256 * 6 + 2];
        json_escape(esc_target, sizeof(esc_target), entries[i].target);
        json_escape(esc_host,   sizeof(esc_host),   entries[i].host);
        fprintf(f, "%s{\"target\":\"%s\",\"host\":\"%s\",\"port\":%u}",
                i ? "," : "", esc_target, esc_host, entries[i].port);
    }
    fprintf(f, "]}\n");
    fclose(f);

    if (rename(tmp, path) != 0) {
        syslog(LOG_WARNING, "persist: rename %s → %s failed: %m", tmp, path);
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Add / remove helpers
 * ----------------------------------------------------------------------- */

int persist_add(const char *path,
                 const char *target, const char *host, uint16_t port)
{
    iscsi_persist_entry_t entries[ISCSI_PERSIST_MAX_SESSIONS];
    int count = persist_load(path, entries, ISCSI_PERSIST_MAX_SESSIONS);
    if (count < 0) count = 0;

    /* Update existing entry if present */
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].target, target) == 0) {
            snprintf(entries[i].host, sizeof(entries[i].host), "%s", host);
            entries[i].port = port;
            return persist_save(path, entries, count);
        }
    }

    /* Append new entry */
    if (count >= ISCSI_PERSIST_MAX_SESSIONS) {
        syslog(LOG_WARNING, "persist: max sessions (%d) reached",
               ISCSI_PERSIST_MAX_SESSIONS);
        return -1;
    }
    snprintf(entries[count].target, sizeof(entries[count].target), "%s", target);
    snprintf(entries[count].host,   sizeof(entries[count].host),   "%s", host);
    entries[count].port = port;
    return persist_save(path, entries, count + 1);
}

int persist_remove(const char *path, const char *target)
{
    iscsi_persist_entry_t entries[ISCSI_PERSIST_MAX_SESSIONS];
    int count = persist_load(path, entries, ISCSI_PERSIST_MAX_SESSIONS);
    if (count <= 0) return 0;   /* nothing to remove */

    /* Remove matching entry by shifting remainder down */
    int found = 0;
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].target, target) == 0) {
            memmove(&entries[i], &entries[i + 1],
                    (size_t)(count - i - 1) * sizeof(entries[0]));
            count--;
            found = 1;
            break;
        }
    }

    if (!found) return 0;   /* target wasn't persisted */
    return persist_save(path, entries, count);
}
