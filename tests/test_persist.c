/*
 * test_persist.c - Unit tests for persist.c (session persistence)
 *
 * Tests use a temp file in /tmp to avoid needing root access.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/persist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST(name) \
    do { printf("  %-56s", name); fflush(stdout); } while (0)
#define PASS()  printf("PASS\n")
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* Use a unique temp path per test run */
static char g_path[256];

static void setup_path(void)
{
    snprintf(g_path, sizeof(g_path),
             "/tmp/test_persist_%d.json", (int)getpid());
    unlink(g_path);   /* ensure clean state */
}

/* -----------------------------------------------------------------------
 * Test: load from nonexistent file → 0 entries (not an error)
 * ----------------------------------------------------------------------- */

static void test_load_nonexistent(void)
{
    TEST("persist_load: nonexistent file → 0 entries");
    setup_path();

    iscsi_persist_entry_t entries[8];
    int n = persist_load(g_path, entries, 8);
    if (n != 0) FAIL("expected 0 for nonexistent file");
    else PASS();
}

/* -----------------------------------------------------------------------
 * Test: save then load roundtrip
 * ----------------------------------------------------------------------- */

static void test_save_load_roundtrip(void)
{
    TEST("persist_save / persist_load: roundtrip 3 sessions");
    setup_path();

    iscsi_persist_entry_t in[3] = {
        { "iqn.2024-01.io.test:disk0", "192.168.1.10", 3260 },
        { "iqn.2024-01.io.test:disk1", "192.168.1.11", 3261 },
        { "iqn.2024-01.io.test:disk2", "10.0.0.1",     3260 },
    };

    if (persist_save(g_path, in, 3) != 0) {
        FAIL("persist_save failed"); goto cleanup; }

    iscsi_persist_entry_t out[8];
    int n = persist_load(g_path, out, 8);

    if (n != 3) { FAIL("expected 3 entries"); goto cleanup; }
    for (int i = 0; i < 3; i++) {
        if (strcmp(out[i].target, in[i].target) != 0) {
            FAIL("target mismatch"); goto cleanup; }
        if (strcmp(out[i].host, in[i].host) != 0) {
            FAIL("host mismatch"); goto cleanup; }
        if (out[i].port != in[i].port) {
            FAIL("port mismatch"); goto cleanup; }
    }
    PASS();
cleanup:
    unlink(g_path);
}

/* -----------------------------------------------------------------------
 * Test: persist_add adds new entry
 * ----------------------------------------------------------------------- */

static void test_add_new(void)
{
    TEST("persist_add: adds new entry to empty file");
    setup_path();

    int rc = persist_add(g_path, "iqn.2024-01.io.test:new", "10.0.0.5", 3260);
    if (rc != 0) { FAIL("persist_add returned error"); goto cleanup; }

    iscsi_persist_entry_t out[8];
    int n = persist_load(g_path, out, 8);
    if (n != 1) { FAIL("expected 1 entry"); goto cleanup; }
    if (strcmp(out[0].target, "iqn.2024-01.io.test:new") != 0) {
        FAIL("target mismatch"); goto cleanup; }
    if (out[0].port != 3260) { FAIL("port mismatch"); goto cleanup; }

    PASS();
cleanup:
    unlink(g_path);
}

/* -----------------------------------------------------------------------
 * Test: persist_add updates existing entry (idempotent)
 * ----------------------------------------------------------------------- */

static void test_add_update(void)
{
    TEST("persist_add: updates existing entry (idempotent)");
    setup_path();

    persist_add(g_path, "iqn.2024-01.io.test:vol0", "192.168.1.1", 3260);
    persist_add(g_path, "iqn.2024-01.io.test:vol1", "192.168.1.2", 3260);
    /* Update vol0 with new host/port */
    persist_add(g_path, "iqn.2024-01.io.test:vol0", "10.0.0.1", 3261);

    iscsi_persist_entry_t out[8];
    int n = persist_load(g_path, out, 8);
    if (n != 2) { FAIL("expected 2 entries after update"); goto cleanup; }

    /* Find vol0 and check updated values */
    int found = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(out[i].target, "iqn.2024-01.io.test:vol0") == 0) {
            found = 1;
            if (strcmp(out[i].host, "10.0.0.1") != 0) {
                FAIL("host not updated"); goto cleanup; }
            if (out[i].port != 3261) {
                FAIL("port not updated"); goto cleanup; }
        }
    }
    if (!found) { FAIL("vol0 entry missing after update"); goto cleanup; }
    PASS();
cleanup:
    unlink(g_path);
}

/* -----------------------------------------------------------------------
 * Test: persist_remove removes entry
 * ----------------------------------------------------------------------- */

static void test_remove(void)
{
    TEST("persist_remove: removes target, others remain");
    setup_path();

    persist_add(g_path, "iqn.2024-01.io.test:a", "10.0.0.1", 3260);
    persist_add(g_path, "iqn.2024-01.io.test:b", "10.0.0.2", 3260);
    persist_add(g_path, "iqn.2024-01.io.test:c", "10.0.0.3", 3260);

    persist_remove(g_path, "iqn.2024-01.io.test:b");

    iscsi_persist_entry_t out[8];
    int n = persist_load(g_path, out, 8);
    if (n != 2) { FAIL("expected 2 entries after remove"); goto cleanup; }
    for (int i = 0; i < n; i++) {
        if (strcmp(out[i].target, "iqn.2024-01.io.test:b") == 0) {
            FAIL("removed entry still present"); goto cleanup; }
    }
    PASS();
cleanup:
    unlink(g_path);
}

/* -----------------------------------------------------------------------
 * Test: persist_remove of nonexistent target is harmless
 * ----------------------------------------------------------------------- */

static void test_remove_nonexistent(void)
{
    TEST("persist_remove: nonexistent target → no error");
    setup_path();

    persist_add(g_path, "iqn.2024-01.io.test:only", "10.0.0.1", 3260);
    int rc = persist_remove(g_path, "iqn.2024-01.io.test:missing");
    if (rc != 0) { FAIL("persist_remove returned error for missing target"); goto cleanup; }

    iscsi_persist_entry_t out[8];
    int n = persist_load(g_path, out, 8);
    if (n != 1) FAIL("entry count changed after no-op remove");
    else PASS();

cleanup:
    unlink(g_path);
}

/* -----------------------------------------------------------------------
 * Test: save empty array → load returns 0
 * ----------------------------------------------------------------------- */

static void test_save_empty(void)
{
    TEST("persist_save: empty array → load returns 0");
    setup_path();

    if (persist_save(g_path, NULL, 0) != 0) {
        FAIL("persist_save failed for empty array"); goto cleanup; }

    iscsi_persist_entry_t out[8];
    int n = persist_load(g_path, out, 8);
    if (n != 0) FAIL("expected 0 entries");
    else PASS();

cleanup:
    unlink(g_path);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_persist\n");

    test_load_nonexistent();
    test_save_load_roundtrip();
    test_add_new();
    test_add_update();
    test_remove();
    test_remove_nonexistent();
    test_save_empty();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
