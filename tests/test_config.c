/*
 * test_config.c - Unit tests for config.c (global and per-target config)
 *
 * Tests use temp files in /tmp to avoid needing root access.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/config.h"
#include "../src/daemon/session.h"

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

/* Write a string to a temp file, return path (caller must unlink) */
static char g_tmpfile[256];
static void write_tmpfile(const char *contents)
{
    snprintf(g_tmpfile, sizeof(g_tmpfile), "/tmp/test_config_%d.conf", (int)getpid());
    FILE *fp = fopen(g_tmpfile, "w");
    if (!fp) { perror("fopen"); return; }
    fputs(contents, fp);
    fclose(fp);
}

/* Build a minimal session suitable for config_apply_session* tests */
static iscsi_session_t *make_sess(void)
{
    return session_create(SESS_TYPE_NORMAL,
                          "iqn.2024-01.io.test:init",
                          "iqn.2024-01.io.test:target",
                          "127.0.0.1:3260");
}

/* -----------------------------------------------------------------------
 * Test: config_defaults fills sane values
 * ----------------------------------------------------------------------- */

static void test_defaults(void)
{
    TEST("config_defaults: fills sane default values");

    iscsid_config_t cfg;
    config_defaults(&cfg);

    int ok = 1;
    if (cfg.max_burst_length   == 0) ok = 0;
    if (cfg.first_burst_length == 0) ok = 0;
    if (cfg.max_recv_dsl       == 0) ok = 0;
    if (cfg.pid_file[0]        == '\0') ok = 0;
    if (cfg.socket_path[0]     == '\0') ok = 0;
    if (cfg.num_target_configs != 0)   ok = 0;

    if (ok) PASS(); else FAIL("unexpected zero value in defaults");
}

/* -----------------------------------------------------------------------
 * Test: config_load parses global CHAP keys
 * ----------------------------------------------------------------------- */

static void test_load_global_chap(void)
{
    TEST("config_load: global CHAP keys parsed correctly");

    write_tmpfile(
        "node.session.auth.authmethod = CHAP\n"
        "node.session.auth.username   = myuser\n"
        "node.session.auth.password   = mysecret123\n"
        "node.session.auth.password_in = targetsecret\n"
    );

    iscsid_config_t cfg;
    config_defaults(&cfg);
    int rc = config_load(&cfg, g_tmpfile);
    unlink(g_tmpfile);

    if (rc != 0) { FAIL("config_load returned error"); return; }

    int ok = 1;
    if (strcmp(cfg.auth_method,      "CHAP")          != 0) ok = 0;
    if (strcmp(cfg.chap_username,    "myuser")         != 0) ok = 0;
    if (strcmp(cfg.chap_secret,      "mysecret123")    != 0) ok = 0;
    if (strcmp(cfg.chap_target_secret,"targetsecret")  != 0) ok = 0;
    if (cfg.num_target_configs != 0) ok = 0;

    if (ok) PASS(); else FAIL("key mismatch");
}

/* -----------------------------------------------------------------------
 * Test: config_load parses per-target sections
 * ----------------------------------------------------------------------- */

static void test_load_per_target(void)
{
    TEST("config_load: per-target [iqn...] sections parsed");

    write_tmpfile(
        "node.session.auth.authmethod = CHAP\n"
        "node.session.auth.username   = global-user\n"
        "node.session.auth.password   = global-pass\n"
        "\n"
        "[iqn.2024-01.io.storage:disk0]\n"
        "node.session.auth.authmethod = CHAP\n"
        "node.session.auth.username   = disk0-user\n"
        "node.session.auth.password   = disk0-pass\n"
        "\n"
        "[iqn.2024-01.io.storage:disk1]\n"
        "node.session.auth.authmethod = None\n"
    );

    iscsid_config_t cfg;
    config_defaults(&cfg);
    int rc = config_load(&cfg, g_tmpfile);
    unlink(g_tmpfile);

    if (rc != 0) { FAIL("config_load returned error"); return; }

    int ok = 1;
    if (cfg.num_target_configs != 2) { ok = 0; goto done; }

    /* disk0 entry */
    const iscsi_target_config_t *t0 = &cfg.target_configs[0];
    if (strcmp(t0->target,       "iqn.2024-01.io.storage:disk0") != 0) ok = 0;
    if (strcmp(t0->auth_method,  "CHAP")       != 0) ok = 0;
    if (strcmp(t0->chap_username,"disk0-user") != 0) ok = 0;
    if (strcmp(t0->chap_secret,  "disk0-pass") != 0) ok = 0;

    /* disk1 entry */
    const iscsi_target_config_t *t1 = &cfg.target_configs[1];
    if (strcmp(t1->target,      "iqn.2024-01.io.storage:disk1") != 0) ok = 0;
    if (strcmp(t1->auth_method, "None") != 0) ok = 0;

done:
    if (ok) PASS(); else FAIL("target config mismatch");
}

/* -----------------------------------------------------------------------
 * Test: config_apply_session_target uses global when no target entry
 * ----------------------------------------------------------------------- */

static void test_apply_no_target_override(void)
{
    TEST("config_apply_session_target: unknown target → global credentials");

    write_tmpfile(
        "node.session.auth.username = global-user\n"
        "node.session.auth.password = global-pass\n"
    );

    iscsid_config_t cfg;
    config_defaults(&cfg);
    config_load(&cfg, g_tmpfile);
    unlink(g_tmpfile);

    iscsi_session_t *sess = make_sess();
    if (!sess) { FAIL("session_create"); return; }

    config_apply_session_target(&cfg, "iqn.2024-01.io.storage:unknown", sess);

    int ok = (strcmp(sess->chap_secret,   "global-pass") == 0 &&
              strcmp(sess->chap_username, "global-user") == 0);
    session_destroy(sess);
    if (ok) PASS(); else FAIL("credential mismatch");
}

/* -----------------------------------------------------------------------
 * Test: config_apply_session_target overrides credentials per-target
 * ----------------------------------------------------------------------- */

static void test_apply_target_chap_override(void)
{
    TEST("config_apply_session_target: per-target CHAP overrides global");

    write_tmpfile(
        "node.session.auth.username = global-user\n"
        "node.session.auth.password = global-pass\n"
        "\n"
        "[iqn.2024-01.io.storage:disk0]\n"
        "node.session.auth.authmethod = CHAP\n"
        "node.session.auth.username   = disk0-user\n"
        "node.session.auth.password   = disk0-pass\n"
    );

    iscsid_config_t cfg;
    config_defaults(&cfg);
    config_load(&cfg, g_tmpfile);
    unlink(g_tmpfile);

    iscsi_session_t *sess = make_sess();
    if (!sess) { FAIL("session_create"); return; }

    config_apply_session_target(&cfg, "iqn.2024-01.io.storage:disk0", sess);

    int ok = (strcmp(sess->chap_secret,   "disk0-pass") == 0 &&
              strcmp(sess->chap_username, "disk0-user") == 0);
    session_destroy(sess);
    if (ok) PASS(); else FAIL("per-target credentials not applied");
}

/* -----------------------------------------------------------------------
 * Test: per-target authmethod=None clears global CHAP
 * ----------------------------------------------------------------------- */

static void test_apply_target_none_clears_chap(void)
{
    TEST("config_apply_session_target: authmethod=None clears global CHAP");

    write_tmpfile(
        "node.session.auth.username = global-user\n"
        "node.session.auth.password = global-pass\n"
        "\n"
        "[iqn.2024-01.io.storage:disk1]\n"
        "node.session.auth.authmethod = None\n"
    );

    iscsid_config_t cfg;
    config_defaults(&cfg);
    config_load(&cfg, g_tmpfile);
    unlink(g_tmpfile);

    iscsi_session_t *sess = make_sess();
    if (!sess) { FAIL("session_create"); return; }

    config_apply_session_target(&cfg, "iqn.2024-01.io.storage:disk1", sess);

    int ok = (sess->chap_secret[0] == '\0');
    session_destroy(sess);
    if (ok) PASS(); else FAIL("CHAP not cleared for authmethod=None target");
}

/* -----------------------------------------------------------------------
 * Test: non-matching target entry leaves global settings intact
 * ----------------------------------------------------------------------- */

static void test_apply_other_target_no_bleed(void)
{
    TEST("config_apply_session_target: different target entry doesn't bleed");

    write_tmpfile(
        "node.session.auth.username = global-user\n"
        "node.session.auth.password = global-pass\n"
        "\n"
        "[iqn.2024-01.io.storage:other]\n"
        "node.session.auth.username = other-user\n"
        "node.session.auth.password = other-pass\n"
    );

    iscsid_config_t cfg;
    config_defaults(&cfg);
    config_load(&cfg, g_tmpfile);
    unlink(g_tmpfile);

    iscsi_session_t *sess = make_sess();
    if (!sess) { FAIL("session_create"); return; }

    config_apply_session_target(&cfg, "iqn.2024-01.io.storage:notother", sess);

    int ok = (strcmp(sess->chap_secret,   "global-pass") == 0 &&
              strcmp(sess->chap_username, "global-user") == 0);
    session_destroy(sess);
    if (ok) PASS(); else FAIL("wrong target entry applied");
}

/* -----------------------------------------------------------------------
 * Test: config_load with no file is not an error
 * ----------------------------------------------------------------------- */

static void test_load_missing_file(void)
{
    TEST("config_load: missing file → 0 (not an error)");

    iscsid_config_t cfg;
    config_defaults(&cfg);
    int rc = config_load(&cfg, "/tmp/nonexistent_iscsid_test_XXXXX.conf");
    if (rc == 0) PASS(); else FAIL("expected 0 for missing file");
}

/* -----------------------------------------------------------------------
 * Test: numeric config keys (keepalive, error recovery level)
 * ----------------------------------------------------------------------- */

static void test_load_numeric_keys(void)
{
    TEST("config_load: numeric keys parsed with bounds checking");

    write_tmpfile(
        "iscsid.keepalive_timer    = 45\n"
        "iscsid.keepalive_idle     = 20\n"
        "iscsid.tcp_keepalive_idle = 120\n"
        "iscsid.tcp_keepalive_interval = 15\n"
        "iscsid.tcp_keepalive_count    = 5\n"
        "node.session.iscsi.ErrorRecoveryLevel = 1\n"
        "iscsid.debug = 1\n"
    );

    iscsid_config_t cfg;
    config_defaults(&cfg);
    int rc = config_load(&cfg, g_tmpfile);
    unlink(g_tmpfile);

    if (rc != 0) { FAIL("config_load returned error"); return; }

    int ok = 1;
    if (cfg.keepalive_timer_sec    != 45)  ok = 0;
    if (cfg.keepalive_idle_sec     != 20)  ok = 0;
    if (cfg.tcp_keepalive_idle     != 120) ok = 0;
    if (cfg.tcp_keepalive_interval != 15)  ok = 0;
    if (cfg.tcp_keepalive_count    != 5)   ok = 0;
    if (cfg.error_recovery_level   != 1)   ok = 0;
    if (cfg.log_debug              != 1)   ok = 0;

    if (ok) PASS(); else FAIL("numeric key value mismatch");
}

static void test_load_numeric_invalid(void)
{
    TEST("config_load: out-of-range numerics → defaults preserved");

    write_tmpfile(
        "iscsid.keepalive_timer    = 0\n"      /* below minimum 1 */
        "iscsid.keepalive_idle     = 9999\n"   /* above maximum 3600 */
        "iscsid.tcp_keepalive_count = 99\n"    /* above maximum 20 */
        "node.session.iscsi.ErrorRecoveryLevel = 5\n"  /* above maximum 2 */
        "iscsid.debug = garbage\n"
    );

    iscsid_config_t cfg;
    config_defaults(&cfg);
    int rc = config_load(&cfg, g_tmpfile);
    unlink(g_tmpfile);

    if (rc != 0) { FAIL("config_load returned error"); return; }

    int ok = 1;
    /* All out-of-range values must leave defaults intact */
    if (cfg.keepalive_timer_sec  != 30) ok = 0;
    if (cfg.keepalive_idle_sec   != 25) ok = 0;
    if (cfg.tcp_keepalive_count  !=  3) ok = 0;
    if (cfg.error_recovery_level !=  0) ok = 0;
    if (cfg.log_debug            !=  0) ok = 0;

    if (ok) PASS(); else FAIL("out-of-range value overwrote default");
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_config\n");

    test_defaults();
    test_load_global_chap();
    test_load_per_target();
    test_apply_no_target_override();
    test_apply_target_chap_override();
    test_apply_target_none_clears_chap();
    test_apply_other_target_no_bleed();
    test_load_missing_file();
    test_load_numeric_keys();
    test_load_numeric_invalid();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
