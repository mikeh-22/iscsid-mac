/*
 * test_pdu.c - Unit tests for PDU encode/decode and key-value helpers
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/pdu.h"
#include "../src/shared/iscsi_protocol.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST(name) \
    do { printf("  %-50s", name); fflush(stdout); } while (0)
#define PASS()  printf("PASS\n")
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* -----------------------------------------------------------------------
 * PDU header size check
 * ----------------------------------------------------------------------- */

static void test_hdr_sizes(void)
{
    TEST("PDU header struct sizes == 48");
    if (sizeof(iscsi_hdr_t) != 48)        FAIL("iscsi_hdr_t");
    else if (sizeof(iscsi_login_req_t) != 48) FAIL("login_req");
    else if (sizeof(iscsi_login_rsp_t) != 48) FAIL("login_rsp");
    else if (sizeof(iscsi_scsi_cmd_t)  != 48) FAIL("scsi_cmd");
    else if (sizeof(iscsi_scsi_rsp_t)  != 48) FAIL("scsi_rsp");
    else PASS();
}

/* -----------------------------------------------------------------------
 * dlength helpers
 * ----------------------------------------------------------------------- */

static void test_dlength(void)
{
    TEST("iscsi_dlength set/get roundtrip");
    uint8_t dlength[3];
    uint32_t vals[] = { 0, 1, 512, 65536, 0xABCDEF, 16777215 };
    int ok = 1;
    for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
        iscsi_dlength_set(dlength, vals[i]);
        uint32_t got = iscsi_dlength_get(dlength);
        if (got != vals[i]) { ok = 0; break; }
    }
    if (ok) PASS(); else FAIL("dlength mismatch");
}

/* -----------------------------------------------------------------------
 * key=value helpers
 * ----------------------------------------------------------------------- */

static void test_kv_append_get(void)
{
    TEST("pdu_kv_append / pdu_kv_get");
    char buf[512];
    int used = 0;
    used = pdu_kv_append(buf, sizeof(buf), used, "InitiatorName",
                         "iqn.2024-01.io.test:init");
    used = pdu_kv_append(buf, sizeof(buf), used, "SessionType", "Normal");
    used = pdu_kv_append(buf, sizeof(buf), used, "MaxBurstLength", "262144");

    assert(used > 0);

    const char *v;
    v = pdu_kv_get(buf, (uint32_t)used, "SessionType");
    if (!v || strcmp(v, "Normal") != 0) {
        FAIL("SessionType not found or wrong");
        return;
    }
    v = pdu_kv_get(buf, (uint32_t)used, "InitiatorName");
    if (!v || strcmp(v, "iqn.2024-01.io.test:init") != 0) {
        FAIL("InitiatorName wrong");
        return;
    }
    v = pdu_kv_get(buf, (uint32_t)used, "NotPresent");
    if (v) {
        FAIL("NotPresent should be NULL");
        return;
    }
    uint32_t mbl;
    if (pdu_kv_get_int(buf, (uint32_t)used, "MaxBurstLength", &mbl) != 0 ||
        mbl != 262144) {
        FAIL("MaxBurstLength wrong");
        return;
    }
    PASS();
}

static void test_kv_overflow(void)
{
    TEST("pdu_kv_append overflow detection");
    char buf[32];
    int used = 0;
    used = pdu_kv_append(buf, sizeof(buf), used, "Key", "Value");
    assert(used > 0);
    int used2 = pdu_kv_append(buf, sizeof(buf), used,
                               "VeryLongKeyThatWillNotFit", "AlsoLong");
    if (used2 == -1) PASS();
    else             FAIL("expected -1 on overflow");
}

/* -----------------------------------------------------------------------
 * PDU send/recv over a socketpair
 * ----------------------------------------------------------------------- */

static void test_pdu_sendrecv(void)
{
    TEST("pdu_send / pdu_recv over socketpair");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        FAIL("socketpair");
        return;
    }

    /* Build a simple NOP-Out PDU with data */
    iscsi_pdu_t tx;
    pdu_init(&tx, ISCSI_OP_NOOP_OUT, ISCSI_FLAG_FINAL);
    const char *payload = "Hello, iSCSI!";
    pdu_set_data_copy(&tx, payload, (uint32_t)strlen(payload));

    if (pdu_send(sv[0], &tx, 0, 0) != 0) {
        FAIL("pdu_send failed");
        close(sv[0]); close(sv[1]);
        pdu_free_data(&tx);
        return;
    }

    iscsi_pdu_t rx;
    int rc = pdu_recv(sv[1], &rx, 0, 0);
    close(sv[0]); close(sv[1]);

    if (rc != 0) {
        FAIL("pdu_recv failed");
        pdu_free_data(&tx);
        return;
    }

    /* Verify opcode, flags, data */
    if ((rx.hdr.opcode & 0x3f) != ISCSI_OP_NOOP_OUT) {
        FAIL("opcode mismatch");
    } else if (rx.data_len != strlen(payload)) {
        FAIL("data_len mismatch");
    } else if (memcmp(rx.data, payload, strlen(payload)) != 0) {
        FAIL("data content mismatch");
    } else {
        PASS();
    }

    pdu_free_data(&tx);
    pdu_free_data(&rx);
}

/* -----------------------------------------------------------------------
 * pad4
 * ----------------------------------------------------------------------- */

static void test_pad4(void)
{
    TEST("iscsi_pad4");
    assert(iscsi_pad4(0) == 0);
    assert(iscsi_pad4(1) == 4);
    assert(iscsi_pad4(4) == 4);
    assert(iscsi_pad4(5) == 8);
    assert(iscsi_pad4(13) == 16);
    assert(iscsi_pad4(512) == 512);
    PASS();
}

/* -----------------------------------------------------------------------
 * Login flags helpers
 * ----------------------------------------------------------------------- */

static void test_login_flags(void)
{
    TEST("iscsi_login_flags encode/decode");
    uint8_t f = iscsi_login_flags(1, 0,
                                    ISCSI_LOGIN_OPERATIONAL_NEG,
                                    ISCSI_FULL_FEATURE_PHASE);
    int ok = 1;
    if (!(f & ISCSI_LOGIN_TRANSIT))  ok = 0;
    if (  f & ISCSI_LOGIN_CONTINUE)  ok = 0;
    if (iscsi_login_csg(f) != ISCSI_LOGIN_OPERATIONAL_NEG) ok = 0;
    if (iscsi_login_nsg(f) != ISCSI_FULL_FEATURE_PHASE)    ok = 0;
    if (ok) PASS(); else FAIL("flag mismatch");
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("=== PDU unit tests ===\n");
    test_hdr_sizes();
    test_dlength();
    test_kv_append_get();
    test_kv_overflow();
    test_pdu_sendrecv();
    test_pad4();
    test_login_flags();

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
