/*
 * test_isns.c - Unit tests for isns_parse_response()
 *
 * Exercises the TLV parser with hand-crafted byte buffers, covering:
 *   - single target with IPv4-mapped-IPv6 portal address
 *   - non-target nodes filtered out
 *   - max_targets cap respected
 *   - IPv6 portal address
 *   - status != 0 returns 0 targets
 *   - empty / truncated payloads
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/isns.h"
#include "../src/daemon/discovery.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define TEST(name) \
    do { printf("  %-56s", name); fflush(stdout); } while (0)
#define PASS()  printf("PASS\n")
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* -----------------------------------------------------------------------
 * TLV builder helpers (mirrors isns.c internals)
 * ----------------------------------------------------------------------- */

static size_t off_g;
static uint8_t buf_g[4096];

static void buf_reset(void)       { off_g = 0; }

static void append_u32_be(uint32_t v)
{
    buf_g[off_g++] = (v >> 24) & 0xFF;
    buf_g[off_g++] = (v >> 16) & 0xFF;
    buf_g[off_g++] = (v >>  8) & 0xFF;
    buf_g[off_g++] =  v        & 0xFF;
}

/* Append TLV: tag, length, value (padded to 4 bytes) */
static void tlv(uint32_t tag, const uint8_t *value, uint32_t vlen)
{
    append_u32_be(tag);
    append_u32_be(vlen);
    for (uint32_t i = 0; i < vlen; i++)
        buf_g[off_g++] = value[i];
    /* Pad to 4-byte boundary */
    uint32_t pad = (4 - (vlen & 3)) & 3;
    for (uint32_t i = 0; i < pad; i++)
        buf_g[off_g++] = 0;
}

static void tlv_str(uint32_t tag, const char *s)
{
    tlv(tag, (const uint8_t *)s, (uint32_t)strlen(s));
}

static void tlv_u32(uint32_t tag, uint32_t v)
{
    uint8_t b[4] = { (v>>24)&0xFF, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF };
    tlv(tag, b, 4);
}

/* IPv4-mapped-IPv6: ::ffff:a.b.c.d */
static void tlv_ip4mapped(uint32_t tag, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t ip[16] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,a,b,c,d};
    tlv(tag, ip, 16);
}

/* Status TLV (tag 263) */
static void tlv_status(uint32_t code)   { tlv_u32(263, code); }
static void tlv_delimiter(void)         { tlv_u32(0, 0); /* tag=0, len=0 — zero bytes value */ }

/* Actually tag=0 means len=0, so use direct bytes */
static void tlv_delimiter_raw(void)
{
    /* tag=0, len=0 */
    append_u32_be(0);  /* tag */
    append_u32_be(0);  /* len */
}

/* iSNS node type: 1 = target */
#define NODE_TARGET     0x00000001
#define NODE_INITIATOR  0x00000002

/* TLV tags from isns.c */
#define TAG_DELIMITER    0
#define TAG_IP_ADDR     16
#define TAG_PORT        17
#define TAG_NAME        32
#define TAG_NODE_TYPE   33

/* -----------------------------------------------------------------------
 * Test: single target, IPv4-mapped portal
 * ----------------------------------------------------------------------- */

static void test_single_target_ipv4mapped(void)
{
    TEST("parse: single target with IPv4-mapped portal");

    buf_reset();
    tlv_status(0);
    tlv_delimiter_raw();
    tlv_str(TAG_NAME, "iqn.2024-01.io.test:disk0");
    tlv_u32(TAG_NODE_TYPE, NODE_TARGET);
    tlv_ip4mapped(TAG_IP_ADDR, 192, 168, 1, 100);
    /* Portal port: high 16 = 3260, low 16 = 0 (TCP) */
    tlv_u32(TAG_PORT, (3260u << 16) | 0u);

    iscsi_target_info_t targets[4];
    int n = isns_parse_response(buf_g, off_g, targets, 4);

    if (n != 1) { FAIL("expected 1 target"); return; }
    if (strcmp(targets[0].target_name, "iqn.2024-01.io.test:disk0") != 0) {
        FAIL("wrong target name"); return;
    }
    if (strcmp(targets[0].host, "192.168.1.100") != 0) {
        FAIL("wrong host"); return;
    }
    if (targets[0].port != 3260) { FAIL("wrong port"); return; }

    PASS();
}

/* -----------------------------------------------------------------------
 * Test: initiator node filtered out
 * ----------------------------------------------------------------------- */

static void test_initiator_filtered(void)
{
    TEST("parse: initiator node filtered, only target returned");

    buf_reset();
    tlv_status(0);
    tlv_delimiter_raw();

    /* Initiator node first */
    tlv_str(TAG_NAME, "iqn.2024-01.io.test:initiator");
    tlv_u32(TAG_NODE_TYPE, NODE_INITIATOR);

    /* Target node second */
    tlv_str(TAG_NAME, "iqn.2024-01.io.test:target");
    tlv_u32(TAG_NODE_TYPE, NODE_TARGET);
    tlv_ip4mapped(TAG_IP_ADDR, 10, 0, 0, 1);
    tlv_u32(TAG_PORT, (3260u << 16));

    iscsi_target_info_t targets[4];
    int n = isns_parse_response(buf_g, off_g, targets, 4);

    if (n != 1) { FAIL("expected 1 target after filtering initiator"); return; }
    if (strcmp(targets[0].target_name, "iqn.2024-01.io.test:target") != 0) {
        FAIL("wrong target name survived"); return;
    }

    PASS();
}

/* -----------------------------------------------------------------------
 * Test: max_targets cap
 * ----------------------------------------------------------------------- */

static void test_max_targets_cap(void)
{
    TEST("parse: max_targets cap respected");

    buf_reset();
    tlv_status(0);
    tlv_delimiter_raw();

    for (int i = 0; i < 5; i++) {
        char name[64];
        snprintf(name, sizeof(name), "iqn.2024-01.io.test:disk%d", i);
        tlv_str(TAG_NAME, name);
        tlv_u32(TAG_NODE_TYPE, NODE_TARGET);
        tlv_ip4mapped(TAG_IP_ADDR, 10, 0, 0, (uint8_t)(i + 1));
        tlv_u32(TAG_PORT, (3260u << 16));
    }

    iscsi_target_info_t targets[3];
    int n = isns_parse_response(buf_g, off_g, targets, 3);

    if (n != 3) FAIL("expected exactly 3 (cap applied)");
    else PASS();
}

/* -----------------------------------------------------------------------
 * Test: non-zero status → 0 targets
 * ----------------------------------------------------------------------- */

static void test_error_status(void)
{
    TEST("parse: status != 0 returns 0 targets");

    buf_reset();
    tlv_status(0x0003);   /* error code 3 */
    tlv_delimiter_raw();
    tlv_str(TAG_NAME, "iqn.2024-01.io.test:disk0");
    tlv_u32(TAG_NODE_TYPE, NODE_TARGET);

    iscsi_target_info_t targets[4];
    int n = isns_parse_response(buf_g, off_g, targets, 4);

    if (n != 0) FAIL("expected 0 on error status");
    else PASS();
}

/* -----------------------------------------------------------------------
 * Test: empty payload → 0 targets
 * ----------------------------------------------------------------------- */

static void test_empty_payload(void)
{
    TEST("parse: empty payload → 0 targets");

    iscsi_target_info_t targets[4];
    int n = isns_parse_response(NULL, 0, targets, 4);
    if (n != 0) FAIL("expected 0 for empty payload");
    else PASS();
}

/* -----------------------------------------------------------------------
 * Test: two targets with different portals
 * ----------------------------------------------------------------------- */

static void test_two_targets(void)
{
    TEST("parse: two targets with separate portals");

    buf_reset();
    tlv_status(0);
    tlv_delimiter_raw();

    tlv_str(TAG_NAME, "iqn.2024-01.io.test:lun0");
    tlv_u32(TAG_NODE_TYPE, NODE_TARGET);
    tlv_ip4mapped(TAG_IP_ADDR, 172, 16, 0, 1);
    tlv_u32(TAG_PORT, (3260u << 16));

    tlv_str(TAG_NAME, "iqn.2024-01.io.test:lun1");
    tlv_u32(TAG_NODE_TYPE, NODE_TARGET);
    tlv_ip4mapped(TAG_IP_ADDR, 172, 16, 0, 2);
    tlv_u32(TAG_PORT, (3261u << 16));

    iscsi_target_info_t targets[4];
    int n = isns_parse_response(buf_g, off_g, targets, 4);

    if (n != 2) { FAIL("expected 2 targets"); return; }
    if (targets[0].port != 3260) { FAIL("first target port wrong"); return; }
    if (targets[1].port != 3261) { FAIL("second target port wrong"); return; }
    if (strcmp(targets[0].host, "172.16.0.1") != 0) { FAIL("first host wrong"); return; }
    if (strcmp(targets[1].host, "172.16.0.2") != 0) { FAIL("second host wrong"); return; }

    PASS();
}

/* -----------------------------------------------------------------------
 * Test: no portal attributes → target name present, default port
 * ----------------------------------------------------------------------- */

static void test_target_no_portal(void)
{
    TEST("parse: target with no portal attrs → name filled, port=3260");

    buf_reset();
    tlv_status(0);
    tlv_delimiter_raw();

    tlv_str(TAG_NAME, "iqn.2024-01.io.test:noportal");
    tlv_u32(TAG_NODE_TYPE, NODE_TARGET);
    /* No IP or port TLVs */

    iscsi_target_info_t targets[4];
    int n = isns_parse_response(buf_g, off_g, targets, 4);

    if (n != 1) { FAIL("expected 1 target"); return; }
    if (strcmp(targets[0].target_name, "iqn.2024-01.io.test:noportal") != 0) {
        FAIL("wrong name"); return;
    }
    if (targets[0].port != 3260) { FAIL("expected default port 3260"); return; }

    PASS();
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_isns\n");

    test_single_target_ipv4mapped();
    test_initiator_filtered();
    test_max_targets_cap();
    test_error_status();
    test_empty_payload();
    test_two_targets();
    test_target_no_portal();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
