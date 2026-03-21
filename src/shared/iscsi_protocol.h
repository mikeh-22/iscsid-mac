/*
 * iscsi_protocol.h - iSCSI Protocol Definitions (RFC 7143)
 *
 * Open-source iSCSI initiator daemon for macOS.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>

/* iSCSI default port */
#define ISCSI_PORT              3260

/* PDU header size (bytes) */
#define ISCSI_HDR_LEN           48

/* Maximum lengths */
#define ISCSI_MAX_NAME_LEN      224
#define ISCSI_MAX_TEXT_LEN      65536
#define ISCSI_MAX_DATA_SEG_LEN  (1 << 24)   /* 16 MiB */
#define ISCSI_MAX_RECV_SEG_LEN  (1 << 24)

/* Protocol version */
#define ISCSI_DRAFT20_VERSION   0x00

/* Reserved/special task tag values */
#define ISCSI_RSVD_TASK_TAG     0xFFFFFFFF

/* iSCSI login stages */
#define ISCSI_SECURITY_NEGOTIATION      0
#define ISCSI_LOGIN_OPERATIONAL_NEG     1
#define ISCSI_FULL_FEATURE_PHASE        3

/* -----------------------------------------------------------------------
 * Initiator opcodes (RFC 7143 §10.2.1)
 * ----------------------------------------------------------------------- */
#define ISCSI_OP_NOOP_OUT       0x00    /* NOP-Out */
#define ISCSI_OP_SCSI_CMD       0x01    /* SCSI Command */
#define ISCSI_OP_TASK_MGT_REQ   0x02    /* Task Management Function Request */
#define ISCSI_OP_LOGIN_REQ      0x03    /* Login Request */
#define ISCSI_OP_TEXT_REQ       0x04    /* Text Request */
#define ISCSI_OP_SCSI_DATA_OUT  0x05    /* SCSI Data-Out */
#define ISCSI_OP_LOGOUT_REQ     0x06    /* Logout Request */
#define ISCSI_OP_SNACK_REQ      0x10    /* SNACK Request */

/* Target opcodes (RFC 7143 §10.2.1) */
#define ISCSI_OP_NOOP_IN        0x20    /* NOP-In */
#define ISCSI_OP_SCSI_RSP       0x21    /* SCSI Response */
#define ISCSI_OP_TASK_MGT_RSP   0x22    /* Task Management Function Response */
#define ISCSI_OP_LOGIN_RSP      0x23    /* Login Response */
#define ISCSI_OP_TEXT_RSP       0x24    /* Text Response */
#define ISCSI_OP_SCSI_DATA_IN   0x25    /* SCSI Data-In */
#define ISCSI_OP_LOGOUT_RSP     0x26    /* Logout Response */
#define ISCSI_OP_R2T            0x31    /* Ready To Transfer */
#define ISCSI_OP_ASYNC_MSG      0x32    /* Asynchronous Message */
#define ISCSI_OP_REJECT         0x3f    /* Reject */

/* Opcode flag bits */
#define ISCSI_OP_IMMEDIATE      0x40    /* Immediate delivery flag in byte 0 */
#define ISCSI_FLAG_FINAL        0x80    /* Final PDU in sequence (byte 1) */

/* Login PDU flags (byte 1) */
#define ISCSI_LOGIN_TRANSIT     0x80    /* Transit to next stage */
#define ISCSI_LOGIN_CONTINUE    0x40    /* More login data follows */
#define ISCSI_LOGIN_NSG_MASK    0x03    /* Next Stage Group mask */
#define ISCSI_LOGIN_CSG_MASK    0x0C    /* Current Stage Group mask */
#define ISCSI_LOGIN_CSG_SHIFT   2

/* Text Request/Response flags */
#define ISCSI_TEXT_FINAL        0x80
#define ISCSI_TEXT_CONTINUE     0x40

/* SCSI Command flags (byte 1) */
#define ISCSI_SCSI_FLAG_FINAL   0x80
#define ISCSI_SCSI_FLAG_READ    0x40
#define ISCSI_SCSI_FLAG_WRITE   0x20
#define ISCSI_SCSI_ATTR_MASK    0x07

/* Logout reasons (byte 1 bits 4:0) */
#define ISCSI_LOGOUT_CLOSE_SESSION      0
#define ISCSI_LOGOUT_CLOSE_CONNECTION   1
#define ISCSI_LOGOUT_TASK_REASSIGN      2

/* Login response status codes (byte 36-37) */
#define ISCSI_STATUS_SUCCESS                0x0000
#define ISCSI_STATUS_TARGET_MOVED_TEMP      0x0101
#define ISCSI_STATUS_TARGET_MOVED_PERM      0x0102
#define ISCSI_STATUS_INITIATOR_ERROR        0x0200
#define ISCSI_STATUS_AUTH_FAILED            0x0201
#define ISCSI_STATUS_UNAUTHORIZED           0x0202
#define ISCSI_STATUS_TARGET_NOT_FOUND       0x0204
#define ISCSI_STATUS_TARGET_REMOVED         0x0205
#define ISCSI_STATUS_NO_RESOURCES           0x0300
#define ISCSI_STATUS_TARGET_ERROR           0x0301
#define ISCSI_STATUS_SERVICE_UNAVAILABLE    0x0302
#define ISCSI_STATUS_OUT_OF_RESOURCES       0x0303

/* Task Management Function codes */
#define ISCSI_TM_FUNC_ABORT_TASK            1
#define ISCSI_TM_FUNC_ABORT_TASK_SET        2
#define ISCSI_TM_FUNC_CLEAR_ACA             3
#define ISCSI_TM_FUNC_CLEAR_TASK_SET        4
#define ISCSI_TM_FUNC_LOGICAL_UNIT_RESET    5
#define ISCSI_TM_FUNC_TARGET_WARM_RESET     6
#define ISCSI_TM_FUNC_TARGET_COLD_RESET     7
#define ISCSI_TM_FUNC_TASK_REASSIGN         8

/* Reject reasons */
#define ISCSI_REJECT_CMD_NOT_SUPPORTED      0x04
#define ISCSI_REJECT_IMM_CMD_REJECT         0x05
#define ISCSI_REJECT_TASKMT_NOT_SUPPORTED   0x06
#define ISCSI_REJECT_DATA_DIGEST_ERROR      0x08
#define ISCSI_REJECT_SNACK_REJECT           0x0B
#define ISCSI_REJECT_PROTOCOL_ERROR         0x0C
#define ISCSI_REJECT_CMD_BEFORE_LOGIN       0x0E

/* ISID qualifier type bits (byte 8, bits 7:6) */
#define ISCSI_ISID_OUI          0x00
#define ISCSI_ISID_EN           0x40
#define ISCSI_ISID_RANDOM       0x80

/* -----------------------------------------------------------------------
 * PDU Structures (all fields in network byte order)
 * ----------------------------------------------------------------------- */

/* Generic iSCSI PDU header (48 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* byte 0: flags[7:6] | opcode[5:0] */
    uint8_t  flags;             /* byte 1: opcode-specific flags */
    uint8_t  rsvd2[2];          /* bytes 2-3 */
    uint8_t  ahslength;         /* byte 4: AHS total length (in 4B words) */
    uint8_t  dlength[3];        /* bytes 5-7: data segment length (big-endian) */
    uint8_t  lun[8];            /* bytes 8-15: LUN or opcode-specific */
    uint32_t itt;               /* bytes 16-19: Initiator Task Tag */
    uint32_t ttt;               /* bytes 20-23: Target Transfer Tag */
    uint32_t statsn;            /* bytes 24-27: StatSN / CmdSN */
    uint32_t expstatsn;         /* bytes 28-31: ExpStatSN / ExpCmdSN */
    uint32_t maxcmdsn;          /* bytes 32-35: MaxCmdSN */
    uint32_t expdatasn;         /* bytes 36-39: ExpDataSN / R2TSN / etc. */
    uint32_t rsvd40;            /* bytes 40-43 */
    uint32_t rsvd44;            /* bytes 44-47 */
} iscsi_hdr_t;

/* Login Request PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x03 | ISCSI_OP_IMMEDIATE */
    uint8_t  flags;             /* T|C|0|0|NSG|CSG */
    uint8_t  max_version;       /* Version-max */
    uint8_t  min_version;       /* Version-min */
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  isid[6];           /* Initiator Session ID */
    uint16_t tsih;              /* Target Session Identifying Handle */
    uint32_t itt;               /* Initiator Task Tag */
    uint16_t cid;               /* Connection ID */
    uint16_t rsvd22;
    uint32_t cmdsn;             /* CmdSN */
    uint32_t expstatsn;         /* ExpStatSN */
    uint8_t  rsvd32[16];
} iscsi_login_req_t;

/* Login Response PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x23 */
    uint8_t  flags;             /* T|C|0|0|NSG|CSG */
    uint8_t  max_version;
    uint8_t  active_version;
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  isid[6];
    uint16_t tsih;
    uint32_t itt;
    uint32_t rsvd20;
    uint32_t statsn;
    uint32_t expcmdsn;
    uint32_t maxcmdsn;
    uint8_t  status_class;      /* byte 36 */
    uint8_t  status_detail;     /* byte 37 */
    uint8_t  rsvd38[10];
} iscsi_login_rsp_t;

/* Text Request PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x04 | ISCSI_OP_IMMEDIATE */
    uint8_t  flags;             /* F|C */
    uint8_t  rsvd2[2];
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  lun[8];
    uint32_t itt;
    uint32_t ttt;
    uint32_t cmdsn;
    uint32_t expstatsn;
    uint8_t  rsvd32[16];
} iscsi_text_req_t;

/* Text Response PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x24 */
    uint8_t  flags;             /* F|C */
    uint8_t  rsvd2[2];
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  lun[8];
    uint32_t itt;
    uint32_t ttt;
    uint32_t statsn;
    uint32_t expcmdsn;
    uint32_t maxcmdsn;
    uint8_t  rsvd36[12];
} iscsi_text_rsp_t;

/* SCSI Command PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x01 */
    uint8_t  flags;             /* F|R|W|0|0|ATTR */
    uint8_t  rsvd2[2];
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  lun[8];
    uint32_t itt;
    uint32_t expected_datasn;
    uint32_t cmdsn;
    uint32_t expstatsn;
    uint8_t  cdb[16];
} iscsi_scsi_cmd_t;

/* SCSI Response PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x21 */
    uint8_t  flags;             /* F|0|0|0|0|0|o|u|O|U */
    uint8_t  response;          /* 0x00 = command completed */
    uint8_t  status;            /* SCSI status */
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  rsvd8[8];
    uint32_t itt;
    uint32_t snacktag;
    uint32_t statsn;
    uint32_t expcmdsn;
    uint32_t maxcmdsn;
    uint32_t expdatasn;
    uint32_t bidir_residualcnt;
    uint32_t residualcnt;
} iscsi_scsi_rsp_t;

/* SCSI Data-Out PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x05 */
    uint8_t  flags;             /* F */
    uint8_t  rsvd2[2];
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  lun[8];
    uint32_t itt;
    uint32_t ttt;
    uint32_t rsvd24;
    uint32_t expstatsn;
    uint32_t rsvd32;
    uint32_t datasn;
    uint32_t bufoffset;
    uint32_t rsvd44;
} iscsi_data_out_t;

/* SCSI Data-In PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x25 */
    uint8_t  flags;             /* F|A|0|0|0|S|U|O */
    uint8_t  rsvd2;
    uint8_t  status;
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  lun[8];
    uint32_t itt;
    uint32_t ttt;
    uint32_t statsn;
    uint32_t expcmdsn;
    uint32_t maxcmdsn;
    uint32_t datasn;
    uint32_t bufoffset;
    uint32_t residualcnt;
} iscsi_data_in_t;

/* Ready To Transfer (R2T) PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x31 */
    uint8_t  flags;             /* F */
    uint8_t  rsvd2[2];
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  lun[8];
    uint32_t itt;
    uint32_t ttt;
    uint32_t statsn;
    uint32_t expcmdsn;
    uint32_t maxcmdsn;
    uint32_t r2tsn;
    uint32_t bufoffset;
    uint32_t desired_datasn;
} iscsi_r2t_t;

/* Logout Request PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x06 | ISCSI_OP_IMMEDIATE */
    uint8_t  flags;             /* F | reason_code[4:0] */
    uint8_t  rsvd2[2];
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  rsvd8[8];
    uint32_t itt;
    uint16_t cid;
    uint16_t rsvd22;
    uint32_t cmdsn;
    uint32_t expstatsn;
    uint8_t  rsvd32[16];
} iscsi_logout_req_t;

/* Logout Response PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x26 */
    uint8_t  flags;             /* F */
    uint8_t  response;
    uint8_t  rsvd3;
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  rsvd8[8];
    uint32_t itt;
    uint32_t rsvd20;
    uint32_t statsn;
    uint32_t expcmdsn;
    uint32_t maxcmdsn;
    uint8_t  rsvd36[4];
    uint16_t time2wait;
    uint16_t time2retain;
    uint32_t rsvd44;
} iscsi_logout_rsp_t;

/* NOP-Out PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x00 */
    uint8_t  flags;             /* F */
    uint8_t  rsvd2[2];
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  lun[8];
    uint32_t itt;
    uint32_t ttt;
    uint32_t cmdsn;
    uint32_t expstatsn;
    uint8_t  rsvd32[16];
} iscsi_nop_out_t;

/* NOP-In PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x20 */
    uint8_t  flags;             /* F */
    uint8_t  rsvd2[2];
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  lun[8];
    uint32_t itt;
    uint32_t ttt;
    uint32_t statsn;
    uint32_t expcmdsn;
    uint32_t maxcmdsn;
    uint8_t  rsvd36[12];
} iscsi_nop_in_t;

/* Reject PDU header overlay */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;            /* 0x3f */
    uint8_t  flags;             /* F */
    uint8_t  reason;
    uint8_t  rsvd3;
    uint8_t  ahslength;
    uint8_t  dlength[3];
    uint8_t  rsvd8[8];
    uint32_t rsvd16;
    uint32_t rsvd20;
    uint32_t statsn;
    uint32_t expcmdsn;
    uint32_t maxcmdsn;
    uint32_t datasn;
    uint8_t  rsvd40[8];
} iscsi_reject_t;

/* -----------------------------------------------------------------------
 * Inline helpers
 * ----------------------------------------------------------------------- */

/* Extract 24-bit data segment length from dlength[3] field */
static inline uint32_t iscsi_dlength_get(const uint8_t dlength[3])
{
    return ((uint32_t)dlength[0] << 16) |
           ((uint32_t)dlength[1] <<  8) |
            (uint32_t)dlength[2];
}

/* Set 24-bit data segment length into dlength[3] field */
static inline void iscsi_dlength_set(uint8_t dlength[3], uint32_t len)
{
    dlength[0] = (len >> 16) & 0xff;
    dlength[1] = (len >>  8) & 0xff;
    dlength[2] =  len        & 0xff;
}

/* Round up to next 4-byte boundary (padding for data segments) */
static inline uint32_t iscsi_pad4(uint32_t len)
{
    return (len + 3) & ~3u;
}

/* Extract current stage from login flags byte */
static inline uint8_t iscsi_login_csg(uint8_t flags)
{
    return (flags & ISCSI_LOGIN_CSG_MASK) >> ISCSI_LOGIN_CSG_SHIFT;
}

/* Extract next stage from login flags byte */
static inline uint8_t iscsi_login_nsg(uint8_t flags)
{
    return flags & ISCSI_LOGIN_NSG_MASK;
}

/* Build login flags byte */
static inline uint8_t iscsi_login_flags(int transit, int cont,
                                         uint8_t csg, uint8_t nsg)
{
    return (transit ? ISCSI_LOGIN_TRANSIT : 0) |
           (cont    ? ISCSI_LOGIN_CONTINUE : 0) |
           ((csg & 0x3) << ISCSI_LOGIN_CSG_SHIFT) |
           (nsg & ISCSI_LOGIN_NSG_MASK);
}

/* Static assertion that PDU overlay structs are exactly 48 bytes */
_Static_assert(sizeof(iscsi_hdr_t)         == ISCSI_HDR_LEN, "iscsi_hdr_t size");
_Static_assert(sizeof(iscsi_login_req_t)   == ISCSI_HDR_LEN, "iscsi_login_req_t size");
_Static_assert(sizeof(iscsi_login_rsp_t)   == ISCSI_HDR_LEN, "iscsi_login_rsp_t size");
_Static_assert(sizeof(iscsi_text_req_t)    == ISCSI_HDR_LEN, "iscsi_text_req_t size");
_Static_assert(sizeof(iscsi_text_rsp_t)    == ISCSI_HDR_LEN, "iscsi_text_rsp_t size");
_Static_assert(sizeof(iscsi_scsi_cmd_t)    == ISCSI_HDR_LEN, "iscsi_scsi_cmd_t size");
_Static_assert(sizeof(iscsi_scsi_rsp_t)    == ISCSI_HDR_LEN, "iscsi_scsi_rsp_t size");
_Static_assert(sizeof(iscsi_data_out_t)    == ISCSI_HDR_LEN, "iscsi_data_out_t size");
_Static_assert(sizeof(iscsi_data_in_t)     == ISCSI_HDR_LEN, "iscsi_data_in_t size");
_Static_assert(sizeof(iscsi_r2t_t)         == ISCSI_HDR_LEN, "iscsi_r2t_t size");
_Static_assert(sizeof(iscsi_logout_req_t)  == ISCSI_HDR_LEN, "iscsi_logout_req_t size");
_Static_assert(sizeof(iscsi_logout_rsp_t)  == ISCSI_HDR_LEN, "iscsi_logout_rsp_t size");
_Static_assert(sizeof(iscsi_nop_out_t)     == ISCSI_HDR_LEN, "iscsi_nop_out_t size");
_Static_assert(sizeof(iscsi_nop_in_t)      == ISCSI_HDR_LEN, "iscsi_nop_in_t size");
_Static_assert(sizeof(iscsi_reject_t)      == ISCSI_HDR_LEN, "iscsi_reject_t size");
