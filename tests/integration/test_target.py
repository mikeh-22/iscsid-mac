#!/usr/bin/env python3
"""
integration/test_target.py - Verify the tgt iSCSI target is functional.

Connects a raw iSCSI login (SecurityNegotiation → FullFeaturePhase) and
sends a SendTargets text request, then asserts the expected IQN appears
in the response. This validates the Docker target image and exercises
the same PDU format that iscsid uses.

RFC 7143 §10.12 / §10.17 login + text PDU implementation in ~150 lines.
"""

import socket
import struct
import sys
import os

TARGET_HOST = os.environ.get("ISCSI_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("ISCSI_PORT", "3260"))
EXPECTED_IQN = os.environ.get("EXPECTED_IQN", "iqn.2024-01.io.iscsid-mac:test")
INITIATOR_NAME = "iqn.2026-01.io.iscsid-mac:ci-test"

# iSCSI opcodes
OP_LOGIN_REQ  = 0x43
OP_LOGIN_RSP  = 0x23
OP_TEXT_REQ   = 0x44
OP_TEXT_RSP   = 0x24

ISCSI_VERSION = 0x00

def dlength_set(n: int) -> bytes:
    return bytes([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])

def dlength_get(b: bytes) -> int:
    return (b[0] << 16) | (b[1] << 8) | b[2]

def pad4(n: int) -> int:
    return (n + 3) & ~3

def kv(*pairs) -> bytes:
    parts = []
    for k, v in pairs:
        parts.append(f"{k}={v}\x00".encode())
    return b"".join(parts)

def send_pdu(sock, hdr: bytes, data: bytes = b""):
    assert len(hdr) == 48
    sock.sendall(hdr)
    if data:
        padded = data + b"\x00" * (pad4(len(data)) - len(data))
        sock.sendall(padded)

def recv_pdu(sock):
    hdr = b""
    while len(hdr) < 48:
        chunk = sock.recv(48 - len(hdr))
        if not chunk:
            raise EOFError("connection closed")
        hdr += chunk
    dlen = dlength_get(hdr[5:8])
    data = b""
    remaining = pad4(dlen)
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("connection closed during data")
        data += chunk
        remaining -= len(chunk)
    return hdr, data[:dlen]

def build_login(isid, cid, cmdsn, expstatsn, csg, nsg, transit, data):
    flags = (0x80 if transit else 0x00) | ((csg & 0x3) << 2) | (nsg & 0x3)
    hdr = bytearray(48)
    hdr[0]  = OP_LOGIN_REQ
    hdr[1]  = flags
    hdr[2]  = ISCSI_VERSION   # max version
    hdr[3]  = ISCSI_VERSION   # min version
    hdr[4]  = 0               # TotalAHSLength
    hdr[5:8]= dlength_set(len(data))
    hdr[8:14] = isid
    hdr[14:16] = b"\x00\x00"  # TSIH = 0 (new session)
    hdr[16:20] = struct.pack(">I", 1)  # ITT
    hdr[20:22] = struct.pack(">H", cid)
    hdr[22:24] = b"\x00\x00"
    hdr[24:28] = struct.pack(">I", cmdsn)
    hdr[28:32] = struct.pack(">I", expstatsn)
    return bytes(hdr)

def build_text(cmdsn, expstatsn, data):
    hdr = bytearray(48)
    hdr[0] = OP_TEXT_REQ
    hdr[1] = 0x80             # F=1 (final)
    hdr[4] = 0
    hdr[5:8] = dlength_set(len(data))
    hdr[16:20] = struct.pack(">I", 2)   # ITT
    hdr[20:24] = struct.pack(">I", 0xffffffff)  # TargetTransferTag
    hdr[24:28] = struct.pack(">I", cmdsn)
    hdr[28:32] = struct.pack(">I", expstatsn)
    return bytes(hdr)

def test_sendtargets():
    print(f"Connecting to {TARGET_HOST}:{TARGET_PORT}...")
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    isid = bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x01])
    cid, cmdsn, expstatsn = 1, 1, 0

    # --- Security phase (None auth, transit to OpNeg) ---
    data = kv(
        ("InitiatorName",   INITIATOR_NAME),
        ("SessionType",     "Discovery"),
        ("AuthMethod",      "None"),
    )
    # CSG=0 (SecurityNeg), NSG=1 (OpNeg), T=1
    hdr = build_login(isid, cid, cmdsn, expstatsn, csg=0, nsg=1, transit=True, data=data)
    send_pdu(sock, hdr, data)

    rsp_hdr, rsp_data = recv_pdu(sock)
    assert rsp_hdr[0] == OP_LOGIN_RSP, f"expected login rsp, got {rsp_hdr[0]:#x}"
    status = struct.unpack(">H", rsp_hdr[36:38])[0]
    assert status == 0, f"login failed with status {status:#06x}"
    expstatsn = struct.unpack(">I", rsp_hdr[24:28])[0] + 1

    rsp_flags = rsp_hdr[1]
    transited = bool(rsp_flags & 0x80)

    if not transited:
        # Target wants another round-trip to confirm transit
        data = kv()
        hdr = build_login(isid, cid, cmdsn, expstatsn, csg=1, nsg=3, transit=True, data=data)
        send_pdu(sock, hdr, data)
        rsp_hdr, rsp_data = recv_pdu(sock)
        assert rsp_hdr[0] == OP_LOGIN_RSP
        status = struct.unpack(">H", rsp_hdr[36:38])[0]
        assert status == 0, f"op-neg login failed: {status:#06x}"
        expstatsn = struct.unpack(">I", rsp_hdr[24:28])[0] + 1

    print(f"Login OK (status=0x0000), in Full Feature Phase")

    # --- SendTargets text request ---
    cmdsn += 1
    data = kv(("SendTargets", "All"))
    hdr = build_text(cmdsn, expstatsn, data)
    send_pdu(sock, hdr, data)

    rsp_hdr, rsp_data = recv_pdu(sock)
    assert rsp_hdr[0] == OP_TEXT_RSP, f"expected text rsp, got {rsp_hdr[0]:#x}"

    text = rsp_data.decode(errors="replace")
    print(f"SendTargets response ({len(rsp_data)} bytes):")
    for part in rsp_data.split(b"\x00"):
        if part:
            print(f"  {part.decode(errors='replace')}")

    assert EXPECTED_IQN in text, \
        f"Expected IQN '{EXPECTED_IQN}' not found in response:\n{text}"

    print(f"\nPASS: found '{EXPECTED_IQN}' in SendTargets response")
    sock.close()

if __name__ == "__main__":
    try:
        test_sendtargets()
    except AssertionError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
