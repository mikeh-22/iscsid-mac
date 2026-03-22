# iscsid-mac

[![CI](https://github.com/mikeh-22/iscsid-mac/actions/workflows/ci.yml/badge.svg)](https://github.com/mikeh-22/iscsid-mac/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mikeh-22/iscsid-mac/actions/workflows/codeql.yml/badge.svg)](https://github.com/mikeh-22/iscsid-mac/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

An open-source iSCSI initiator daemon for macOS, implementing [RFC 7143](https://www.rfc-editor.org/rfc/rfc7143) in userspace.

Apple shipped a proprietary iSCSI initiator through macOS High Sierra (10.13) and then removed it. This project replaces it with a clean, open implementation targeting modern macOS on Apple Silicon.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   User Space                        │
│                                                     │
│  iscsictl ──JSON/Unix socket──► iscsid              │
│                                    │                │
│                              TCP port 3260          │
│                                    │                │
│                            iSCSI target             │
│                                                     │
│  iscsid ──IOUserClient──► iSCSIInitiator.dext       │
│                                    │                │
│                            SCSI Parallel Family     │
└─────────────────────────────────────────────────────┘
│                   Kernel                            │
│            Block storage stack                      │
└─────────────────────────────────────────────────────┘
```

**Key constraint**: DriverKit system extensions cannot open network sockets (Apple security model). Therefore all TCP/IP and iSCSI protocol work lives in `iscsid`; the DriverKit extension (`iSCSIInitiator.dext`) handles only SCSI ↔ block-device translation and communicates with the daemon via `IOUserClient`.

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| `iscsid` | C | Daemon: RFC 7143 protocol, CHAP auth, session management, Unix socket IPC |
| `iscsictl` | C | CLI: discovery, login, logout, session listing |
| `iSCSIInitiator.dext` | C++ | DriverKit SCSI controller (requires Apple entitlements) |

## Requirements

- macOS 12 (Monterey) or later
- Apple Silicon (arm64) — the default build target
- Xcode Command Line Tools (`xcode-select --install`)
- CMake 3.20+ (`brew install cmake`)

## Building

```sh
git clone https://github.com/mikeh-22/iscsid-mac
cd iscsid-mac

# Debug build (includes AddressSanitizer + UBSan)
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(sysctl -n hw.logicalcpu)

# Release build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(sysctl -n hw.logicalcpu)
```

Binaries are written to `build/`:

```
build/iscsid        # daemon
build/iscsictl      # CLI tool
build/test_pdu      # PDU unit tests
build/test_auth     # CHAP auth unit tests
```

## Testing

### Unit tests

```sh
ctest --test-dir build -V
```

```
=== PDU unit tests ===
  PDU header struct sizes == 48                     PASS
  iscsi_dlength set/get roundtrip                   PASS
  pdu_kv_append / pdu_kv_get                        PASS
  pdu_kv_append overflow detection                  PASS
  pdu_send / pdu_recv over socketpair               PASS
  iscsi_pad4                                        PASS
  iscsi_login_flags encode/decode                   PASS

=== CHAP auth unit tests ===
  chap_hex_encode / chap_hex_decode roundtrip       PASS
  CHAP MD5 known-answer test                        PASS
  chap_parse_challenge from KV buffer               PASS
  chap_parse_challenge rejects wrong algorithm      PASS
```

### Integration tests (Docker)

`tests/target/` contains a Dockerised [tgt](https://github.com/fujita/tgt) iSCSI target used in CI. To run the full end-to-end flow locally:

```sh
# Start the target
docker build -t iscsid-mac-target tests/target/
docker run -d --name iscsi-target --privileged -p 3260:3260 iscsid-mac-target

# Start the daemon (no root needed with a custom socket path)
./build/iscsid -s /tmp/iscsid-test.sock -f -d &

# Exercise the daemon
./build/iscsictl -s /tmp/iscsid-test.sock discover -h 127.0.0.1 -p 3260
./build/iscsictl -s /tmp/iscsid-test.sock login    -h 127.0.0.1 -p 3260 \
    -t iqn.2024-01.io.iscsid-mac:test
./build/iscsictl -s /tmp/iscsid-test.sock list
./build/iscsictl -s /tmp/iscsid-test.sock logout   -t iqn.2024-01.io.iscsid-mac:test

# Teardown
docker stop iscsi-target && docker rm iscsi-target
```

CI runs this end-to-end test automatically on every push and pull request.

## Usage

### Start the daemon

```sh
# Foreground (development)
sudo build/iscsid -f -d

# As a system service
sudo cp etc/io.iscsid-mac.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/io.iscsid-mac.plist
```

### Discover targets

```sh
iscsictl discover -h 192.168.1.100
# Discovered 2 target(s):
#   1: iqn.2024-01.io.example:storage1
#      Address: 192.168.1.100:3260
#   2: iqn.2024-01.io.example:storage2
#      Address: 192.168.1.100:3260
```

### Login to a target

```sh
iscsictl login -h 192.168.1.100 -t iqn.2024-01.io.example:storage1
```

### List active sessions

```sh
iscsictl list
#   iqn.2024-01.io.example:storage1   192.168.1.100:3260   LOGGED_IN
```

### Logout

```sh
iscsictl logout -t iqn.2024-01.io.example:storage1
```

## Configuration

Copy `etc/iscsid.conf.sample` to `/etc/iscsid.conf` and edit:

```ini
# CHAP authentication
node.session.auth.authmethod = CHAP
node.session.auth.username   = iqn.2024-01.io.example:myinitiator
node.session.auth.password   = my-secret-at-least-12-bytes

# Mutual CHAP (target authenticates back to initiator)
node.session.auth.username_in = iqn.2024-01.io.example:mytarget
node.session.auth.password_in = target-secret-12bytes

# Session parameters
node.session.iscsi.MaxBurstLength   = 262144
node.session.iscsi.FirstBurstLength = 65536
node.session.iscsi.ImmediateData    = Yes
```

The initiator IQN is read from `/etc/iscsi/initiatorname.iscsi` (created automatically on first run if absent):

```ini
InitiatorName=iqn.2024-01.io.iscsid-mac:mymac
```

## Protocol implementation

Implements [RFC 7143](https://www.rfc-editor.org/rfc/rfc7143) (iSCSI) and [RFC 1994](https://www.rfc-editor.org/rfc/rfc1994) (CHAP):

- Login state machine: SecurityNegotiation → LoginOperationalNegotiation → FullFeaturePhase
- CHAP-MD5 (mandatory per RFC 7143) and CHAP-SHA256
- Mutual CHAP authentication
- SendTargets discovery sessions
- iSNS discovery (RFC 4171)
- Operational parameter negotiation (burst lengths, R2T, ImmediateData, digests, etc.)
- CRC32C header and data digests (RFC 7143 §6.7)
- NOP-Out/NOP-In keepalive
- Logout (close session and close connection reasons)
- Error Recovery Level 0 and 1 (connection reconnect within Time2Wait/Time2Retain)
- Multi-connection session support (add-connection login, MaxConnections negotiation)

**Not yet implemented**: ERL 2, multi-connection sessions beyond the negotiation layer.

## DriverKit extension

`dext/iSCSIInitiator.dext` is a skeleton `IOUserSCSIParallelInterfaceController` that wires the macOS SCSI parallel family to the `iscsid` daemon. Deploying it requires:

1. **Apple Developer Program** membership
2. The `com.apple.developer.driverkit.family.scsicontroller` entitlement (request from Apple)
3. An Xcode project with a System Extension target

Until the entitlement is obtained, iSCSI volumes can be accessed as raw block data through the daemon socket, or by running a local NBD (Network Block Device) server bridge.

## Source layout

```
iscsid-mac/
├── src/
│   ├── shared/
│   │   └── iscsi_protocol.h   # RFC 7143 PDU structs & constants
│   ├── daemon/
│   │   ├── pdu.c/h            # PDU encode/decode, key=value text
│   │   ├── auth.c/h           # CHAP-MD5 / CHAP-SHA256 (CommonCrypto)
│   │   ├── connection.c/h     # TCP connection lifecycle
│   │   ├── session.c/h        # Session state & sequence numbers
│   │   ├── login.c/h          # Login/logout state machine
│   │   ├── discovery.c/h      # SendTargets discovery
│   │   ├── config.c/h         # Config file & initiator name
│   │   ├── ipc.c/h            # Unix socket IPC (length-prefixed JSON)
│   │   └── main.c             # Daemon entry point
│   └── cli/
│       └── main.c             # iscsictl
├── dext/
│   ├── iSCSIInitiator.cpp/h   # DriverKit SCSI controller
│   └── Info.plist
├── tests/
│   ├── test_pdu.c             # PDU encode/decode unit tests
│   ├── test_auth.c            # CHAP auth unit tests
│   ├── integration/
│   │   └── test_target.py     # Raw iSCSI protocol smoke test
│   └── target/
│       ├── Dockerfile         # Ubuntu + tgt iSCSI target (used in CI)
│       └── entrypoint.sh
├── etc/
│   ├── iscsid.conf.sample
│   └── io.iscsid-mac.plist    # LaunchDaemon
└── CMakeLists.txt
```

## Related work

- [iscsi-osx/iSCSIInitiator](https://github.com/iscsi-osx/iSCSIInitiator) — prior open-source attempt using a kernel extension; development stalled when Apple deprecated kexts and DriverKit lacked socket support
- [open-iscsi](https://github.com/open-iscsi/open-iscsi) — Linux reference implementation

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for code style, test requirements, and the PR checklist. To report a security vulnerability, follow the process in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
