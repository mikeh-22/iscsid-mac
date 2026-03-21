# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

```sh
# Configure (one time, or after CMakeLists.txt changes)
cmake -B build -DCMAKE_BUILD_TYPE=Debug    # AddressSanitizer + UBSan enabled
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build everything
cmake --build build -j$(sysctl -n hw.logicalcpu)

# Run all tests
ctest --test-dir build -V

# Run a single test binary directly
./build/test_pdu
./build/test_auth
```

cmake is at `/opt/homebrew/bin/cmake`. The build dir is `build/` (already configured). Debug builds enable `-fsanitize=address,undefined`.

## End-to-end testing

A Docker-based iSCSI target (Ubuntu + `tgt`) lives in `tests/target/`:

```sh
docker build -t iscsid-mac-target tests/target/
docker run -d --name iscsi-target --privileged -p 3260:3260 iscsid-mac-target

# Start daemon (foreground, user-writable socket for dev)
./build/iscsid -s /tmp/iscsid-test.sock -f -d &

./build/iscsictl -s /tmp/iscsid-test.sock ping
./build/iscsictl -s /tmp/iscsid-test.sock discover -h 127.0.0.1 -p 3260
./build/iscsictl -s /tmp/iscsid-test.sock login -h 127.0.0.1 -p 3260 -t iqn.2024-01.io.iscsid-mac:test
./build/iscsictl -s /tmp/iscsid-test.sock list
./build/iscsictl -s /tmp/iscsid-test.sock logout -t iqn.2024-01.io.iscsid-mac:test

docker stop iscsi-target && docker rm iscsi-target
```

The daemon needs `sudo` in production (for `/var/run/iscsid.sock` and `/var/run/iscsid.pid`). Use `-s /tmp/...` to skip that during development.

## Architecture

```
iscsictl ──JSON/Unix socket──► iscsid ──TCP:3260──► iSCSI target
                                  │
                           IOUserClient
                                  │
                       iSCSIInitiator.dext ──► SCSI Parallel Family ──► block devices
```

**Critical constraint**: DriverKit extensions cannot open TCP sockets. All network I/O and RFC 7143 protocol logic lives in `iscsid`. The DEXT (`dext/`) is a skeleton that handles only SCSI ↔ block-device translation; deploying it requires Apple entitlements not yet obtained.

### Protocol layer stack (bottom-up)

| Layer | Files | Responsibility |
|-------|-------|----------------|
| PDU framing | `pdu.c/h` | 48-byte header send/recv, data segment with 4-byte padding, NUL-terminated KV text parsing |
| Auth | `auth.c/h` | CHAP-MD5 / CHAP-SHA256 using CommonCrypto; `chap_ctx_t` holds challenge/secrets |
| Connection | `connection.c/h` | Single TCP connection lifecycle (getaddrinfo, connect, keepalive, nodelay) |
| Session | `session.c/h` | Session state, ISID generation (`/dev/urandom`), CmdSN/StatSN sequencing with mutex |
| Login FSM | `login.c/h` | SecurityNeg → LoginOperationalNeg → FullFeaturePhase; handles None and CHAP auth |
| Discovery | `discovery.c/h` | SendTargets discovery session; parses NUL-delimited KV text responses |
| Config | `config.c/h` | Key=value config file; auto-generates IQN if `/etc/iscsi/initiatorname.iscsi` absent |
| IPC | `ipc.c/h` | Unix domain socket, length-prefixed (4-byte big-endian) JSON messages |
| Daemon | `src/daemon/main.c` | Event loop, signal handling, IPC dispatch, session registry |
| CLI | `src/cli/main.c` | Connects to daemon socket, sends JSON commands, pretty-prints responses |

### RFC 7143 login state machine (the tricky part)

The T-bit (transit) rule: **a stage transition only occurs when both sides send T=1 with the same NSG in the same exchange**. The initiator must set T=1 first; the target echoes it.

- **None auth**: initiator sends T=1, NSG=OpNeg in the very first Security PDU. Target may respond with T=1 (transit immediately) or T=0 (needs a confirm round-trip).
- **CHAP**: three security-phase round-trips — propose → receive challenge → send response with T=1.

See the comment block at the top of `login.c` for the exact PDU sequence.

### IPC wire format

Request and response are flat JSON objects. String fields are escaped with `json_escape()` in `main.c` (handles `"`, `\`, control chars) to prevent injection via target names or hostnames. Commands: `ping`, `discover`, `login`, `logout`, `list`, `status`.

### Sensitive memory handling

`explicit_bzero` is not available on macOS. The codebase uses `memset_s` (C11 Annex K, enabled via `#define __STDC_WANT_LIB_EXT1__ 1`) wrapped as `secure_zero()` in `auth.c`. Call `chap_clear()` after any CHAP exchange to wipe secrets.

### Adding a new test

Tests are self-contained C files in `tests/`. They use a simple `PASS`/`FAIL` counter pattern — see `tests/test_pdu.c` for the convention. Add a new executable to `CMakeLists.txt` following the existing `test_pdu` / `test_auth` pattern, then register it with `add_test()`.
