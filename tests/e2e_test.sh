#!/usr/bin/env bash
# e2e_test.sh - End-to-end integration test for iscsid-mac
#
# Requires:
#   - Docker (skipped if not available)
#   - Build directory as $1 (e.g. /path/to/build)
#
# Exit codes:
#   0   = all tests passed
#   1   = tests failed
#   77  = skipped (Docker unavailable, or target image missing)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

BUILDDIR="${1:-$(dirname "$0")/../build}"
ISCSID="$BUILDDIR/iscsid"
ISCSICTL="$BUILDDIR/iscsictl"
SOCK="/tmp/iscsid-e2e-$$.sock"
PERSIST="/tmp/iscsid-e2e-$$.persist"
CONTAINER="iscsid-e2e-$$"
TARGET_IQN="iqn.2024-01.io.iscsid-mac:test"
ISCSID_PID=""

# Colours for readability
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
pass() { printf "  ${GREEN}PASS${NC}  %s\n" "$*"; }
fail() { printf "  ${RED}FAIL${NC}  %s\n" "$*"; FAIL_COUNT=$((FAIL_COUNT+1)); }
FAIL_COUNT=0

cleanup() {
    if [ -n "$ISCSID_PID" ] && kill -0 "$ISCSID_PID" 2>/dev/null; then
        kill "$ISCSID_PID" 2>/dev/null || true
        wait "$ISCSID_PID" 2>/dev/null || true
    fi
    docker rm -f "$CONTAINER" 2>/dev/null || true
    rm -f "$SOCK" "$PERSIST"
}
trap cleanup EXIT

# ---- Prerequisites ----

if ! command -v docker &>/dev/null; then
    echo "e2e: Docker not found, skipping" >&2
    exit 77
fi
if ! docker info &>/dev/null; then
    echo "e2e: Docker daemon not running, skipping" >&2
    exit 77
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Build the target image if not already built
if ! docker image inspect iscsid-mac-target &>/dev/null; then
    echo "e2e: building iscsid-mac-target image..."
    docker build -t iscsid-mac-target "$REPO_ROOT/tests/target/" >/dev/null 2>&1 || {
        echo "e2e: failed to build target image, skipping" >&2
        exit 77
    }
fi

echo "e2e: starting iSCSI target container..."
docker run -d --name "$CONTAINER" --privileged -p 3260:3260 \
    iscsid-mac-target >/dev/null

# Wait for target to be ready: poll until the IQN target is actually configured.
# tgtd opens port 3260 before the entrypoint configures the target, so we must
# check tgtadm --mode target (not system) and confirm a target is listed.
for i in $(seq 1 40); do
    if docker exec "$CONTAINER" tgtadm --mode target --op show 2>/dev/null \
            | grep -q "Target"; then
        break
    fi
    sleep 0.5
done

echo "e2e: starting iscsid daemon..."
"$ISCSID" -s "$SOCK" -f \
    -c /dev/null \
    &
ISCSID_PID=$!
sleep 0.5

# Verify daemon is alive
if ! kill -0 "$ISCSID_PID" 2>/dev/null; then
    echo "e2e: iscsid failed to start" >&2
    exit 1
fi

echo "e2e: running tests..."

# ---- Test: ping ----
if "$ISCSICTL" -s "$SOCK" ping 2>&1 | grep -q "pong"; then
    pass "ping → pong"
else
    fail "ping did not return pong"
fi

# ---- Test: SendTargets discover ----
DISC_OUT=$("$ISCSICTL" -s "$SOCK" discover -h 127.0.0.1 -p 3260 2>&1)
if echo "$DISC_OUT" | grep -q "$TARGET_IQN"; then
    pass "discover: found $TARGET_IQN"
else
    fail "discover: target not found (output: $DISC_OUT)"
fi

# ---- Test: login ----
LOGIN_OUT=$("$ISCSICTL" -s "$SOCK" login \
    -h 127.0.0.1 -p 3260 -t "$TARGET_IQN" 2>&1)
if echo "$LOGIN_OUT" | grep -qi "logged in"; then
    pass "login: logged in to $TARGET_IQN"
else
    fail "login failed (output: $LOGIN_OUT)"
fi

# ---- Test: list shows session ----
LIST_OUT=$("$ISCSICTL" -s "$SOCK" list 2>&1)
if echo "$LIST_OUT" | grep -q "$TARGET_IQN"; then
    pass "list: session visible"
else
    fail "list: session not visible (output: $LIST_OUT)"
fi

# ---- Test: luns (REPORT LUNS) ----
LUNS_OUT=$("$ISCSICTL" -s "$SOCK" luns -t "$TARGET_IQN" 2>&1)
if echo "$LUNS_OUT" | grep -qE "LUN|lun"; then
    pass "luns: REPORT LUNS returned data"
else
    fail "luns: no LUN data (output: $LUNS_OUT)"
fi

# ---- Test: logout ----
LOGOUT_OUT=$("$ISCSICTL" -s "$SOCK" logout -t "$TARGET_IQN" 2>&1)
if echo "$LOGOUT_OUT" | grep -qi "logged out"; then
    pass "logout: logged out from $TARGET_IQN"
else
    fail "logout failed (output: $LOGOUT_OUT)"
fi

# ---- Test: list shows no sessions after logout ----
LIST_OUT=$("$ISCSICTL" -s "$SOCK" list 2>&1)
if echo "$LIST_OUT" | grep -q "No active sessions"; then
    pass "list: no sessions after logout"
else
    fail "list: session still visible after logout (output: $LIST_OUT)"
fi

echo ""
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "e2e: ALL TESTS PASSED"
    exit 0
else
    echo "e2e: $FAIL_COUNT FAILURE(S)"
    exit 1
fi
