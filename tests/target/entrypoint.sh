#!/bin/bash
set -e

TARGET_IQN="iqn.2024-01.io.iscsid-mac:test"

# Start tgtd in foreground-compatible mode
tgtd --foreground &
TGTD_PID=$!
sleep 1

# Create target
tgtadm --lld iscsi --op new --mode target --tid 1 \
    --targetname "${TARGET_IQN}"

# Add LUN 1 backed by disk image
tgtadm --lld iscsi --op new --mode logicalunit --tid 1 --lun 1 \
    --backing-store /disk0.img

# Allow all initiators (no auth for testing)
tgtadm --lld iscsi --op bind --mode target --tid 1 --initiator-address ALL

echo "iSCSI target ready: ${TARGET_IQN}"
echo "Listening on port 3260"

wait $TGTD_PID
