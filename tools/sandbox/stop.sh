#!/bin/bash
# stop.sh - stop the sandbox started by start.sh, including its keyring daemon and Xvfb.
state=${SANDBOX_STATE:-${TMPDIR:-/tmp}/landhorse-sandbox}
if [ -f "$state/pid" ]; then
    kill -- "-$(cat "$state/pid")" 2>/dev/null || true
    rm -f "$state/pid"
fi
