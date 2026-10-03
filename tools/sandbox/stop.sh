#!/bin/bash
# stop.sh - stop the sandbox started by start.sh, including its keyring daemon and Xvfb.
state=${SANDBOX_STATE:-${TMPDIR:-/tmp}/landhorse-sandbox}
if [ -f "$state/pid" ]; then
    pgid=$(cat "$state/pid")
    kill -- "-$pgid" 2>/dev/null || true
    # Wait for Xvfb to release the display, so start.sh can run straight after.
    for _ in $(seq 1 20); do kill -0 -- "-$pgid" 2>/dev/null || break; sleep 0.25; done
    rm -f "$state/pid"
fi
# The sandbox's keys are disposable; don't leave private keys lying around.
[ -f "$state/agent-dir" ] && rm -rf "$(cat "$state/agent-dir")" "$state/agent-dir"
rm -rf "$state/home" "$state/run" "$state/published" "$state/published-2"
