#!/bin/bash
# start.sh [landhorse args...] - run landhorse against throwaway data on a virtual display.
#
# Uses Xvfb display :77 (override with SANDBOX_DISPLAY) and keeps its state in
# $TMPDIR/landhorse-sandbox (override with SANDBOX_STATE). Build first with
# `go run mage.go binary`. Drive it with xdotool and capture it with shot.sh; stop.sh
# tears it down. The keyring password is "sandbox".
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
state=${SANDBOX_STATE:-${TMPDIR:-/tmp}/landhorse-sandbox}
display=${SANDBOX_DISPLAY:-77}
mkdir -p "$state"
if [ -f "$state/pid" ] && kill -0 -- "-$(cat "$state/pid")" 2>/dev/null; then
    echo "a sandbox is already running from $state; run stop.sh first" >&2
    exit 1
fi
rm -f "$state/ready"

setsid xvfb-run -n "$display" -f "$state/xauth" -s "-screen 0 1280x800x24" \
    dbus-run-session -- "$here/populate.sh" "$state" "$root/landhorse" --log-level=debug "$@" \
    > "$state/app.log" 2>&1 < /dev/null &
echo $! > "$state/pid"

for _ in $(seq 1 60); do [ -f "$state/ready" ] && break; sleep 1; done
sleep 3
if [ ! -f "$state/ready" ]; then
    echo "sandbox failed to start; see $state/app.log" >&2
    tail -20 "$state/app.log" >&2
    exit 1
fi
echo "landhorse running on DISPLAY=:$display XAUTHORITY=$state/xauth (log: $state/app.log)"
