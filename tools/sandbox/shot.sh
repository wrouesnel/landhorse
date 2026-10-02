#!/bin/bash
# shot.sh NAME - save a screenshot of the sandbox display to $SANDBOX_STATE/NAME.png.
set -euo pipefail
state=${SANDBOX_STATE:-${TMPDIR:-/tmp}/landhorse-sandbox}
DISPLAY=:${SANDBOX_DISPLAY:-77} XAUTHORITY=$state/xauth import -window root "$state/$1.png"
echo "$state/$1.png"
