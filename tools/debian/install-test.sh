#!/bin/bash
# install-test.sh SERIES - check that the built landhorse package replaces seahorse cleanly.
#
# In a fresh container of the release it installs seahorse and openpgp-applet (which
# depends on seahorse), then installs landhorse from release/deb/SERIES/, and checks that
# seahorse was removed, openpgp-applet stayed installed, the seahorse command and schema
# still exist, and that apt sees gnome's "seahorse (>= 3.36)" dependency as satisfied.
set -euo pipefail

declare -A RELEASES=([noble]=24.04 [resolute]=26.04)
series=${1:?usage: install-test.sh SERIES}
release=${RELEASES[$series]:?unknown series $series}
out="$(git rev-parse --show-toplevel)/release/deb/$series"
ls "$out"/landhorse_*.deb >/dev/null

podman run --rm -v "$out:/debs:ro,Z" -e DEBIAN_FRONTEND=noninteractive \
    "docker.io/library/ubuntu:$release" bash -euc '
        fail() { echo "FAIL: $*"; exit 1; }
        apt-get update -qq
        apt-get install -qq -y --no-install-recommends seahorse openpgp-applet >/dev/null
        dpkg -s seahorse >/dev/null || fail "seahorse did not install"

        apt-get install -qq -y --no-install-recommends /debs/landhorse_*.deb >/dev/null
        echo "--- after installing landhorse"
        if dpkg -s seahorse 2>/dev/null | grep -q "^Status: install ok installed"; then fail "seahorse still installed"; fi
        echo "ok: seahorse was replaced"
        dpkg -s openpgp-applet | grep -q "^Status: install ok installed" || fail "openpgp-applet was removed"
        echo "ok: openpgp-applet (Depends: seahorse) is still installed"
        apt-get check >/dev/null || fail "apt reports broken dependencies"
        echo "ok: apt-get check passes"

        [ "$(readlink -f /usr/bin/seahorse)" = /usr/bin/landhorse ] || fail "/usr/bin/seahorse is not landhorse"
        seahorse --version | grep -q . || fail "seahorse --version printed nothing"
        echo "ok: seahorse command runs landhorse $(landhorse --version)"
        apt-get install -qq -y --no-install-recommends libglib2.0-bin >/dev/null
        gsettings get org.gnome.seahorse server-auto-retrieve | grep -q false || fail "org.gnome.seahorse schema missing"
        echo "ok: org.gnome.seahorse schema is installed"
        [ -f /usr/share/applications/org.gnome.seahorse.Application.desktop ] || fail "compat desktop entry missing"
        echo "ok: org.gnome.seahorse.Application.desktop present"

        sim=$(apt-get install -s --no-install-recommends gnome-core 2>&1 || true)
        if echo "$sim" | grep -q "^Inst seahorse "; then fail "installing gnome-core would bring seahorse back"; fi
        echo "ok: gnome-core resolves seahorse to landhorse ($(echo "$sim" | grep -c "^Inst ") packages to install, none of them seahorse)"
        sim=$(apt-get install -s --no-install-recommends gnome 2>&1 || true)
        if echo "$sim" | grep -q "^Inst seahorse "; then fail "installing gnome would bring seahorse back"; fi
        echo "$sim" | grep -q "^Inst gnome " || fail "gnome could not be resolved: $(echo "$sim" | tail -3)"
        echo "ok: gnome (Depends: seahorse >= 3.36) is satisfied by landhorse"
    '
