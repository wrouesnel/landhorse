#!/bin/bash
# install-test.sh FEDORA_VERSION - check that the built landhorse RPM replaces seahorse cleanly.
#
# In a fresh container of the release it installs seahorse, then landhorse from
# dist/rpm/fedora-VERSION/ (with --allowerasing, as landhorse conflicts with seahorse rather
# than obsoleting it), and checks that seahorse was removed, the seahorse command and schema
# still exist, landhorse provides "seahorse", and nemo-seahorse (which requires seahorse)
# resolves without bringing seahorse back.
set -euo pipefail

fedora=${1:?usage: install-test.sh FEDORA_VERSION}
out="$(git rev-parse --show-toplevel)/dist/rpm/fedora-$fedora"
ls "$out"/landhorse-[0-9]*.x86_64.rpm >/dev/null

podman run --rm -v "$out:/rpms:ro,Z" "registry.fedoraproject.org/fedora:$fedora" bash -euc '
    fail() { echo "FAIL: $*"; exit 1; }
    dnf -q -y install seahorse >/dev/null
    rpm -q seahorse >/dev/null || fail "seahorse did not install"

    rpm=$(ls /rpms/landhorse-[0-9]*.x86_64.rpm)
    dnf -q -y install --allowerasing "$rpm" >/dev/null
    echo "--- after installing landhorse"
    if rpm -q seahorse >/dev/null 2>&1; then fail "seahorse still installed"; fi
    echo "ok: seahorse was replaced"
    [ "$(rpm -q --whatprovides seahorse --qf "%{NAME}\n")" = landhorse ] || fail "nothing provides seahorse"
    echo "ok: landhorse provides seahorse"

    [ "$(readlink -f /usr/bin/seahorse)" = /usr/bin/landhorse ] || fail "/usr/bin/seahorse is not landhorse"
    seahorse --version | grep -q . || fail "seahorse --version printed nothing"
    echo "ok: seahorse command runs landhorse $(landhorse --version)"
    gsettings get org.gnome.seahorse server-auto-retrieve | grep -q false || fail "org.gnome.seahorse schema missing"
    echo "ok: org.gnome.seahorse schema is installed and compiled"

    if out=$(dnf -y install --assumeno nemo-seahorse 2>&1); then :; fi
    echo "$out" | grep -q "nemo-seahorse" || fail "nemo-seahorse did not resolve: $(echo "$out" | tail -3)"
    if echo "$out" | grep -E "^ +seahorse +" >/dev/null; then fail "installing nemo-seahorse would bring seahorse back"; fi
    echo "ok: nemo-seahorse (Requires: seahorse) is satisfied by landhorse"
'
