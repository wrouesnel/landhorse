#!/bin/bash
# build.sh SERIES - build landhorse's Ubuntu source and binary packages for SERIES.
#
# SERIES is an Ubuntu codename from the list below. The source tree is assembled from the
# working tree (tracked files, plus untracked files that aren't ignored), with the Go
# modules vendored and debian/copyright generated, and given a per-series version such as
# 0.1.0~ubuntu24.04.1. It is then built in a container of that release, which also runs
# the tests and lintian. Results land in release/deb/SERIES/.
#
# The source package is unsigned. To upload to a PPA:
#   debsign -k<fingerprint> release/deb/SERIES/*_source.changes
#   dput ppa:<you>/<ppa> release/deb/SERIES/*_source.changes
set -euo pipefail

declare -A RELEASES=([noble]=24.04 [resolute]=26.04)

series=${1:?usage: build.sh SERIES (one of: ${!RELEASES[*]})}
release=${RELEASES[$series]:-}
[ -n "$release" ] || { echo "unknown series $series; known: ${!RELEASES[*]}" >&2; exit 1; }

root=$(git rev-parse --show-toplevel)
cd "$root"
base=$(dpkg-parsechangelog -l debian/changelog -S Version 2>/dev/null || sed -n '1s/.*(\(.*\)).*/\1/p' debian/changelog)
version="${base}~ubuntu${release}.1"
out="$root/release/deb/$series"
src="$out/landhorse-$version"

rm -rf "$out"
mkdir -p "$src"
git ls-files -z --cached --others --exclude-standard | xargs -0 cp --parents -P -t "$src"
(cd "$src" && GOFLAGS=-mod=mod go mod vendor && python3 tools/debian/gen-copyright.py)

# Per-series changelog entry on top of the committed one.
{
    echo "landhorse ($version) $series; urgency=medium"
    echo
    echo "  * Build for Ubuntu $release."
    echo
    echo " -- $(sed -n 's/^ -- \(.*>\).*/\1/p' debian/changelog | head -1)  $(date -R)"
    echo
    cat debian/changelog
} > "$src/debian/changelog"

podman run --rm -v "$out:/build:Z" -w "/build/landhorse-$version" \
    -e DEBIAN_FRONTEND=noninteractive "docker.io/library/ubuntu:$release" bash -euc '
        apt-get update -qq
        apt-get install -qq -y --no-install-recommends dpkg-dev lintian >/dev/null
        apt-get build-dep -qq -y --no-install-recommends ./ >/dev/null
        dpkg-buildpackage -S -d -us -uc
        dpkg-buildpackage -b -us -uc
        cd /build
        lintian --info --display-info --no-tag-display-limit *.changes || true
    '
ls -1 "$out"/*.deb "$out"/*.dsc
