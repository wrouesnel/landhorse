#!/bin/bash
# build.sh FEDORA_VERSION - build landhorse's source and binary RPMs for a Fedora release.
#
# The source tarball is assembled from the working tree (tracked files, plus untracked files
# that aren't ignored) with the Go modules vendored, and the spec is generated from
# packaging/rpm/landhorse.spec.in with the version from debian/changelog. Both are built in a
# container of that Fedora release, which also runs the tests and rpmlint. Results land in
# dist/rpm/fedora-VERSION/; the source RPM there is what COPR builds. With SRPM_ONLY=1 only
# the source RPM is built.
set -euo pipefail

RELEASES=(43 44)

fedora=${1:?usage: build.sh FEDORA_VERSION (one of: ${RELEASES[*]})}
[[ " ${RELEASES[*]} " == *" $fedora "* ]] || { echo "unknown Fedora release $fedora; known: ${RELEASES[*]}" >&2; exit 1; }

root=$(git rev-parse --show-toplevel)
cd "$root"
version=$(sed -n '1s/.*(\(.*\)).*/\1/p' debian/changelog)
out="$root/dist/rpm/fedora-$fedora"
stage="$out/stage/landhorse-$version"

rm -rf "$out"
mkdir -p "$stage"
git ls-files -z --cached --others --exclude-standard | xargs -0 cp --parents -P -t "$stage"
(cd "$stage" && GOFLAGS=-mod=mod go mod vendor && python3 tools/debian/gen-copyright.py)

# Bundled Go modules, as Fedora's packaging guidelines ask.
# RPM versions can't contain "-", so Go pseudo-versions use "~", as go-rpm-macros does.
# A replaced module ("path [version] => replacement version") is named by its replacement,
# whose code is what's vendored.
bundled=$(awk '/^# /{
        path = $2; v = $3
        for (i = 3; i < NF; i++) if ($i == "=>") { path = $(i+1); v = $(i+2) }
        sub(/^v/, "", v); gsub(/-/, "~", v)
        print "Provides:       bundled(golang(" path ")) = " v
    }' "$stage/vendor/modules.txt" | sort -u)
changelog="* $(date '+%a %b %d %Y') $(sed -n 's/^ -- \(.*>\).*/\1/p' debian/changelog | head -1) - $version-1
- Release $version."
python3 - "$root/packaging/rpm/landhorse.spec.in" "$out/landhorse.spec" "$version" "$bundled" "$changelog" <<'PY'
import sys
src, dst, version, bundled, changelog = sys.argv[1:]
spec = open(src).read().replace("@VERSION@", version).replace("@BUNDLED_PROVIDES@", bundled)
open(dst, "w").write(spec.replace("@CHANGELOG@", changelog))
PY
tar -C "$out/stage" -czf "$out/landhorse-$version.tar.gz" "landhorse-$version"
rm -rf "$out/stage"

podman run --rm -v "$out:/build:Z" -w /build -e SRPM_ONLY="${SRPM_ONLY:-}" \
    "registry.fedoraproject.org/fedora:$fedora" bash -euc '
    dnf -q -y install rpm-build rpmlint "dnf-command(builddep)" >/dev/null
    if [ -n "$SRPM_ONLY" ]; then
        rpmbuild --define "_topdir /build/rpmbuild" --define "_sourcedir /build" -bs landhorse.spec
        mv rpmbuild/SRPMS/*.src.rpm /build/
        rm -rf rpmbuild
        exit 0
    fi
    dnf -q -y builddep landhorse.spec >/dev/null
    rpmbuild --define "_topdir /build/rpmbuild" --define "_sourcedir /build" -ba landhorse.spec
    mv rpmbuild/SRPMS/*.src.rpm rpmbuild/RPMS/*/*.rpm /build/
    rm -rf rpmbuild
    rpmlint --info *.rpm || true
'
ls -1 "$out"/*.rpm
