#!/bin/sh
# Contract fixtures for the Monas-owned Pistis provider package gate.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
validator="$root/deploy/deb/validate-monas-pistis-provider-deb.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/pistis-provider-deb.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required" >&2
    exit 69
}

build_fixture() {
    fixture=$1
    mutate=${2-}
    stage="$work/$fixture"
    mkdir -p "$stage/DEBIAN" "$stage/lib/systemd/system" "$stage/usr/lib/tmpfiles.d"
    printf '%s\n' \
        'Package: monas' \
        'Version: 0.0.1' \
        'Architecture: amd64' \
        'Maintainer: Mnemosyne Biosciences Ltd <support@mnemosyne.co.uk>' \
        'Description: fixture' > "$stage/DEBIAN/control"
    printf '%s\n' '#!/bin/sh' 'exit 0' > "$stage/DEBIAN/postinst"
    chmod 0755 "$stage/DEBIAN/postinst"
    printf '%s\n' \
        '[Service]' \
        'User=mnemosyne-monas' \
        'SupplementaryGroups=mnemosyne-pistis-jenkins' \
        'UMask=0007' \
        'ReadWritePaths=/var/lib/mnemosyne-monas /run/mnemosyne-pistis' > "$stage/lib/systemd/system/monas-pistis.service"
    printf '%s\n' 'd /run/mnemosyne-pistis 2770 mnemosyne-monas mnemosyne-pistis-jenkins -' > "$stage/usr/lib/tmpfiles.d/monas-pistis-runtime.conf"
    case "$mutate" in
        activation) printf '%s\n' 'systemctl start monas-pistis.service' >> "$stage/DEBIAN/postinst" ;;
        socket) : > "$stage/usr/lib/jenkins-authority.sock" ;;
        wrong-user) sed -i.bak 's/User=mnemosyne-monas/User=root/' "$stage/lib/systemd/system/monas-pistis.service"; rm "$stage/lib/systemd/system/monas-pistis.service.bak" ;;
        missing-unit) rm "$stage/lib/systemd/system/monas-pistis.service" ;;
        '') ;;
        *) exit 64 ;;
    esac
    dpkg-deb --build --root-owner-group "$stage" "$work/$fixture.deb" >/dev/null
}

build_fixture valid
"$validator" "$work/valid.deb"
for invalid in activation socket wrong-user missing-unit; do
    build_fixture "$invalid" "$invalid"
    if "$validator" "$work/$invalid.deb" >/dev/null 2>&1; then
        echo "invalid $invalid provider package was accepted" >&2
        exit 1
    fi
done
echo 'Monas Pistis provider Debian contract: pass'
