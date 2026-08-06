#!/bin/sh
# Validates the non-activating Monas-owned Pistis provider Debian boundary.
set -eu

usage() {
    echo "usage: $0 PACKAGE.deb" >&2
    exit 64
}

[ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ] || usage
command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required" >&2
    exit 69
}
command -v tar >/dev/null 2>&1 || {
    echo "tar is required" >&2
    exit 69
}

package=$1
package_name=$(dpkg-deb -f "$package" Package)
[ "$package_name" = monas ] || {
    echo "provider package must be named monas" >&2
    exit 65
}

contents=$(dpkg-deb -c "$package")
require_content() {
    printf '%s\n' "$contents" | grep -F -- " $1" >/dev/null || {
        echo "provider package is missing $1" >&2
        exit 65
    }
}
reject_content() {
    if printf '%s\n' "$contents" | grep -F -- "$1" >/dev/null; then
        echo "provider package must not ship $1" >&2
        exit 65
    fi
}

require_content './lib/systemd/system/monas-pistis.service'
require_content './usr/lib/tmpfiles.d/monas-pistis-runtime.conf'
reject_content 'jenkins-authority.sock'

unit=$(dpkg-deb --fsys-tarfile "$package" | tar -xOf - ./lib/systemd/system/monas-pistis.service)
tmpfiles=$(dpkg-deb --fsys-tarfile "$package" | tar -xOf - ./usr/lib/tmpfiles.d/monas-pistis-runtime.conf)
printf '%s\n' "$unit" | grep -Fx 'User=mnemosyne-monas' >/dev/null || {
    echo "provider unit must use mnemosyne-monas" >&2
    exit 65
}
printf '%s\n' "$unit" | grep -Fx 'SupplementaryGroups=mnemosyne-pistis-jenkins' >/dev/null || {
    echo "provider unit must use the Jenkins peer group" >&2
    exit 65
}
printf '%s\n' "$unit" | grep -Fx 'UMask=0007' >/dev/null || {
    echo "provider unit must set UMask=0007" >&2
    exit 65
}
printf '%s\n' "$unit" | grep -Fx 'ReadWritePaths=/var/lib/mnemosyne-monas /run/mnemosyne-pistis' >/dev/null || {
    echo "provider unit must restrict writable paths" >&2
    exit 65
}
printf '%s\n' "$tmpfiles" | grep -Fx 'd /run/mnemosyne-pistis 2770 mnemosyne-monas mnemosyne-pistis-jenkins -' >/dev/null || {
    echo "provider runtime directory policy is invalid" >&2
    exit 65
}

control=$(dpkg-deb --ctrl-tarfile "$package" | tar -xOf - ./postinst 2>/dev/null || true)
[ -n "$control" ] || {
    echo "provider package must have a non-activating postinst" >&2
    exit 65
}
if printf '%s\n' "$control" | grep -E '(^|[[:space:];])(systemctl|service)[[:space:]].*(enable|start|restart)|(^|[[:space:];])(enable|start|restart)[[:space:]]+monas-pistis' >/dev/null; then
    echo "provider package must not activate Monas" >&2
    exit 65
fi

printf '%s\n' 'Monas Pistis provider Debian boundary: pass'
