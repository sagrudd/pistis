#!/bin/sh
set -eu

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 ROOT_DER ROOT_GENERATION DERIVED_DATA_PATH AUTHORITY_ORIGIN [ALTERNATE_ORIGIN]" >&2
    exit 64
fi

root_der=$1
root_generation=$2
derived_data=$3
authority_origin=$4
alternate_origin=${5-}
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

validate_origin() {
    origin=$1
    [ -n "$origin" ] || return 0
    case "$origin" in
        https://*/*|https://*\?*|https://*\#*)
            echo "authority origins must be HTTPS origins without path, query, or fragment" >&2
            exit 65
            ;;
        https://*) ;;
        *)
            echo "authority origins must use HTTPS" >&2
            exit 65
            ;;
    esac
}

validate_origin "$authority_origin"
validate_origin "$alternate_origin"
[ "$authority_origin" != "$alternate_origin" ] || [ -z "$alternate_origin" ] || {
    echo "authority origins must be distinct" >&2
    exit 65
}

case "$root_generation" in
    ''|0|*[!0-9]*) echo "root generation must be a positive canonical integer" >&2; exit 65 ;;
esac
[ "${root_generation#0}" = "$root_generation" ] || {
    echo "root generation must be a positive canonical integer" >&2
    exit 65
}
[ -f "$root_der" ] && [ ! -L "$root_der" ] || {
    echo "root DER must be one regular non-symlink file" >&2
    exit 65
}
root_size=$(stat -f %z "$root_der")
[ "$root_size" -gt 0 ] && [ "$root_size" -le 65536 ] || {
    echo "root DER size is outside the accepted bound" >&2
    exit 65
}
/usr/bin/openssl x509 -inform DER -in "$root_der" -noout >/dev/null

root_b64url=$(/usr/bin/openssl base64 -A -in "$root_der" | tr '+/' '-_' | tr -d '=')
root_sha256_b64url=$(/usr/bin/openssl dgst -sha256 -binary "$root_der" |
    /usr/bin/openssl base64 -A | tr '+/' '-_' | tr -d '=')

exec /usr/bin/xcodebuild -quiet \
    -project "$project_root/Pistis.xcodeproj" \
    -scheme Pistis \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$derived_data" \
    -allowProvisioningUpdates \
    PISTIS_MONAS_SITE_ROOT_AUTHORITY_ORIGIN="$authority_origin" \
    PISTIS_MONAS_SITE_ROOT_AUTHORITY_ALTERNATE_ORIGIN="$alternate_origin" \
    PISTIS_MONAS_SITE_ROOT_AUTHORITY_TRUST_MODE='site-root-generation-v1' \
    PISTIS_MONAS_SITE_ROOT_AUTHORITY_SPKI_SHA256='' \
    PISTIS_MONAS_SITE_ROOT_AUTHORITY_ROOT_DER_B64URL="$root_b64url" \
    PISTIS_MONAS_SITE_ROOT_AUTHORITY_ROOT_SHA256_B64URL="$root_sha256_b64url" \
    PISTIS_MONAS_SITE_ROOT_AUTHORITY_ROOT_GENERATION="$root_generation" \
    build
