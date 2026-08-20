#!/bin/sh
set -eu

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [DERIVED_DATA_PATH]" >&2
    exit 64
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
derived_data=${1:-"$project_root/.derived-data/release"}

# Host origin, TLS pins, Site Root certificates, and installation identity are
# runtime ceremony data. They must never be supplied as build arguments.
exec /usr/bin/xcodebuild -quiet \
    -project "$project_root/Pistis.xcodeproj" \
    -scheme Pistis \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$derived_data" \
    -allowProvisioningUpdates \
    build
