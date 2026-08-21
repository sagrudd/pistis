#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
archive=${1:-"$root/build/Pistis.xcarchive"}

if [ "$(uname -s)" != Darwin ]; then
    echo "approved iPhone archive creation requires macOS and Xcode" >&2
    exit 69
fi

security find-identity -v -p codesigning 2>/dev/null \
    | grep -Fq 'Apple Distribution' || {
        echo "blocked: an Apple Distribution certificate is not installed for the authorised team" >&2
        echo "Install the reviewed distribution certificate and provisioning capability before archiving Pistis" >&2
        exit 69
    }

xcodebuild \
    -project "$root/ios/PistisApp/Pistis.xcodeproj" \
    -scheme Pistis \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "$archive" \
    -allowProvisioningUpdates \
    archive

"$script_dir/verify-approved-iphone-build.sh" \
    "$archive/Products/Applications/Pistis.app"
