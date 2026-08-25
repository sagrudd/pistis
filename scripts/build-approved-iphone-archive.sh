#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
archive=${1:-"$root/build/Pistis.xcarchive"}
profile_name=pistis

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

profile_dir="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
profile_found=false
for profile in "$profile_dir"/*.mobileprovision; do
    [ -f "$profile" ] || continue
    installed_name=$(security cms -D -i "$profile" 2>/dev/null \
        | plutil -extract Name raw -o - - 2>/dev/null || true)
    if [ "$installed_name" = "$profile_name" ]; then
        profile_app_id=$(security cms -D -i "$profile" 2>/dev/null \
            | plutil -extract Entitlements.application-identifier raw -o - - 2>/dev/null || true)
        if [ "$profile_app_id" = "C7A6NQTSY4.org.mnemosynebiosciences.pistis" ] \
            && security cms -D -i "$profile" 2>/dev/null \
                | plutil -extract ProvisionedDevices xml1 -o - - >/dev/null 2>&1; then
            profile_found=true
            break
        fi
    fi
done

[ "$profile_found" = true ] || {
    echo "blocked: the approved provisioning profile '$profile_name' is not installed" >&2
    echo "Install the reviewed Ad Hoc profile before archiving Pistis" >&2
    exit 69
}

xcodebuild \
    -project "$root/ios/PistisApp/Pistis.xcodeproj" \
    -scheme Pistis \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "$archive" \
    archive

"$script_dir/verify-approved-iphone-build.sh" \
    "$archive/Products/Applications/Pistis.app"
