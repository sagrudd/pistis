#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
archive=${1:-"$root/build/Pistis.xcarchive"}
export_path=${2:-"$root/build/Pistis-adhoc"}
profile_name=pistis
bundle_id=org.mnemosynebiosciences.pistis
team_id=C7A6NQTSY4

if [ "$(uname -s)" != Darwin ]; then
    echo "approved iPhone IPA export requires macOS and Xcode" >&2
    exit 69
fi

[ -d "$archive/Products/Applications/Pistis.app" ] || {
    echo "usage: $0 /path/to/Pistis.xcarchive /path/to/export-directory" >&2
    exit 64
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
        if [ "$profile_app_id" = "$team_id.$bundle_id" ] \
            && security cms -D -i "$profile" 2>/dev/null \
                | plutil -extract ProvisionedDevices xml1 -o - - >/dev/null 2>&1; then
            profile_found=true
            break
        fi
    fi
done

[ "$profile_found" = true ] || {
    echo "blocked: the approved provisioning profile '$profile_name' is not installed" >&2
    exit 69
}

options=$(mktemp "${TMPDIR:-/tmp}/pistis-adhoc-export.XXXXXX.plist")
temporary_unpack=$(mktemp -d "${TMPDIR:-/tmp}/pistis-adhoc-ipa.XXXXXX")
trap 'rm -f "$options"; rm -rf "$temporary_unpack"' EXIT HUP INT TERM

cat >"$options" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>release-testing</string>
    <key>signingStyle</key>
    <string>manual</string>
    <key>teamID</key>
    <string>$team_id</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>$bundle_id</key>
        <string>$profile_name</string>
    </dict>
</dict>
</plist>
EOF

xcodebuild -exportArchive \
    -archivePath "$archive" \
    -exportPath "$export_path" \
    -exportOptionsPlist "$options"

ipa="$export_path/Pistis.ipa"
[ -f "$ipa" ] || {
    echo "export failed: Xcode did not produce $ipa" >&2
    exit 65
}

ditto -x -k "$ipa" "$temporary_unpack"
"$script_dir/verify-approved-iphone-build.sh" \
    "$temporary_unpack/Payload/Pistis.app"
printf '%s\n' "approved Pistis Ad Hoc IPA: $ipa"
