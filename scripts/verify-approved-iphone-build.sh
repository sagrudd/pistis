#!/bin/sh

set -eu

app=${1:-}
expected_bundle_id=org.mnemosynebiosciences.pistis
expected_team_id=C7A6NQTSY4

if [ -z "$app" ] || [ ! -d "$app" ]; then
    echo "usage: $0 /path/to/Pistis.app" >&2
    exit 64
fi

if [ "$(uname -s)" != Darwin ]; then
    echo "approved iPhone build verification requires macOS codesign tools" >&2
    exit 69
fi

entitlements=$(mktemp "${TMPDIR:-/tmp}/pistis-entitlements.XXXXXX")
trap 'rm -f "$entitlements"' EXIT HUP INT TERM

codesign --verify --deep --strict "$app"
codesign -d --entitlements :- "$app" >"$entitlements" 2>/dev/null
details=$(codesign -dvvv "$app" 2>&1)

bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Info.plist")
team_id=$(printf '%s\n' "$details" | sed -n 's/^TeamIdentifier=//p' | head -n 1)
attest_environment=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.devicecheck.appattest-environment' "$entitlements" 2>/dev/null || true)
get_task_allow=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.get-task-allow' "$entitlements" 2>/dev/null || true)

[ "$bundle_id" = "$expected_bundle_id" ] || {
    echo "rejected: unexpected Pistis bundle identifier" >&2
    exit 65
}
[ "$team_id" = "$expected_team_id" ] || {
    echo "rejected: unexpected Apple development team" >&2
    exit 65
}
[ "$attest_environment" = production ] || {
    echo "rejected: App Attest production entitlement is absent" >&2
    exit 65
}
[ "$get_task_allow" != true ] || {
    echo "rejected: development get-task-allow entitlement is enabled" >&2
    exit 65
}
printf '%s\n' "$details" | grep -q '^Authority=Apple Distribution' || {
    echo "rejected: the app is not signed with Apple Distribution" >&2
    exit 65
}

printf '%s\n' "approved Pistis iPhone build: bundle=$bundle_id team=$team_id app-attest=$attest_environment distribution-signing=verified"
