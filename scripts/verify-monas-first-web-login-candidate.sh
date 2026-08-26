#!/bin/sh
set -eu

usage() {
    printf '%s\n' "usage: $0 IPHONE_SIMULATOR_UDID [EVIDENCE_DIRECTORY]" >&2
    exit 64
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
simulator_id=$1
evidence_dir=${2:-}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runbook=$root/docs/operations/monas-first-web-login-runbook.md
project=$root/ios/PistisApp/Pistis.xcodeproj

[ -f "$runbook" ] || { printf '%s\n' "candidate gate: runbook missing" >&2; exit 1; }
[ -d "$project" ] || { printf '%s\n' "candidate gate: Xcode project missing" >&2; exit 1; }

branch=$(git -C "$root" symbolic-ref --quiet --short HEAD || true)
[ "$branch" = main ] || {
    printf '%s\n' "candidate gate: formal verification must run from merged main" >&2
    exit 1
}
[ -z "$(git -C "$root" status --short)" ] || {
    printf '%s\n' "candidate gate: formal verification requires a clean checkout" >&2
    exit 1
}

for gate in 0 1 2 3 4 5 6 7 8 9 10 11; do
    count=$(grep -Ec "^## Gate ${gate}( | —)" "$runbook")
    [ "$count" -eq 1 ] || {
        printf '%s\n' "candidate gate: Gate $gate is missing or duplicated in the runbook" >&2
        exit 1
    }
done

device_state=$(xcrun simctl list devices available | grep -F "$simulator_id" || true)
[ -n "$device_state" ] || {
    printf '%s\n' "candidate gate: iPhone Simulator $simulator_id is unavailable" >&2
    exit 1
}

if [ -n "$evidence_dir" ]; then
    mkdir -p "$evidence_dir"
    core_log=$evidence_dir/pistis-core-tests.log
    xcode_result=$evidence_dir/pistis-monas-first-web-login.xcresult
    test -e "$xcode_result" && {
        printf '%s\n' "candidate gate: refusing to replace $xcode_result" >&2
        exit 1
    }
else
    core_log=/dev/null
    xcode_result=
fi

printf '%s\n' "candidate checkpoint: complete Gate 0-11 runbook present"
if [ "$core_log" = /dev/null ]; then
    swift test --package-path "$root/ios/PistisCore"
else
    swift test --package-path "$root/ios/PistisCore" 2>&1 | tee "$core_log"
fi
printf '%s\n' "candidate checkpoint: PistisCore protocol suite passed"

set -- xcodebuild test -quiet \
    -project "$project" \
    -scheme Pistis \
    -destination "platform=iOS Simulator,id=$simulator_id" \
    -only-testing:PistisTests \
    -only-testing:PistisUITests \
    CODE_SIGNING_ALLOWED=NO
if [ -n "$xcode_result" ]; then
    set -- "$@" -resultBundlePath "$xcode_result"
fi
"$@"

printf '%s\n' "candidate checkpoint: complete iPhone Simulator test suite passed"
printf '%s\n' "candidate checkpoint: physical Face ID, Secure Enclave and App Attest remain unclaimed"
printf '%s\n' "candidate result: PASS"
