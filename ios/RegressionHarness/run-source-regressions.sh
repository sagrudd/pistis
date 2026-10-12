#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$root"
parent=ef00ff34efbb9cfeac9298c9c77f1dc9694162cd
test "$(git rev-parse "$parent^{tree}")" = 13857903766fc230de7b6f87f6f38122cd6945d6
test "$(git rev-parse "$parent:Cargo.lock")" = ca9e7b9adcb9e6640a0c63c9ce39f2bc111fd432
git merge-base --is-ancestor "$parent" HEAD
git diff --quiet "$parent" -- ios/PistisApp ios/PistisCore deny.toml .mnemosyne/expedition.json
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'Refusing source qualification from an uncommitted checkout' >&2
  exit 1
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
umask 077
private_tmp="$(mktemp -d /tmp/p.XXXXXXXX)"
trap 'rm -r "$private_tmp"' EXIT
export TMPDIR="$private_tmp"
echo "source_commit=$(git rev-parse HEAD) source_tree=$(git rev-parse 'HEAD^{tree}')"
echo "cargo_lock_blob=$(git rev-parse HEAD:Cargo.lock) cargo_lock_sha256=$(sha256sum Cargo.lock | cut -d' ' -f1)"
echo "simulator_recipe_sha256=$(sha256sum ios/RegressionHarness/recipe.json | cut -d' ' -f1)"
python3 ios/RegressionHarness/preflight.py | python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["ios_manifest"]["local_witness_matches"]; assert not v["qualifies_release"]; print("iOS release witness matches; no release qualification")'

cargo +1.94.0 test --locked -p pistis-qr
cargo +1.94.0 clippy --locked -p pistis-qr --all-targets -- -D warnings
cargo +1.94.0 test --workspace --all-features --locked
cargo +1.94.0 clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo +1.94.0 doc --workspace --all-features --locked --no-deps
cargo +1.94.0 build --locked -p pistis-qr --example ios_qr_roundtrip --example ios_qr_acquisition
cargo +1.94.0 audit --deny warnings
cargo +1.94.0 deny --locked --workspace --all-features check
swift test --package-path ios/RegressionHarness
swift test --package-path ios/PistisCore

for suite in self-test self-test-onboarding; do
  swift run --package-path ios/RegressionHarness pistis-ios-harness "$suite" \
    --qr-roundtrip "$CARGO_TARGET_DIR/debug/examples/ios_qr_roundtrip" |
    python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["expectationsMet"] and not v["milestoneComplete"]; assert not any(o["diagnostic"].get("genuineServiceReceipt", False) or o["diagnostic"].get("physicalDeviceEvidence", False) or o["diagnostic"].get("releaseAcceptance", False) for o in v["observations"]); print(v["schema"], len(v["observations"]), "source-only observations passed; milestone incomplete")'
done

cargo +1.90.0 test --locked -p pistis-qr
cargo +1.94.0 run --locked -p xtask -- architecture
cargo +1.94.0 run --locked -p xtask -- language
markdownlint-cli2 '**/*.md' '#target' '#.git' '#**/.build/**'
git diff --check
echo 'Source-only checks passed; no native/device, service, Expedition or release qualification'
