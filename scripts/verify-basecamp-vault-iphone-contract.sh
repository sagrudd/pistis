#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
migration=$root/ios/PistisApp/Sources/Platform/BaseCampVaultMigrationV1.swift
successor=$root/ios/PistisApp/Sources/Platform/BaseCampVaultSuccessorRotationV1.swift
transport=$root/ios/PistisApp/Sources/Platform/BaseCampVaultMigrationTransportV1.swift
coordinator=$root/ios/PistisApp/Sources/App/BaseCampVaultMigrationCoordinatorV1.swift
scan=$root/ios/PistisApp/Sources/App/ScanAndApprovalViews.swift
ordinary=$root/ios/PistisApp/Sources/App/ProductionCeremonyCoordinator.swift
migration_tests=$root/ios/PistisApp/Tests/PlatformTests/BaseCampVaultMigrationV1Tests.swift
successor_tests=$root/ios/PistisApp/Tests/PlatformTests/BaseCampVaultSuccessorRotationV1Tests.swift
ui_tests=$root/ios/PistisApp/UITests/PistisUITests.swift
adr=$root/docs/adr/0042-basecamp-vault-migration-iphone-protocol.md
fixture=$root/fixtures/basecamp-vault-v1/contract.json
migration_vector=$root/fixtures/basecamp-vault-v1/migration-vector.json
successor_vector=$root/fixtures/basecamp-vault-v1/successor-vector.json

for file in "$migration" "$successor" "$transport" "$coordinator" "$scan" \
    "$ordinary" "$migration_tests" "$successor_tests" "$ui_tests" "$adr" "$fixture" \
    "$migration_vector" "$successor_vector"; do
    [ -f "$file" ] || {
        printf '%s\n' "basecamp iPhone contract: missing $file" >&2
        exit 1
    }
done

for vector in "$migration_vector" "$successor_vector"; do
    jq -e '
        .test_only == true
        and (.qr_json | type == "string" and length > 0)
        and (.presentation_json | type == "string" and length > 0)
        and (.submission_json | type == "string" and length > 0)
        and (.canonical_challenge_hex | type == "string" and length > 0)
        and (.signature_structure_hex | type == "string" and length > 0)
        and (.signature_raw_hex | type == "string" and length == 128)
        and (.old_ciphertext_hex | type == "string" and length == 120)
        and (.rewrapped_ciphertext_hex | type == "string" and length == 120)
        and .expected_submit_http_status == 204
    ' "$vector" >/dev/null || {
        printf '%s\n' "basecamp iPhone contract: incomplete test-only vector $vector" >&2
        exit 1
    }
done

verify_sha256() {
    expected=$1
    file=$2
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
    [ "$actual" = "$expected" ] || {
        printf '%s\n' "basecamp iPhone contract: vector digest drift for $file" >&2
        exit 1
    }
}
verify_sha256 d9de2ec82a1c3fec93134f06aa5e2b4345bb7575631feeee3eaf0d12d5e59773 \
    "$migration_vector"
verify_sha256 5bc90b25325a2f43229524325c12f41542e70034e18bc70fe357e63bf7e8cbd1 \
    "$successor_vector"

require() {
    needle=$1
    file=$2
    grep -F "$needle" "$file" >/dev/null || {
        printf '%s\n' "basecamp iPhone contract: missing '$needle' in $file" >&2
        exit 1
    }
}

require 'thesaurophylax.basecamp-vault-custody-provisioning.v1\0' "$migration"
require 'thesaurophylax.basecamp-vault-successor-rotation.v1\0' "$successor"
require 'basecamp-vault-passphrase-delivery-v1' "$migration"
require 'mnemosyne-expedition-basecamp.service' "$migration"
require '/run/mnemosyne-thesaurophylax/basecamp-vault-passphrase.sock' "$migration"
require 'expectedSiteTrustDomain: String,' "$migration"
require 'expectedDeviceKeyID: String,' "$migration"
require 'expectedSiteTrustDomain: String,' "$successor"
require 'expectedDeviceKeyID: String,' "$successor"
require 'addingReportingOverflow(1)' "$successor"

for constant in \
    'monas.basecamp-vault-migration-qr.v1' \
    'monas.basecamp-vault-migration-presentation.v1' \
    'monas.basecamp-vault-migration-submission.v1' \
    '/v1/pistis/basecamp-vault-migration/presentation' \
    '/v1/pistis/basecamp-vault-migration/submit' \
    'monas.basecamp-vault-successor-rotation-qr.v1' \
    'monas.basecamp-vault-successor-rotation-presentation.v1' \
    'monas.basecamp-vault-successor-rotation-submission.v1' \
    '/v1/pistis/basecamp-vault-unlock/presentation' \
    '/v1/pistis/basecamp-vault-unlock/submit'; do
    require "$constant" "$transport"
done
require '["schema", "purpose", "recipient", "presentation_path"]' "$transport"

if grep -F 'BaseCampVault' "$ordinary" >/dev/null; then
    printf '%s\n' 'basecamp iPhone contract: ordinary login references governed Base Camp' >&2
    exit 1
fi

require 'Approve migration with Face ID' "$scan"
require 'Approve successor with Face ID' "$scan"
require 'if phase == .completed { dismiss() }' "$scan"
require 'baseCampVaultMigration.phase != .completed' "$scan"
require 'baseCampVaultSuccessor.phase != .completed' "$scan"
if grep -E 'Button\("Done"\).*Base Camp|Base Camp.*Button\("Done"' "$scan" >/dev/null; then
    printf '%s\n' 'basecamp iPhone contract: governed completion regained redundant Done' >&2
    exit 1
fi

for test_name in \
    testCheckedInMigrationVectorIsExecutableByteForByte \
    testCrossProductFixturePinsBothCompleteRouteContracts \
    testAcceptedNineteenFieldMigrationVectorAndReview \
    testEveryTagPositionAndEveryFieldLengthAreCanonical \
    testStrictMigrationOuterCrossBindsPinnedSiteDeviceAndRevocation \
    testBaseCampTransportRejectsOriginAndSPKISubstitution \
    testSimulatorFullMigrationQRGetValidateProduceAndPostFlow \
    testCoordinatorRequiresExplicitReviewBeforeFaceIDApproval; do
    require "$test_name" "$migration_tests"
done
for test_name in \
    testCheckedInSuccessorVectorIsExecutableByteForByte \
    testAcceptedAuthoritativeEighteenFieldVector \
    testGenerationRepeatGapLeadingZeroAndOverflowDeny \
    testWrongLocalKeyRevocationCrossSiteAndFreshnessDeny \
    testProducerOpensUnderNAndRewrapsUnderExactlyNPlusOne \
    testQRIsExactNonBearerFourFieldDescriptor \
    testSimulatorFullSuccessorQRGetValidateProduceAndPostFlow \
    testSuccessorCoordinatorRequiresReviewAndLocalSiteRootBeforeApproval; do
    require "$test_name" "$successor_tests"
done
if grep -E 'testEmit(Migration|Successor)Vector|data\.write\(' \
    "$migration_tests" "$successor_tests" >/dev/null; then
    printf '%s\n' 'basecamp iPhone contract: release tests still author fixture artefacts' >&2
    exit 1
fi
require 'testBaseCampGovernedCeremoniesAreNotOrdinaryLoginAutoApproval' "$ui_tests"
require 'completion navigation that does not restart Scan' "$adr"

printf '%s\n' 'basecamp iPhone contract: PASS'
