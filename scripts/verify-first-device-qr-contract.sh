#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_text() {
    local path="$1"
    local text="$2"
    if ! rg --fixed-strings --line-number -- "$text" "$root_dir/$path" >/dev/null; then
        printf 'first-device QR contract missing: %s in %s\n' "$text" "$path" >&2
        exit 1
    fi
}

# The initial Monas Site Root gate is intentionally a distinct, fixed JSON
# family. It is not an authentication credential and must be routed to the
# Site Root coordinator rather than rejected by the ordinary Pistis parser.
require_text ios/PistisApp/Sources/Platform/QRScannerAdapter.swift 'case pistisAuthenticationOrMonasSiteRoot'
require_text ios/PistisApp/Sources/Platform/QRScannerAdapter.swift 'text.hasPrefix("PISTIS1:") || text.hasPrefix("{")'
require_text ios/PistisApp/Sources/App/ScanAndApprovalViews.swift 'profile: .pistisAuthenticationOrMonasSiteRoot'
require_text ios/PistisApp/Sources/App/ScanAndApprovalViews.swift 'siteRootCeremony.accept(qrText: payload.text)'
require_text ios/PistisApp/Sources/Platform/SiteRootGenesisRegistration.swift 'monas.site-root-genesis-registration-presentation.v1'

# The post-Site-Root identity ceremony must remain a signed Pistis transport
# and must never regress to raw JSON or an unvalidated browser URL.
require_text ios/PistisCore/Sources/PistisCore/FirstDevicePresentation.swift 'text.hasPrefix("PISTIS1:")'
require_text ios/PistisCore/Sources/PistisCore/FirstDevicePresentation.swift 'pistis.first-device-presentation.v3'
require_text ios/PistisApp/Sources/App/FirstDeviceEnrolmentView.swift 'FirstDevicePresentationV4.verify'

printf 'first-device QR contract: OK\n'
