import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
import PistisCore

struct ScanView: View {
    @StateObject private var ceremony = ProductionCeremonyCoordinator()
    @StateObject private var siteRootCeremony = SiteRootDelegationCoordinator()
    @State private var scanning = true
    @State private var siteRootScanning = false
    @State private var scanFailure: PlatformFailure?
    @State private var siteRootScanFailure: PlatformFailure?
    @State private var readiness = PasswordlessReadiness.checking

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x6) {
                MnSectionHeading(
                    "Scan a Pistis request",
                    orientation: "Point the camera at a Pistis QR code. Captured frames are not saved."
                )

                ZStack {
                    RoundedRectangle(cornerRadius: MnRadius.large)
                        .fill(MnColor.textPrimary)
                        .aspectRatio(1, contentMode: .fit)
                    if scanning {
                        QRScannerCameraView(profile: .pistisAuthenticationV2, onResult: handleScan)
                            .clipShape(RoundedRectangle(cornerRadius: MnRadius.large))
                            .aspectRatio(1, contentMode: .fill)
                        Image(systemName: "viewfinder")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 160, height: 160)
                            .foregroundStyle(MnColor.onBrand)
                            .accessibilityHidden(true)
                    } else {
                        Image(systemName: "qrcode.viewfinder")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 112, height: 112)
                            .foregroundStyle(MnColor.onBrand)
                            .accessibilityHidden(true)
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(scanning ? "Scanning for a Pistis QR code" : "Pistis camera unavailable")

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x2) {
                        MnStatusLabel(
                            text: statusText,
                            kind: statusKind
                        )
                        Text("Only bounded PISTIS1 version-2 challenge text is accepted. Request facts appear only after the enrolled installation key verifies the exact signed payload.")
                            .font(.footnote)
                            .foregroundStyle(MnColor.textPrimary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        MnStatusLabel(
                            text: readiness.approvalEnabled
                                ? "Passwordless approval ready"
                                : "Passwordless approval unavailable",
                            kind: readiness.approvalEnabled ? .success : .warning
                        )
                        ForEach(readiness.items) { item in
                            ReadinessRow(item: item)
                        }
                        if !readiness.approvalEnabled {
                            Text("Approve remains disabled until every capability and trust check is ready.")
                                .font(.footnote.weight(.semibold))
                        }
                    }
                }

                if let scanFailure {
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnStatusLabel(text: "Scan failed", kind: .danger)
                            Text(scanFailure.safeUserMessage)
                            if scanFailure == .cameraPermissionDenied {
                                Button("Open Settings") { openCameraSettings() }
                                    .font(.headline)
                                    .frame(minHeight: MnMetrics.minimumTarget)
                            }
                        }
                    }
                }

                Divider()

                MnSectionHeading(
                    "Site Root delegation",
                    orientation: "Scan a separate Monas Site Root delegation. This does not alter the Pistis v2 approval scanner."
                )

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x3) {
                        MnStatusLabel(
                            text: siteRootStatusText,
                            kind: siteRootStatusKind
                        )
                        Text("Pistis displays only redacted delegation facts before Face ID signs the exact canonical Monas record. The phone never exports a private key or creates authority.")
                            .font(.footnote)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                if siteRootScanning {
                    QRScannerCameraView(profile: .monasSiteRootDelegationV1, onResult: handleSiteRootScan)
                        .clipShape(RoundedRectangle(cornerRadius: MnRadius.large))
                        .aspectRatio(1, contentMode: .fit)
                        .accessibilityLabel("Scanning for a Monas Site Root delegation")
                }

                if let siteRootScanFailure {
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnStatusLabel(text: "Site Root delegation unavailable", kind: .danger)
                            Text(siteRootScanFailure.safeUserMessage)
                            Button("Clear") { resetSiteRoot() }
                                .font(.headline)
                                .frame(minHeight: MnMetrics.minimumTarget)
                        }
                    }
                }

                MnPrimaryButton(
                    siteRootScanning ? "Stop Site Root scan" : "Scan Site Root delegation",
                    systemImage: siteRootScanning ? "stop.circle" : "qrcode.viewfinder"
                ) {
                    siteRootScanning ? stopSiteRootScanning() : startSiteRootScanning()
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle("Scan")
        .mnScreenBackground()
        .task { readiness = await PasswordlessReadinessProbe.current() }
        .onAppear { startScanning() }
        .onDisappear { stopScanning() }
        .sheet(item: reviewBinding) { request in
            ApprovalView(request: request, coordinator: ceremony)
        }
        .sheet(item: siteRootReviewBinding) { review in
            SiteRootDelegationReviewView(review: review, coordinator: siteRootCeremony)
        }
    }

    @MainActor
    private func handleScan(_ result: Result<ScannedQRPayload, PlatformFailure>) {
        scanning = false
        switch result {
        case let .success(payload):
            scanFailure = nil
            Task {
                await ceremony.accept(qrText: payload.text)
                if case let .failed(failure) = ceremony.phase {
                    scanFailure = failure
                }
            }
        case let .failure(failure):
            guard failure != .operationCancelled else { return }
            scanFailure = failure
        }
    }

    private func startScanning() {
        ceremony.reset()
        scanFailure = nil
        scanning = true
    }

    private func stopScanning() {
        scanning = false
    }

    private func openCameraSettings() {
#if canImport(UIKit)
        guard let settings = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(settings)
#endif
    }

    @MainActor
    private func handleSiteRootScan(_ result: Result<ScannedQRPayload, PlatformFailure>) {
        siteRootScanning = false
        switch result {
        case let .success(payload):
            siteRootScanFailure = nil
            siteRootCeremony.accept(qrText: payload.text)
            if case let .failed(failure) = siteRootCeremony.phase {
                siteRootScanFailure = failure
            }
        case let .failure(failure):
            guard failure != .operationCancelled else { return }
            siteRootScanFailure = failure
        }
    }

    private func startSiteRootScanning() {
        ceremony.reset()
        scanning = false
        resetSiteRoot()
        siteRootScanning = true
    }

    private func stopSiteRootScanning() {
        siteRootScanning = false
    }

    private func resetSiteRoot() {
        siteRootScanning = false
        siteRootScanFailure = nil
        siteRootCeremony.reset()
    }

    private var reviewBinding: Binding<ApprovalRequest?> {
        Binding {
            if case let .review(request) = ceremony.phase { request } else { nil }
        } set: { value in
            if value == nil { ceremony.reset() }
        }
    }

    private var siteRootReviewBinding: Binding<SiteRootDelegationReview?> {
        Binding {
            if case let .review(review) = siteRootCeremony.phase { review } else { nil }
        } set: { value in
            if value == nil { resetSiteRoot() }
        }
    }

    private var statusText: String {
        switch ceremony.phase {
        case .verifying: "Verifying enrolled installation"
        case .review: "Verified request ready for review"
        default: scanning ? "Camera active" : "Ready to scan"
        }
    }

    private var statusKind: MnStatusKind {
        switch ceremony.phase {
        case .review: .success
        case .verifying: .warning
        default: .neutral
        }
    }

    private var siteRootStatusText: String {
        switch siteRootCeremony.phase {
        case .review: "Delegation ready for redacted review"
        case .signing: "Awaiting Face ID"
        case let .submitted(receipt): receipt.accepted ? "Delegation submitted" : "Delegation not accepted"
        case .failed: "Delegation denied"
        case .idle: siteRootScanning ? "Camera active" : "Ready to scan a Monas delegation"
        }
    }

    private var siteRootStatusKind: MnStatusKind {
        switch siteRootCeremony.phase {
        case .review, .submitted: .success
        case .signing: .warning
        case .failed: .danger
        case .idle: .neutral
        }
    }
}

private struct ReadinessRow: View {
    let item: ReadinessItem

    var body: some View {
        HStack(alignment: .top, spacing: MnSpacing.x3) {
            Image(systemName: symbol)
                .foregroundStyle(color)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: MnSpacing.x1) {
                Text(item.title)
                    .font(.subheadline.weight(.semibold))
                Text(item.detail)
                    .font(.footnote)
                    .foregroundStyle(MnColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(item.title): \(stateLabel). \(item.detail)")
    }

    private var symbol: String {
        switch item.state {
        case .ready: "checkmark.circle.fill"
        case .actionRequired: "exclamationmark.circle.fill"
        case .unavailable: "xmark.octagon.fill"
        case .checking: "ellipsis.circle.fill"
        }
    }

    private var color: Color {
        switch item.state {
        case .ready: MnColor.success
        case .actionRequired: MnColor.warning
        case .unavailable: MnColor.danger
        case .checking: MnColor.textPrimary
        }
    }

    private var stateLabel: String {
        switch item.state {
        case .ready: "Ready"
        case .actionRequired: "Action required"
        case .unavailable: "Unavailable"
        case .checking: "Checking"
        }
    }
}

private struct SiteRootDelegationReviewView: View {
    let review: SiteRootDelegationReview
    @ObservedObject var coordinator: SiteRootDelegationCoordinator
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                    MnSectionHeading(
                        "Review Site Root delegation",
                        orientation: "Face ID signs one exact, short-lived Monas delegation. It does not grant authority on its own."
                    )

                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x4) {
                            MnEvidenceRow(label: "Delegation", value: review.reference, monospaced: true)
                            Divider()
                            MnEvidenceRow(label: "Device key", value: review.deviceKeyFingerprint, monospaced: true)
                            Divider()
                            MnEvidenceRow(label: "Monas destination", value: review.destination)
                        }
                    }

                    Text("Only redacted public facts are shown. Pistis will use the separate Secure Enclave Site Root key and will not export private material, use a software fallback, or claim Apple attestation.")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)

                    switch coordinator.phase {
                    case .review:
                        MnPrimaryButton("Sign with Face ID", systemImage: "faceid") {
                            Task { await coordinator.approve() }
                        }
                        Button("Deny") {
                            coordinator.reset()
                            dismiss()
                        }
                        .font(.headline)
                        .foregroundStyle(MnColor.danger)
                        .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
                    case .signing:
                        MnStatusLabel(text: "Waiting for Face ID", kind: .warning)
                    case let .submitted(receipt):
                        MnStatusLabel(
                            text: receipt.accepted ? "Monas accepted the proof" : "Monas did not accept the proof",
                            kind: receipt.accepted ? .success : .danger
                        )
                        MnPrimaryButton("Done") {
                            coordinator.reset()
                            dismiss()
                        }
                    case let .failed(failure):
                        MnStatusLabel(text: "Proof was not submitted", kind: .danger)
                        Text(failure.safeUserMessage)
                        MnPrimaryButton("Done") {
                            coordinator.reset()
                            dismiss()
                        }
                    case .idle:
                        EmptyView()
                    }
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Site Root")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        coordinator.reset()
                        dismiss()
                    }
                    .frame(minHeight: MnMetrics.minimumTarget)
                }
            }
            .mnScreenBackground()
        }
    }
}

struct ApprovalView: View {
    let request: ApprovalRequest
    @ObservedObject var coordinator: ProductionCeremonyCoordinator
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                    MnSectionHeading(request.action, orientation: request.subject)

                    MnStatusLabel(text: request.trustState, kind: .success)

                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x4) {
                            MnEvidenceRow(label: "Installation", value: request.installation)
                            Divider()
                            MnEvidenceRow(label: "Local user", value: request.localUser)
                            Divider()
                            MnEvidenceRow(label: "External identity", value: request.externalIdentity)
                            Divider()
                            MnEvidenceRow(
                                label: "Installation fingerprint",
                                value: request.fingerprint,
                                monospaced: true
                            )
                            Divider()
                            MnEvidenceRow(label: "Expires in", value: request.expiry)
                            Divider()
                            MnEvidenceRow(label: "Request route", value: request.route)
                        }
                    }

                    Text("Approving asks iOS to verify you before Pistis produces a device signature. Approval alone does not mean the installation accepted it.")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)

                    VStack(spacing: MnSpacing.x3) {
                        MnPrimaryButton("Approve and verify", systemImage: "checkmark.shield") {
                            Task { await coordinator.decide(.approved) }
                        }
                        Button("Deny") {
                            Task { await coordinator.decide(.denied) }
                        }
                        .font(.headline)
                        .foregroundStyle(MnColor.danger)
                        .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
                    }
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Review request")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .frame(minHeight: MnMetrics.minimumTarget)
                }
            }
            .sheet(item: resultBinding) { result in
                ApprovalResultView(result: result) {
                    coordinator.reset()
                    dismiss()
                }
            }
            .mnScreenBackground()
        }
    }

    private var resultBinding: Binding<ApprovalPresentation?> {
        Binding {
            switch coordinator.phase {
            case let .submitting(decision): .submitting(decision)
            case let .terminal(status): .terminal(status)
            case let .failed(failure): .failed(failure)
            default: nil
            }
        } set: { _ in }
    }
}

private enum ApprovalPresentation: Identifiable {
    case submitting(AuthenticationDecision)
    case terminal(AuthoritativeCeremonyStatus)
    case failed(PlatformFailure)

    var id: String {
        switch self {
        case let .submitting(decision): "submitting-\(decision.rawValue)"
        case let .terminal(status): "terminal-\(status.state.rawValue)"
        case .failed: "failed"
        }
    }
}

private struct ApprovalResultView: View {
    let result: ApprovalPresentation
    let done: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x6) {
                    MnSectionHeading(
                        title,
                        orientation: orientation
                    )
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x4) {
                            MnStatusLabel(
                                text: statusText,
                                kind: statusKind
                            )
                        }
                    }
                    if isTerminal {
                        MnPrimaryButton("Done", action: done)
                    } else {
                        ProgressView()
                            .accessibilityLabel("Waiting for the installation authority")
                    }
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Result")
            .navigationBarTitleDisplayMode(.inline)
            .mnScreenBackground()
        }
    }

    private var title: String {
        switch result {
        case .submitting: "Recording decision"
        case let .terminal(status): status.state == .completed
            ? "Authentication accepted" : "Authority result"
        case .failed: "Authentication failed"
        }
    }

    private var orientation: String {
        switch result {
        case .submitting:
            "Face ID, device signature, delivery, and authority verification are in progress."
        case let .terminal(status):
            "The installation authority returned \(status.state.rawValue)."
        case let .failed(failure):
            failure.safeUserMessage
        }
    }

    private var statusText: String {
        switch result {
        case let .submitting(decision): "Human decision: \(decision.rawValue)"
        case let .terminal(status): "Authority state: \(status.state.rawValue)"
        case .failed: "No authoritative completion was recorded"
        }
    }

    private var statusKind: MnStatusKind {
        switch result {
        case .submitting: .warning
        case let .terminal(status): status.state == .completed ? .success : .danger
        case .failed: .danger
        }
    }

    private var isTerminal: Bool {
        if case .submitting = result { false } else { true }
    }
}
