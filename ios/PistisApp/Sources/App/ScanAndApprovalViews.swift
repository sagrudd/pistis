import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
import PistisCore

struct ScanView: View {
    @StateObject private var ceremony = ProductionCeremonyCoordinator()
    @StateObject private var siteRootCeremony = SiteRootDelegationCoordinator()
    @State private var scanning = true
    @State private var scanFailure: PlatformFailure?
    @State private var readiness = PasswordlessReadiness.checking

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x6) {
                MnSectionHeading(
                    "Scan a Pistis or Monas request",
                    orientation: "Point the camera at a supported QR code. Captured frames are not saved."
                )

                ZStack {
                    RoundedRectangle(cornerRadius: MnRadius.large)
                        .fill(MnColor.textPrimary)
                        .aspectRatio(1, contentMode: .fit)
                    if scanning {
                        QRScannerCameraView(
                            profile: .pistisAuthenticationOrMonasSiteRoot,
                            onResult: handleScan
                        )
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
                .accessibilityLabel(scanning ? "Scanning for a supported QR code" : "Pistis camera unavailable")

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x2) {
                        MnStatusLabel(
                            text: statusText,
                            kind: statusKind
                        )
                        Text("Only bounded Pistis v2 and Monas Site Root v1 envelopes are acquired. Each reaches its own mandatory protocol validator before facts are shown.")
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
            if payload.text.hasPrefix("{") {
                siteRootCeremony.accept(qrText: payload.text)
                if case let .failed(failure) = siteRootCeremony.phase {
                    scanFailure = failure
                }
                return
            }
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

    private func resetSiteRoot() {
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
            if value == nil {
                resetSiteRoot()
                startScanning()
            }
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
                    case .attesting:
                        MnStatusLabel(text: "Submitting device assertion", kind: .warning)
                    case .submitted:
                        MnStatusLabel(
                            text: "Device assertion submitted to Monas",
                            kind: .success
                        )
                        Text("Monas must still verify and retain the assertion before it can issue a session.")
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
