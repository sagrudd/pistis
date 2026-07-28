import SwiftUI

struct ScanView: View {
    @State private var scanning = false
    @State private var scanFailure: PlatformFailure?
    @State private var capturedFrame = false
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
                        QRScannerCameraView(onResult: handleScan)
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
                .accessibilityLabel(scanning ? "Camera scanning for a Pistis QR code" : "QR scanner stopped")

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x2) {
                        MnStatusLabel(
                            text: capturedFrame
                                ? "Code captured; verification unavailable"
                                : (scanning ? "Camera active" : "Ready to scan"),
                            kind: capturedFrame ? .warning : .neutral
                        )
                        Text(
                            capturedFrame
                                ? "Pistis discarded the unverified frame. Production challenge verification is not yet enabled, so no approval can be shown or signed."
                                : "Only bounded PISTIS1 text is accepted. A scan is never treated as trusted until the production protocol verifier accepts it."
                        )
                            .font(.footnote)
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
                            Button("Try again") { startScanning() }
                                .font(.headline)
                                .frame(minHeight: MnMetrics.minimumTarget)
                        }
                    }
                }

                MnPrimaryButton(
                    scanning ? "Stop scanning" : "Start camera",
                    systemImage: scanning ? "stop.circle" : "camera.viewfinder"
                ) {
                    scanning ? stopScanning() : startScanning()
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle("Scan")
        .mnScreenBackground()
        .task { readiness = PasswordlessReadinessProbe.current() }
    }

    @MainActor
    private func handleScan(_ result: Result<ScannedQRPayload, PlatformFailure>) {
        scanning = false
        switch result {
        case .success:
            capturedFrame = true
            scanFailure = nil
        case let .failure(failure):
            guard failure != .operationCancelled else { return }
            capturedFrame = false
            scanFailure = failure
        }
    }

    private func startScanning() {
        capturedFrame = false
        scanFailure = nil
        scanning = true
    }

    private func stopScanning() {
        scanning = false
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

struct ApprovalView: View {
    let request: ApprovalRequest
    @Environment(\.dismiss) private var dismiss
    @State private var result: ApprovalResult?

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
                            result = .unavailable
                        }
                        Button("Deny") {
                            result = .denied
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
            .sheet(item: $result) { result in
                ApprovalResultView(result: result) {
                    self.result = nil
                    dismiss()
                }
            }
            .mnScreenBackground()
        }
    }
}

private enum ApprovalResult: String, Identifiable {
    case unavailable
    case denied

    var id: String { rawValue }
}

private struct ApprovalResultView: View {
    let result: ApprovalResult
    let done: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x6) {
                    MnSectionHeading(
                        result == .unavailable ? "Approval unavailable" : "Request denied",
                        orientation: result == .unavailable
                            ? "This development source cannot produce a production mobile envelope."
                            : "No device signature was produced."
                    )
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x4) {
                            MnStatusLabel(
                                text: result == .unavailable ? "Human decision: Not recorded" : "Human decision: Denied",
                                kind: result == .unavailable ? .warning : .danger
                            )
                            MnStatusLabel(
                                text: "Device signature: Not produced",
                                kind: .neutral
                            )
                            MnStatusLabel(
                                text: "Transfer: Not attempted",
                                kind: .neutral
                            )
                            MnStatusLabel(
                                text: "Server verification: Not applicable",
                                kind: .neutral
                            )
                        }
                    }
                    MnPrimaryButton("Done", action: done)
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Result")
            .navigationBarTitleDisplayMode(.inline)
            .mnScreenBackground()
        }
    }
}
