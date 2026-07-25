import SwiftUI

struct ScanView: View {
    @State private var showingApproval = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x6) {
                MnSectionHeading(
                    "Scanner design",
                    orientation: "This placeholder shows the intended QR acquisition area. It does not access the camera in this unvalidated source build."
                )

                ZStack {
                    RoundedRectangle(cornerRadius: MnRadius.large)
                        .fill(MnColor.textPrimary)
                        .aspectRatio(1, contentMode: .fit)
                    Image(systemName: "qrcode.viewfinder")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 112, height: 112)
                        .foregroundStyle(MnColor.onBrand)
                        .accessibilityHidden(true)
                    Text("Camera preview")
                        .font(.caption)
                        .foregroundStyle(MnColor.onBrand)
                        .frame(maxHeight: .infinity, alignment: .bottom)
                        .padding(MnSpacing.x4)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Scanner design placeholder")

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x2) {
                        MnStatusLabel(text: "Camera integration not validated", kind: .warning)
                        Text("This source build does not claim a working scanner. Camera frames will not be saved when native validation is complete.")
                            .font(.footnote)
                    }
                }

                MnPrimaryButton("View approval design example", systemImage: "doc.text.magnifyingglass") {
                    showingApproval = true
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle("Scan")
        .sheet(isPresented: $showingApproval) {
            ApprovalView(request: DemonstrationData.approval)
        }
        .mnScreenBackground()
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
