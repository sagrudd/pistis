import SwiftUI

struct InstallationsView: View {
    let installations: [InstallationSummary]
    let loadFailure: Bool
    let forgetExpired: (UUID) async throws -> Void

    var body: some View {
        List(installations) { installation in
            NavigationLink {
                InstallationDetailView(
                    installation: installation,
                    forgetExpired: forgetExpired
                )
            } label: {
                VStack(alignment: .leading, spacing: MnSpacing.x2) {
                    Text(installation.name)
                        .font(.headline)
                    Text(installation.localAlias)
                        .font(.subheadline)
                    MnStatusLabel(
                        text: installation.status,
                        kind: installation.status == "Trusted" ? .success : .warning
                    )
                        Text("Last used \(installation.lastUsed)")
                            .font(.caption)
                            .foregroundStyle(MnColor.textPrimary)
                }
                .padding(.vertical, MnSpacing.x2)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                "\(installation.name), \(installation.status), last used \(installation.lastUsed)"
            )
            .accessibilityHint("Shows installation trust evidence")
            .listRowBackground(MnColor.raised)
        }
        .scrollContentBackground(.hidden)
        .navigationTitle("Installations")
        .safeAreaInset(edge: .top) {
            Text("Remembered installations and the trust material you reviewed.")
                .font(.subheadline)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, MnMetrics.screenGutter)
                .padding(.vertical, MnSpacing.x2)
                .background(MnColor.canvas)
        }
        .overlay {
            if loadFailure {
                MnEmptyState(
                    title: "Installation record unavailable",
                    explanation: "Pistis could not safely read the protected enrolment record. Unlock this device and try again.",
                    actionTitle: nil
                )
                .padding(MnMetrics.screenGutter)
            } else if installations.isEmpty {
                MnEmptyState(
                    title: "No paired installations",
                    explanation: "A verified pairing will record the installation and fingerprint here.",
                    actionTitle: nil
                )
                .padding(MnMetrics.screenGutter)
            }
        }
        .mnScreenBackground()
    }
}

private struct InstallationDetailView: View {
    let installation: InstallationSummary
    let forgetExpired: (UUID) async throws -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnStatusLabel(
                    text: installation.status,
                    kind: installation.status == "Trusted" ? .success : .warning
                )
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        MnEvidenceRow(label: "Alias", value: installation.localAlias)
                        Divider()
                        MnEvidenceRow(
                            label: "Public fingerprint",
                            value: installation.fingerprint,
                            monospaced: true
                        )
                        Divider()
                        MnEvidenceRow(label: "Last used", value: installation.lastUsed)
                    }
                }
                if installation.status != "Trusted" {
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x2) {
                            MnStatusLabel(text: "Trust material requires review", kind: .warning)
                            Text("Do not approve requests until you have compared the new fingerprint with the installation.")
                        }
                    }
                }
                if installation.allowsLocalForget {
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnStatusLabel(text: "Local deletion only", kind: .warning)
                            Text(
                                "This expired record cannot authorise. Forgetting it removes this phone’s cached trust and device key; it does not delete authority audit history or change server state."
                            )
                            DestructiveConfirmationSlider(
                                label: "Slide to forget this expired installation",
                                confirmationLabel: "Confirm forget local record"
                            ) {
                                try await forgetExpired(installation.id)
                            }
                        }
                    }
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle(installation.name)
        .mnScreenBackground()
    }
}
