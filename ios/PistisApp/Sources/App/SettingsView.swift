import SwiftUI

struct SettingsView: View {
    let resetLocalDevice: () async throws -> Void
    let localResetCompleted: () -> Void

    init(
        resetLocalDevice: @escaping () async throws -> Void = {
            try await LocalDeviceResetService.shared.reset()
        },
        localResetCompleted: @escaping () -> Void = {}
    ) {
        self.resetLocalDevice = resetLocalDevice
        self.localResetCompleted = localResetCompleted
    }

    var body: some View {
        List {
            Section("Device security") {
                SettingsRow(
                    title: "Signing key",
                    detail: "Secure Enclave required",
                    status: "Requires real-device validation",
                    kind: .warning
                )
                SettingsRow(
                    title: "Local verification",
                    detail: "Biometric set required for each signature",
                    status: "Requires real-device validation",
                    kind: .warning
                )
            }

            Section("Application") {
                NavigationLink {
                    DiagnosticsView()
                } label: {
                    Text("Diagnostics")
                        .font(.body)
                }
                .frame(minHeight: MnMetrics.minimumTarget)
                NavigationLink {
                    PrivacyView()
                } label: {
                    Text("Privacy and legal")
                        .font(.body)
                }
                .frame(minHeight: MnMetrics.minimumTarget)
                NavigationLink {
                    AboutView()
                } label: {
                    Text("About Pistis")
                        .font(.body)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(minHeight: MnMetrics.minimumTarget)
            }

            Section {
                VStack(alignment: .leading, spacing: MnSpacing.x3) {
                    Text("Reset this iPhone")
                        .font(.headline)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.isHeader)
                    Text(
                        "Destructive local operation. It does not revoke server sessions or delete authority and audit records."
                    )
                    .font(.footnote)
                    .fixedSize(horizontal: false, vertical: true)
                    DestructiveConfirmationButton(
                        label: "Reset Pistis on this iPhone",
                        confirmationTitle: "Are you really sure?",
                        confirmationMessage:
                            "This permanently erases all Pistis identities and installations stored on this iPhone. Server sessions, authority records and audit evidence remain. Face ID is required, and the operation cannot be undone.",
                        confirmationLabel: "Reset identities and installations",
                        failureTitle: "Pistis reset is incomplete",
                        failureMessage:
                            "One or more local stores could not be erased. Pistis has not presented this iPhone as fresh. Keep the device unlocked and try again."
                    ) {
                        try await resetLocalDevice()
                        localResetCompleted()
                    }
                }
            }
        }
        .scrollContentBackground(.hidden)
        .navigationTitle("Settings")
        .toolbarBackground(MnColor.canvas, for: .navigationBar, .tabBar)
        .toolbarBackground(.visible, for: .navigationBar, .tabBar)
        .mnScreenBackground()
    }
}

private struct SettingsRow: View {
    let title: String
    let detail: String
    let status: String
    let kind: MnStatusKind

    var body: some View {
        VStack(alignment: .leading, spacing: MnSpacing.x2) {
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.subheadline)
            MnStatusLabel(text: status, kind: kind)
        }
        .padding(.vertical, MnSpacing.x2)
        .accessibilityElement(children: .combine)
    }
}

private struct DiagnosticsView: View {
    var body: some View {
        List {
            SettingsRow(
                title: "Protocol",
                detail: "Reference envelope",
                status: "Production interoperability not claimed",
                kind: .warning
            )
            SettingsRow(
                title: "Camera",
                detail: "Required for challenge scanning",
                status: "Permission not yet requested",
                kind: .neutral
            )
            SettingsRow(
                title: "Local transfer",
                detail: "QR response remains available",
                status: "Unavailable",
                kind: .warning
            )
        }
        .scrollContentBackground(.hidden)
        .navigationTitle("Diagnostics")
        .mnScreenBackground()
    }
}

private struct PrivacyView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnSectionHeading(
                    "Privacy and legal",
                    orientation: "Pistis keeps device signing keys on this device."
                )
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x3) {
                        Text("Camera frames are not retained.")
                        Text("Provider access tokens are not stored by the application.")
                        Text(
                            "Local history is informational and is not an authoritative evidence store."
                        )
                    }
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle("Privacy")
        .mnScreenBackground()
    }
}

private struct AboutView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnProvenance()
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x3) {
                        MnEvidenceRow(label: "Application", value: "Pistis")
                        Divider()
                        MnEvidenceRow(
                            label: "Version",
                            value: PistisBuildIdentity.display(
                                infoDictionary: Bundle.main.infoDictionary ?? [:]
                            )
                        )
                        Divider()
                        Text(
                            "Local-first cryptographic identity, authentication, approval, and evidence for scientific computing."
                        )
                        .font(.body)
                    }
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle("About")
        .mnScreenBackground()
    }
}

enum PistisBuildIdentity {
    static func display(infoDictionary: [String: Any]) -> String {
        guard let version = infoDictionary["CFBundleShortVersionString"] as? String,
            !version.isEmpty,
            let build = infoDictionary["CFBundleVersion"] as? String,
            !build.isEmpty
        else { return "Unknown build" }
        return "\(version) (\(build))"
    }
}
