import SwiftUI

struct SettingsView: View {
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
                NavigationLink("Diagnostics") {
                    DiagnosticsView()
                }
                .frame(minHeight: MnMetrics.minimumTarget)
                NavigationLink("Privacy and legal") {
                    PrivacyView()
                }
                .frame(minHeight: MnMetrics.minimumTarget)
                NavigationLink("About Pistis") {
                    AboutView()
                }
                .frame(minHeight: MnMetrics.minimumTarget)
            }
        }
        .scrollContentBackground(.hidden)
        .navigationTitle("Settings")
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
                        Text("Local history is informational and is not an authoritative evidence store.")
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
                        MnEvidenceRow(label: "Version", value: "Development build")
                        Divider()
                        Text("Local-first cryptographic identity, authentication, approval, and evidence for scientific computing.")
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
