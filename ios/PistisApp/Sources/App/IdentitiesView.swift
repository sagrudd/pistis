import SwiftUI

struct IdentitiesView: View {
    let identities: [IdentitySummary]
    let loadFailure: Bool
    let forgetExpired: (UUID) async throws -> Void
    @Binding var providerEnrolmentRequested: Bool
    let bindingAttemptID: UUID?
    let providerEnrolmentRouteID: UUID
    let openFreshEnrolment: () -> Void
    let clearBindingAttempt: () -> Void
    let scanReceiptQR: (ReceiptProvisionScanContext) -> Void

    var body: some View {
        ScrollView {
            LazyVStack(spacing: MnSpacing.x3) {
                MnSectionHeading(
                    "External identities",
                    orientation: "Review the accounts that establish who you are during enrolment."
                )
                .padding(.bottom, MnSpacing.x1)

                if loadFailure {
                    MnEmptyState(
                        title: "Identity record unavailable",
                        explanation: "Pistis could not safely read the protected enrolment record. Unlock this device and try again.",
                        actionTitle: nil
                    )
                } else if identities.isEmpty {
                    MnEmptyState(
                        title: "No enrolled identities",
                        explanation: "Provider enrolment requires a configured GitHub App and has not run on this device.",
                        actionTitle: nil
                    )
                }

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x3) {
                        MnStatusLabel(
                            text: "Protected first-device enrolment",
                            kind: .warning
                        )
                        Label(
                            "GitHub numeric account ID is the stable identity.",
                            systemImage: "person.text.rectangle"
                        )
                        Label(
                            "Provider credentials stay behind the authority boundary.",
                            systemImage: "lock.shield"
                        )
                        Text(
                            "Start with the plus button and scan the signed presentation created by the CLI. The phone never sends provider credentials to Pistis, Monas or Prosopikon."
                        )
                        .font(.footnote)
                    }
                }

                ForEach(IdentityAccountGroup.group(identities)) { account in
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            Text(account.title).font(.headline)
                            Text(account.githubAccountID.map { "GitHub account ID \($0)" } ?? "GitHub account ID not recorded")
                                .font(.caption)
                            ForEach(account.installations, id: \.installationID) { identity in
                                Divider()
                                NavigationLink(value: identity) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: MnSpacing.x2) {
                                            Text(identity.installationName).font(.subheadline)
                                            Text(identity.installationHost).font(.caption)
                                            MnStatusLabel(
                                                text: identity.status,
                                                kind: identity.status == "Enrolled" ? .success : .warning
                                            )
                                        }
                                        Spacer()
                                        Image(systemName: "chevron.right").accessibilityHidden(true)
                                    }
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle("Identities")
        .navigationDestination(for: IdentitySummary.self) { identity in
            IdentityDetailView(
                identity: identity,
                forgetExpired: forgetExpired
            )
        }
        .onChange(of: providerEnrolmentRequested) { _, shown in
            if !shown { clearBindingAttempt() }
        }
        .navigationDestination(isPresented: $providerEnrolmentRequested) {
            FirstDeviceEnrolmentView(bindingAttemptID: bindingAttemptID, scanReceiptQR: scanReceiptQR)
                .id(providerEnrolmentRouteID)
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: openFreshEnrolment) {
                    Label("Enrol first device", systemImage: "plus")
                        .frame(minWidth: MnMetrics.minimumTarget, minHeight: MnMetrics.minimumTarget)
                }
                .accessibilityHint("Scans a protected CLI enrolment presentation")
            }
        }
        .mnScreenBackground()
    }
}

private struct IdentityDetailView: View {
    let identity: IdentitySummary
    let forgetExpired: (UUID) async throws -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnStatusLabel(text: identity.status, kind: identity.status == "Enrolled" ? .success : .warning)
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        MnEvidenceRow(label: "Provider", value: identity.provider)
                        Divider()
                        MnEvidenceRow(label: "GitHub username", value: identity.displayName == "GitHub account" ? "Not recorded" : identity.displayName)
                        Divider()
                        MnEvidenceRow(label: "GitHub account ID", value: identity.githubAccountID.map(String.init) ?? "Not recorded")
                        Divider()
                        MnEvidenceRow(label: "Installation", value: identity.installationName)
                        Divider()
                        MnEvidenceRow(label: "Host", value: identity.installationHost)
                        Divider()
                        MnEvidenceRow(label: "Pistis identity", value: identity.stableSubject)
                        Divider()
                        MnEvidenceRow(
                            label: "Enrolment expires",
                            value: identity.expiresAt.formatted(date: .abbreviated, time: .shortened)
                        )
                    }
                }
                Text("GitHub usernames can change. Use the numeric account ID to identify the account. The expiry applies to this Pistis enrolment.")
                    .font(.footnote)
                    .foregroundStyle(MnColor.textPrimary)
                if identity.allowsLocalForget {
                    let isIncompatible = identity.status == "Re-enrolment required"
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnStatusLabel(text: "Local deletion only", kind: .warning)
                            Text(
                                isIncompatible
                                    ? "This older provider enrolment cannot authorise in the current app. Removing it deletes the phone’s local identity, trust and device key so you can re-enrol; authority-side revocation remains separate."
                                    : "This enrolment cannot authorise. Removing it deletes the identity, trust and device key stored on this phone."
                            )
                            DestructiveConfirmationButton(
                                label: isIncompatible
                                    ? "Remove local account"
                                    : "Remove local enrolment",
                                confirmationTitle: "Remove this local account?",
                                confirmationMessage:
                                    "Remove \(identity.displayName) from \(identity.installationName) (\(identity.installationHost)) on this phone? Other installations stay enrolled."
                            ) {
                                try await forgetExpired(identity.installationID)
                            }
                        }
                    }
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle(identity.displayName)
        .mnScreenBackground()
    }
}
