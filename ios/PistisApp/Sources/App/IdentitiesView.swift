import SwiftUI

struct IdentitiesView: View {
    let identities: [IdentitySummary]
    let loadFailure: Bool
    let forgetExpired: (UUID) async throws -> Void

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

                ForEach(identities) { identity in
                    NavigationLink(value: identity) {
                        MnPanel {
                            HStack(alignment: .top, spacing: MnSpacing.x3) {
                                Image(systemName: identity.provider == "GitHub" ? "chevron.left.forwardslash.chevron.right" : "person.crop.circle")
                                    .font(.title2)
                                    .foregroundStyle(MnColor.action)
                                    .frame(width: MnMetrics.minimumTarget, height: MnMetrics.minimumTarget)
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: MnSpacing.x2) {
                                    Text(identity.displayName)
                                        .font(.headline)
                                    Text(identity.provider)
                                        .font(.subheadline)
                                    Text(identity.stableSubject)
                                        .font(.caption)
                                        .foregroundStyle(MnColor.textPrimary)
                                    MnStatusLabel(text: identity.status, kind: .success)
                                }
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .foregroundStyle(.secondary)
                                    .accessibilityHidden(true)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("\(identity.provider), \(identity.displayName), \(identity.status)")
                    .accessibilityHint("Shows identity evidence")
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
        .navigationDestination(for: FirstDeviceEnrolmentRoute.self) { _ in
            FirstDeviceEnrolmentView()
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink(value: FirstDeviceEnrolmentRoute()) {
                    Label("Enrol first device", systemImage: "plus")
                        .frame(minWidth: MnMetrics.minimumTarget, minHeight: MnMetrics.minimumTarget)
                }
                .accessibilityHint("Scans a protected CLI enrolment presentation")
            }
        }
        .mnScreenBackground()
    }
}

private struct FirstDeviceEnrolmentRoute: Hashable {}

private struct IdentityDetailView: View {
    let identity: IdentitySummary
    let forgetExpired: (UUID) async throws -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnStatusLabel(text: identity.status, kind: .success)
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        MnEvidenceRow(label: "Provider", value: identity.provider)
                        Divider()
                        MnEvidenceRow(label: "Display name", value: identity.displayName)
                        Divider()
                        MnEvidenceRow(label: "Stable provider identity", value: identity.stableSubject)
                    }
                }
                Text("Provider display names may change. Pistis binds the stable provider identity shown above.")
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
                                    : "This expired provider account cannot authorise. Forgetting it removes this phone’s cached identity, trust and device key; it does not delete authority audit history or change server state."
                            )
                            DestructiveConfirmationButton(
                                label: isIncompatible
                                    ? "Remove local account"
                                    : "Remove expired local account",
                                confirmationTitle: "Remove this local account?",
                                confirmationMessage:
                                    "This removes only the account, trust and device key stored on this phone. Authority records and server sessions are unchanged."
                            ) {
                                try await forgetExpired(identity.id)
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
