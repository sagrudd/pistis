import SwiftUI

enum InstallationDetailAction: Equatable {
    case continueAuthorityCustody
    case reconcileAuthorityCustody
    case continueIdentitySetup
    case none

    init(installation: InstallationSummary) {
        if installation.status == "Trusted" {
            self = .reconcileAuthorityCustody
            return
        }
        guard installation.status == "Setup in progress" else {
            self = .none
            return
        }
    self =
      installation.setupPhase == .identityEnrolmentRequired
            ? .continueIdentitySetup : .continueAuthorityCustody
    }
}

struct InstallationsView: View {
    let installations: [InstallationSummary]
    let loadFailure: Bool
    let forgetExpired: (UUID) async throws -> Void
    let recoverSiteRootInstallation: () -> Void
    let reconciliationMessage: String?
    let authorityCustodyBusy: Bool
    let startProviderEnrolment: () -> Void
    let continueAuthorityCustody: (InstallationSummary) -> Void
    let selectInstallation: (UUID) async throws -> Void

    var body: some View {
        List(installations) { installation in
            NavigationLink {
                InstallationDetailView(
                    installation: installation,
          reconciliationMessage: reconciliationMessage,
          authorityCustodyBusy: authorityCustodyBusy,
                    forgetExpired: forgetExpired,
                    startProviderEnrolment: startProviderEnrolment,
                    continueAuthorityCustody: continueAuthorityCustody,
                    selectInstallation: selectInstallation
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
          explanation:
            "Pistis could not safely read the protected enrolment record. Unlock this device and try again.",
                    actionTitle: nil
                )
                .padding(MnMetrics.screenGutter)
            } else if installations.isEmpty {
                MnEmptyState(
                    title: "No paired installations",
          explanation: reconciliationMessage
            ?? "A verified pairing will record the installation and fingerprint here.",
                    actionTitle: "Recover Site Root setup",
                    action: recoverSiteRootInstallation
                )
                .padding(MnMetrics.screenGutter)
            }
        }
        .mnScreenBackground()
    }
}

private struct InstallationDetailView: View {
    let installation: InstallationSummary
  let reconciliationMessage: String?
  let authorityCustodyBusy: Bool
    let forgetExpired: (UUID) async throws -> Void
    let startProviderEnrolment: () -> Void
    let continueAuthorityCustody: (InstallationSummary) -> Void
    let selectInstallation: (UUID) async throws -> Void

    private var action: InstallationDetailAction {
        InstallationDetailAction(installation: installation)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnStatusLabel(
                    text: installation.status,
                    kind: installation.status == "Trusted" ? .success : .warning
                )
        if let reconciliationMessage {
          MnPanel {
            Text(reconciliationMessage)
              .accessibilityLabel("Authority custody status: \(reconciliationMessage)")
          }
        }
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        MnEvidenceRow(label: "Alias", value: installation.localAlias)
                        Divider()
                        MnEvidenceRow(
                            label: installation.evidenceLabel,
                            value: installation.fingerprint,
                            monospaced: true
                        )
                        Divider()
                        MnEvidenceRow(label: "Last used", value: installation.lastUsed)
                    }
                }
                if action != .none {
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x2) {
                            MnStatusLabel(
                                text: action == .continueIdentitySetup
                                    ? "Next: enrol your identity"
                                    : action == .continueAuthorityCustody
                                        ? "Next: recover authority custody"
                                        : "Verify live authority custody",
                                kind: .warning
                            )
              Text(
                action == .continueIdentitySetup
                  ? "Authority custody is ready, but this installation cannot authenticate or approve work yet. Continue only with a new authority-signed provider presentation."
                  : action == .continueAuthorityCustody
                    ? "The Site Root proof is recorded, but v2 authority custody must complete before identity enrolment. Continue with fresh App Attest evidence."
                    : "Local trust is retained. Check Monas's live custody state and perform attended recovery only if its protected authority requires it."
              )
                            MnPrimaryButton(
                                action == .continueIdentitySetup
                                    ? "Continue identity setup"
                                    : action == .continueAuthorityCustody
                                        ? "Continue authority recovery"
                                        : "Check authority custody",
                                systemImage: action == .continueIdentitySetup
                                    ? "person.badge.key" : "key.viewfinder"
                            ) {
                                if action == .continueIdentitySetup {
                                    startProviderEnrolment()
                                } else {
                                    continueAuthorityCustody(installation)
                                }
                            }
              .disabled(action != .continueIdentitySetup && authorityCustodyBusy)
                            .accessibilityHint(
                                action == .continueIdentitySetup
                                    ? "Opens the signed identity-enrolment scanner"
                                    : "Checks the pinned Monas authority and recovers custody if required"
                            )
                        }
                    }
                } else if installation.status != "Trusted" {
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x2) {
                            MnStatusLabel(text: "Trust material requires review", kind: .warning)
              Text(
                "Do not approve requests until you have compared the new fingerprint with the installation."
              )
                        }
                    }
                }
                if installation.status == "Trusted" {
                    MnPrimaryButton("Use this installation", systemImage: "checkmark.circle") {
                        Task { try? await selectInstallation(installation.id) }
                    }
                    .accessibilityHint(
                        "Selects this trusted installation for new authority and provider requests"
                    )
                }
                if installation.allowsLocalForget {
                    let isIncompatible = installation.status == "Re-enrolment required"
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnStatusLabel(text: "Local deletion only", kind: .warning)
                            Text(
                                isIncompatible
                                    ? "This older enrolment cannot authorise in the current app. Removing it deletes this phone’s local trust and device key so you can re-enrol; authority-side revocation and existing server sessions remain separate."
                                    : "This expired record cannot authorise. Forgetting it removes this phone’s cached trust and device key; it does not delete authority audit history or change server state."
                            )
                            DestructiveConfirmationButton(
                                label: isIncompatible
                                    ? "Remove local enrolment"
                                    : "Remove expired local enrolment",
                                confirmationTitle: "Remove this local enrolment?",
                                confirmationMessage:
                                    "This removes only the trust and device key stored on this phone. Authority records and server sessions are unchanged."
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
