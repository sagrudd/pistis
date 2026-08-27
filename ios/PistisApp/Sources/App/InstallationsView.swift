import SwiftUI

enum InstallationDetailAction: Equatable {
    case continueAuthorityCustody
    case continueBrokeredSiteX509
    case completeDasAuthorityRetirement
    case continueIdentitySetup
    case none

    init(installation: InstallationSummary) {
        if installation.status == "Trusted" {
            self = .completeDasAuthorityRetirement
            return
        }
        guard installation.status == "Setup in progress" else {
            self = .none
            return
        }
        if installation.setupPhase == .identityEnrolmentRequired {
            self = .continueIdentitySetup
        } else if installation.localAlias == URL(
            string: SiteRootConvergenceProfileV2.x509BrokerOrigin
        )?.host {
            self = .continueBrokeredSiteX509
        } else {
            self = .continueAuthorityCustody
        }
    }

    var verifiesLiveAuthorityCustody: Bool {
        switch self {
        case .continueAuthorityCustody, .completeDasAuthorityRetirement,
             .continueIdentitySetup:
            return true
        case .continueBrokeredSiteX509, .none:
            return false
        }
    }
}

struct InstallationsView: View {
    let installations: [InstallationSummary]
    let loadFailure: Bool
    let forgetExpired: (UUID) async throws -> Void
    let recoverSiteRootInstallation: () -> Void
    let reconciliationMessage: String?
    let authorityCustodyBusy: Bool
    let continueBrokeredSiteX509: () -> Void
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
                    continueBrokeredSiteX509: continueBrokeredSiteX509,
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
    let continueBrokeredSiteX509: () -> Void
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
                                    ? "Next: verify custody and enrol identity"
                                    : action == .continueBrokeredSiteX509
                                        ? "Next: scan protected Site X.509 approval"
                                    : action == .continueAuthorityCustody
                                        ? "Next: recover authority custody"
                                    : "Verify authority readiness",
                                kind: .warning
                            )
              Text(
                action == .continueIdentitySetup
                  ? "Pistis will verify live authority custody, recover it with fresh App Attest and Face ID if required, and only then open a new authority-signed provider presentation."
                  : action == .continueBrokeredSiteX509
                    ? "Site Root is retained and will not be reissued. Keep the monas-first-install terminal open and scan its single protected Site X.509 continuation QR."
                  : action == .continueAuthorityCustody
                    ? "The Site Root proof is recorded, but v2 authority custody must complete before identity enrolment. Continue with fresh App Attest evidence."
                    : "This installation identity is trusted. Pistis will first verify live Site authority custody, recover it with fresh Face ID if required, and only continue a pending DAS transition when custody is already ready."
              )
                            MnPrimaryButton(
                                action == .continueIdentitySetup
                                    ? "Verify custody and continue"
                                    : action == .continueBrokeredSiteX509
                                        ? "Open protected scanner"
                                    : action == .continueAuthorityCustody
                                        ? "Continue authority recovery"
                                        : "Verify authority readiness",
                                systemImage: action == .continueIdentitySetup
                                    ? "person.badge.key"
                                    : action == .continueBrokeredSiteX509
                                        ? "qrcode.viewfinder" : "key.viewfinder"
                            ) {
                                if action == .continueBrokeredSiteX509 {
                                    continueBrokeredSiteX509()
                                } else if action.verifiesLiveAuthorityCustody {
                                    continueAuthorityCustody(installation)
                                }
                            }
              .disabled(
                action != .continueBrokeredSiteX509
                  && authorityCustodyBusy
              )
                            .accessibilityHint(
                                action == .continueIdentitySetup
                                    ? "Checks live authority custody before opening the signed identity-enrolment scanner"
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
