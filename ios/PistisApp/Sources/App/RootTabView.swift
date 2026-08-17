import SwiftUI

enum AuthorityCustodyContinuationStage: String, CaseIterable {
    case initialStatus = "initial-status"
    case fetchChallenge = "fetch-challenge"
    case generateAssertion = "generate-assertion"
    case submitAssertion = "submit-assertion"
    case resolveCustodyLifecycle = "resolve-custody-lifecycle"
    case prepareCustody = "prepare-custody"
    case beginCustody = "begin-custody"
    case completeCustody = "complete-custody"
    case retainCompletion = "retain-completion"

    var failureMessage: String {
        "Authority custody stopped safely at \(rawValue). No setup evidence was discarded."
    }
}

enum AuthorityCustodyAcceptedAssertionTransitionV2 {
    /// An empty 202 consumes the challenge, but only the subsequent exact
    /// server-owned lifecycle decides whether Pistis may rotate or recover.
    static func next(
        after status: MonasSiteRootDelegationTransport.AuthorityCustodyStatusV2,
        observedLifecycle: MonasSiteRootDelegationTransport.AuthorityCustodyStatusV2
    ) throws -> (
        status: MonasSiteRootDelegationTransport.AuthorityCustodyStatusV2,
        stage: AuthorityCustodyContinuationStage
    ) {
        guard status == .appAttestAssertionRequired else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        guard observedLifecycle == .initialRotationRequired
                || observedLifecycle == .recoveryRequired
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return (observedLifecycle, .prepareCustody)
    }
}

struct RootTabView: View {
    private enum Tab: Hashable {
        case identities
        case installations
        case scan
        case history
        case settings
    }

    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var enrollment = EnrollmentProjectionStore()
    @State private var reconciliationMessage: String?
    @State private var selectedTab = Tab.identities
    @State private var providerEnrolmentRequested = false
    @State private var authorityCustodyContinuationHost: String?
    @State private var authorityCustodyMode: FirstAuthorityCustodyModeV2 = .rotation
  @State private var authorityCustodyAttempt: UUID?
    let siteRootTransport: any MonasSiteRootCeremonyTransport

    var body: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                IdentitiesView(
                    identities: projection.identities,
                    loadFailure: enrollment.state == .failed,
                    forgetExpired: forgetExpiredIdentity,
                    providerEnrolmentRequested: $providerEnrolmentRequested
                )
            }
            .tabItem {
                Label("Identities", systemImage: "person.text.rectangle")
            }
            .tag(Tab.identities)

            NavigationStack {
                InstallationsView(
                    installations: projection.installations,
                    loadFailure: enrollment.state == .failed,
                    forgetExpired: forgetExpired,
                    recoverSiteRootInstallation: recoverSiteRootInstallation,
                    reconciliationMessage: reconciliationMessage,
          authorityCustodyBusy: authorityCustodyAttempt != nil,
                    startProviderEnrolment: startProviderEnrolment,
                    continueAuthorityCustody: continueAuthorityCustody,
                    selectInstallation: selectInstallation
                )
            }
            .tabItem {
                Label("Installations", systemImage: "building.2")
            }
            .tag(Tab.installations)

            NavigationStack {
                ScanView(
                    siteRootTransport: siteRootTransport,
                    expectedSiteRootAuthorityHost: authorityCustodyContinuationHost,
                    authorityCustodyMode: authorityCustodyMode
                ) {
                    authorityCustodyContinuationHost = nil
                    authorityCustodyMode = .rotation
                    selectedTab = .installations
                }
                .id(authorityCustodyMode)
            }
            .tabItem {
                Label("Scan", systemImage: "qrcode.viewfinder")
            }
            .tag(Tab.scan)

            NavigationStack {
                HistoryView(
                    events: projection.history,
                    loadFailure: enrollment.state == .failed
                )
            }
            .tabItem {
                Label("History", systemImage: "clock.arrow.circlepath")
            }
            .tag(Tab.history)

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
            .tag(Tab.settings)
        }
        .tint(MnColor.action)
        .task {
            await enrollment.refresh()
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            Task { await enrollment.refresh() }
        }
        .onReceive(
            NotificationCenter.default.publisher(
                for: InstallationTrustKeychain.enrollmentDidChangeNotification
            )
        ) { _ in
            Task { await enrollment.refresh() }
        }
        .onReceive(
            NotificationCenter.default.publisher(
                for: LocalHistoryRepository.historyDidChangeNotification
            )
        ) { _ in
            Task { await enrollment.refresh() }
        }
        .onReceive(
            NotificationCenter.default.publisher(
                for: SiteRootInstallationRepository.installationsDidChangeNotification
            )
        ) { _ in
            Task { await enrollment.refresh() }
        }
    }

    private var projection: EnrollmentProjection {
    if case .loaded(let projection) = enrollment.state {
            return projection
        }
        return .empty
    }

    private func recoverSiteRootInstallation() {
    reconciliationMessage = nil
        Task {
            guard let transport = siteRootTransport as? MonasSiteRootDelegationTransport,
                  let authorityHost = transport.authorityHost
            else {
                reconciliationMessage = "The fixed Monas Site Root authority is unavailable."
                return
            }
            do {
                let producer = try SecureEnclaveSiteRootProofProducer(
                    authenticationReason: "Read this iPhone's Site Root setup progress"
                )
                guard let registration = try producer.existingRegistration() else {
          reconciliationMessage =
            "No Site Root key exists on this iPhone. Scan the signed Monas invitation first."
                    return
                }
        guard
          let status = try await transport.installationStatus(
                    siteRootDeviceKeyID: registration.deviceKeyID
          )
        else {
                    reconciliationMessage = "Monas has no verified Site Root setup record for this iPhone."
                    return
                }
                try SiteRootInstallationRepository.shared.recordRecoveredFirstCeremony(
                    authorityHost: authorityHost,
                    redactedReference: status.redactedReference,
                    registeredAt: status.registeredAt
                )
                try? LocalHistoryRepository.shared.record(
                    HistoryEvent(
                        id: UUID(),
                        action: "Site Root setup recovered",
                        installation: authorityHost,
                        occurredAt: Date().formatted(date: .abbreviated, time: .standard),
                        decision: "Verified",
                        signature: "No new proof produced",
                        transfer: "Read from fixed Monas authority",
                        verification: "Existing Site Root proof remains server-recorded"
                    )
                )
                reconciliationMessage = nil
                await enrollment.refresh()
            } catch {
                reconciliationMessage = "Pistis could not safely recover Site Root setup progress."
            }
        }
    }

    private func startProviderEnrolment() {
    reconciliationMessage = nil
    routeToProviderEnrolment()
  }

  private func routeToProviderEnrolment() {
        selectedTab = .identities
        // Let the Identities NavigationStack become visible before presenting
        // the existing signed-presentation flow. The redacted local Site Root
        // record never supplies an endpoint, certificate pin, invitation or
        // provider authority.
        Task { @MainActor in
            await Task.yield()
            providerEnrolmentRequested = true
        }
    }

    private func continueAuthorityCustody(_ installation: InstallationSummary) {
    guard authorityCustodyAttempt == nil else { return }
    let attempt = UUID()
    authorityCustodyAttempt = attempt
    reconciliationMessage = "Continuing authority custody with fresh App Attest evidence…"
        Task {
      defer {
        if authorityCustodyAttempt == attempt { authorityCustodyAttempt = nil }
      }
            guard let transport = siteRootTransport as? MonasSiteRootDelegationTransport,
                  transport.isConfiguredAuthorityHost(installation.localAlias)
            else {
                reconciliationMessage =
                    "The retained Site Root authority is not one of this build's pinned origins."
                return
            }
            var failureStage = AuthorityCustodyContinuationStage.initialStatus
            do {
        var status = try await transport.authorityCustodyStatusV2(
            authorityHost: installation.localAlias
        )
        switch status {
                case .ready:
                    if installation.status != "Trusted" {
                        try SiteRootInstallationRepository.shared
                            .recordAuthorityCustodyCompleted(authorityHost: installation.localAlias)
                    }
                    await enrollment.refresh()
          if installation.status == "Trusted" {
            reconciliationMessage = "Authority custody is ready. No re-enrolment is required."
            selectedTab = .installations
          } else {
            reconciliationMessage =
              "Authority custody is ready. Continue identity setup for this installation."
            routeToProviderEnrolment()
          }
                    return
        case .appAttestAssertionRequired, .initialRotationRequired, .recoveryRequired:
          break
        }
        let appAttestTransport = try transport.appAttestTransport(
            authorityHost: installation.localAlias
        )
        if status == .appAttestAssertionRequired {
          failureStage = .fetchChallenge
          let now = UInt64(Date().timeIntervalSince1970)
          let challenge =
            try await appAttestTransport
            .fetchCustodyRotationAssertionChallengeV2(nowUnixSeconds: now)
          failureStage = .generateAssertion
          let assertion = try await AppleAppAttestClient()
            .prepareCustodyRotationAssertion(challenge: challenge)
          failureStage = .submitAssertion
          try await appAttestTransport.submitAssertion(assertion)
          failureStage = .resolveCustodyLifecycle
          let observedLifecycle = try await transport.authorityCustodyStatusV2(
            authorityHost: installation.localAlias
          )
          let transition = try AuthorityCustodyAcceptedAssertionTransitionV2.next(
            after: status, observedLifecycle: observedLifecycle
          )
          status = transition.status
          failureStage = transition.stage
        }
        failureStage = .prepareCustody
        let producer = try SecureEnclaveFirstAuthorityCustodyProducerV2(
          authenticationReason: "Approve this exact first-authority custody continuation"
        )
        switch status {
        case .appAttestAssertionRequired:
          throw PlatformFailure.siteRootAuthorityUnavailable
        case .initialRotationRequired:
          let commitment = try producer.prepareInitialRotation()
          failureStage = .beginCustody
          let presentation =
            try await appAttestTransport
            .beginFirstAuthorityCustodyRotationV2(
              commitment, nowUnixSeconds: UInt64(Date().timeIntervalSince1970)
            )
          let submission = try producer.completeInitialRotation(presentation)
          failureStage = .completeCustody
          _ = try await appAttestTransport.completeFirstAuthorityCustodyRotationV2(
            submission
          )
        case .recoveryRequired:
          let commitment = try producer.retainedRecoveryCommitment()
          failureStage = .beginCustody
          let presentation =
            try await appAttestTransport
            .beginFirstAuthorityCustodyRecoveryV2(
              expectedCommitment: commitment,
              nowUnixSeconds: UInt64(Date().timeIntervalSince1970)
            )
          let submission = try producer.completeRecovery(presentation)
          failureStage = .completeCustody
          _ = try await appAttestTransport.completeFirstAuthorityCustodyRecoveryV2(
            submission
          )
        case .ready:
          break
                }
        failureStage = .retainCompletion
        if installation.status != "Trusted" {
          try SiteRootInstallationRepository.shared.recordAuthorityCustodyCompleted(
            authorityHost: installation.localAlias
          )
        }
        try? LocalHistoryRepository.shared.record(
          HistoryEvent(
            id: UUID(), action: "Authority custody continued",
            installation: installation.localAlias,
            occurredAt: Date().formatted(date: .abbreviated, time: .standard),
            decision: "Verified", signature: "Fresh App Attest assertion accepted",
            transfer: "Pinned Monas v2 custody flow completed",
            verification: "Identity enrolment is now required"
          ))
        reconciliationMessage = installation.status == "Trusted"
          ? "Authority custody recovered and ready. No re-enrolment is required."
          : "Authority custody completed. Continue identity setup for this installation."
        await enrollment.refresh()
        if installation.status == "Trusted" {
          selectedTab = .installations
        } else {
          routeToProviderEnrolment()
        }
            } catch {
        let message = failureStage.failureMessage
        reconciliationMessage = message
        try? LocalHistoryRepository.shared.record(
          HistoryEvent(
            id: UUID(), action: "Authority custody continuation",
            installation: installation.localAlias,
            occurredAt: Date().formatted(date: .abbreviated, time: .standard),
            decision: "Not completed", signature: "No authority change retained",
            transfer: "Pinned Monas v2 custody flow",
            verification: message
          ))
            }
        }
    }

    private func forgetExpired(_ installationID: UUID) async throws {
        let identifier = installationID.data
    guard
      let inventory = try await InstallationTrustKeychain.shared
            .enrollmentInventoryRecord(installationID: identifier)
        else { throw PlatformFailure.invalidConfiguration }
        switch inventory {
    case .current(let stored):
            guard stored.trust.installationID == identifier,
                  InstallationTrustKeychain.allowsLocalForget(
                      active: stored.trust.active,
                      expiresAt: stored.trust.expiresAt,
                      now: Date()
                  )
            else { throw PlatformFailure.invalidConfiguration }
            try await forgetStoredEnrollment(
                stored,
                historyAction: "Local installation record forgotten",
                authenticationReason: "Forget this expired Pistis installation",
                verification: "Expired trust and local device key removed"
            )
    case .legacy(let stored):
            guard stored.trust.installationID == identifier else {
                throw PlatformFailure.invalidConfiguration
            }
            try await forgetLegacyEnrollment(
                stored,
                historyAction: "Incompatible installation enrolment removed",
                authenticationReason: "Remove this incompatible Pistis enrolment"
            )
        }
    }

    private func selectInstallation(_ installationID: UUID) async throws {
        try await InstallationTrustKeychain.shared.selectInstallation(
            installationID: installationID.data
        )
        reconciliationMessage = "Using \(installationID.uuidString) for new requests."
        await enrollment.refresh()
    }

    private func forgetExpiredIdentity(_ externalIdentityID: UUID) async throws {
        let identifier = externalIdentityID.data
    guard
      let inventory = try await InstallationTrustKeychain.shared
            .enrollmentInventoryRecords()
            .first(where: { record in
                switch record {
                case let .current(stored):
                    return stored.trust.externalIdentityID == identifier
                case let .legacy(stored):
                    return stored.trust.externalIdentityID == identifier
                }
            })
        else { throw PlatformFailure.invalidConfiguration }
        switch inventory {
    case .current(let stored):
            guard stored.trust.externalIdentityID == identifier,
                  InstallationTrustKeychain.allowsLocalForget(
                      active: stored.trust.active,
                      expiresAt: stored.trust.expiresAt,
                      now: Date()
                  )
            else { throw PlatformFailure.invalidConfiguration }
            try await forgetStoredEnrollment(
                stored,
                historyAction: "Local provider account forgotten",
                authenticationReason: "Forget this expired Pistis provider account",
                verification: "Expired identity, trust and local device key removed"
            )
    case .legacy(let stored):
            guard stored.trust.externalIdentityID == identifier else {
                throw PlatformFailure.invalidConfiguration
            }
            try await forgetLegacyEnrollment(
                stored,
                historyAction: "Incompatible provider enrolment removed",
                authenticationReason: "Remove this incompatible Pistis account"
            )
        }
    }

    private func forgetStoredEnrollment(
        _ stored: AuthenticatedEnrollmentOutput,
        historyAction: String,
        authenticationReason: String,
        verification: String
    ) async throws {
        if let event = EnrollmentProjection(enrollment: stored).history.first {
            // Local history is diagnostic context, not authorisation state.
            // A stale history encoding must never keep expired credentials.
            try? LocalHistoryRepository.shared.record(event)
        }

        // Remove the expired authorisation record before optional key cleanup.
        // Without this record an orphaned, already-expired key cannot
        // authorise. This prevents an invalidated Enclave key from trapping
        // expired identity data on the phone.
        let keyRemoved = try await LocalForgetTransaction.run(
            removeTrust: {
                try await InstallationTrustKeychain.shared.forgetExpired(
                    installationID: stored.trust.installationID
                )
            },
            removeKey: {
                let signer = try SecureEnclaveSigner(
                    namespace: hexadecimal(stored.trust.installationID),
                    authenticationReason: authenticationReason
                )
                try signer.deleteLocalKey()
            }
        )
        try? LocalHistoryRepository.shared.record(
            HistoryEvent(
                id: UUID(),
                action: historyAction,
                installation: stored.trust.displayName,
                occurredAt: Date().formatted(date: .abbreviated, time: .standard),
                decision: "Completed locally",
                signature: "No authority action requested",
                transfer: "No server state changed",
                verification: keyRemoved
                    ? verification
                    : "Expired trust removed; local key cleanup required"
            )
        )
        await enrollment.refresh()
    }

    private func forgetLegacyEnrollment(
        _ stored: LegacyAuthenticatedEnrollmentOutput,
        historyAction: String,
        authenticationReason: String
    ) async throws {
        let keyRemoved = try await LocalForgetTransaction.run(
            removeTrust: {
                try await InstallationTrustKeychain.shared.forgetIncompatible(
                    installationID: stored.trust.installationID,
                    externalIdentityID: stored.trust.externalIdentityID
                )
            },
            removeKey: {
                let signer = try SecureEnclaveSigner(
                    namespace: hexadecimal(stored.trust.installationID),
                    authenticationReason: authenticationReason
                )
                try signer.deleteLocalKey()
            }
        )
        try? LocalHistoryRepository.shared.record(
            HistoryEvent(
                id: UUID(),
                action: historyAction,
                installation: stored.trust.displayName,
                occurredAt: Date().formatted(date: .abbreviated, time: .standard),
                decision: "Completed locally",
                signature: "No authority action requested",
                transfer: "Authority-side revocation still required",
                verification: keyRemoved
                    ? "Incompatible trust and local device key removed"
                    : "Incompatible trust removed; local key cleanup required"
            )
        )
        await enrollment.refresh()
    }

    private func hexadecimal(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

/// Orders local credential removal so optional key cleanup cannot retain trust.
@MainActor
enum LocalForgetTransaction {
    static func run(
        removeTrust: () async throws -> Void,
        removeKey: () throws -> Void
    ) async throws -> Bool {
        try await removeTrust()
        do {
            try removeKey()
            return true
        } catch {
            return false
        }
    }
}

extension UUID {
  fileprivate var data: Data {
        let value = uuid
        return Data([
            value.0, value.1, value.2, value.3,
            value.4, value.5, value.6, value.7,
            value.8, value.9, value.10, value.11,
            value.12, value.13, value.14, value.15,
        ])
    }
}
