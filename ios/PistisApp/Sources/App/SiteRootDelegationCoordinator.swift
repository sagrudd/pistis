import Foundation

/// UI state for the distinct, attended iPhone Site Root ceremony.
///
/// This coordinator is intentionally separate from `ProductionCeremonyCoordinator`:
/// v2 Pistis authentication must not acquire Site Root semantics by accident.
@MainActor
final class SiteRootDelegationCoordinator: ObservableObject {
    /// The confirmed server state shown after an attended ceremony.  This is
    /// deliberately distinct from the action phase: the initial Site Root
    /// proof establishes setup progress, whereas a later delegation has also
    /// completed the App Attest and custody hand-off.
    enum Completion: Equatable {
        case siteTrustEstablished
        case sessionEstablished
    }

    enum Phase: Equatable {
        case idle
        case review(SiteRootDelegationReview)
        case registeringFirstDevice
        case signing
        case attesting
        case rewrappingCustody
        case submitted(Completion)
        case failed(PlatformFailure)
    }

    @Published private(set) var phase: Phase = .idle
    /// Held independently of phase so Face ID transitions cannot dismiss the
    /// review before its final success or failure evidence is visible.
    @Published private(set) var presentedReview: SiteRootDelegationReview?
    private let transport: any MonasSiteRootCeremonyTransport
    private let appAttestClient: AppleAppAttestClient
    private let authorityCustodyMode: FirstAuthorityCustodyModeV2
    private var pending: PendingPresentation?

    private enum PendingPresentation {
        case delegation(SiteRootDelegationQRPresentationV1)
        case firstDevice(SiteRootGenesisRegistrationPresentationV1)
    }

    init(
        transport: any MonasSiteRootCeremonyTransport = UnavailableMonasSiteRootDelegationTransport(),
        appAttestClient: AppleAppAttestClient = AppleAppAttestClient(),
        authorityCustodyMode: FirstAuthorityCustodyModeV2 = .rotation
    ) {
        self.transport = transport
        self.appAttestClient = appAttestClient
        self.authorityCustodyMode = authorityCustodyMode
    }

    func accept(qrText: String) {
        do {
            let nowUnixMillis = try Self.nowUnixMillis()
            if let authority = transport.genesisAuthorityOrigin,
               let firstDevice = try? SiteRootGenesisRegistrationPresentationV1(
                   qrText: qrText,
                   authorityOrigin: authority,
                   nowUnixMillis: nowUnixMillis
               )
            {
                pending = .firstDevice(firstDevice)
                let review = SiteRootDelegationReview(firstDevice: firstDevice)
                presentedReview = review
                phase = .review(review)
                return
            }
            let scanned = try SiteRootDelegationQRPresentationV1(qrText: qrText)
            pending = .delegation(scanned)
            let review = SiteRootDelegationReview(presentation: scanned.presentation)
            presentedReview = review
            phase = .review(review)
        } catch let failure as PlatformFailure {
            recordFailure(failure, review: nil)
            phase = .failed(failure)
        } catch {
            recordFailure(.qrPayloadUnsupported, review: nil)
            phase = .failed(.qrPayloadUnsupported)
        }
    }

    func approve() async {
        guard let pending else {
            recordFailure(.invalidConfiguration, review: presentedReview)
            phase = .failed(.invalidConfiguration)
            return
        }
        do {
            let producer = try SecureEnclaveSiteRootProofProducer(
                authenticationReason: "Sign this exact Monas Site Root delegation"
            )
            switch pending {
            case let .delegation(qrPresentation):
                try await completeDelegation(
                    qrPresentation.presentation,
                    producer: producer,
                    registerAppAttest: true
                )
            case let .firstDevice(firstDevice):
                phase = .registeringFirstDevice
                let siteRootKey = try producer.register()
                let registration = try await appAttestClient.prepareRegistration(
                    ceremonyID: firstDevice.appAttestCeremonyIDB64URL,
                    siteTrustDomain: firstDevice.siteTrustDomain,
                    clientDataHash: firstDevice.appAttestChallengeDigest
                )
                let delegation = try await transport.registerGenesis(
                    SiteRootGenesisRegistrationRequestV1(
                        presentation: firstDevice,
                        siteRootKey: siteRootKey,
                        appAttestRegistration: registration
                    )
                )
                try await completeInitialStaticDelegation(delegation, producer: producer)
            }
        } catch let failure as PlatformFailure {
            recordFailure(failure, review: presentedReview)
            phase = .failed(failure)
        } catch {
            recordFailure(.productionEnvelopeUnavailable, review: presentedReview)
            phase = .failed(.productionEnvelopeUnavailable)
        }
    }

    func reset() {
        pending = nil
        presentedReview = nil
        phase = .idle
    }

    private func completeDelegation(
        _ delegation: SiteRootDelegationPresentationV1,
        producer: SecureEnclaveSiteRootProofProducer,
        registerAppAttest: Bool
    ) async throws {
        phase = .signing
        let submission = try producer.prove(delegation)
        let bootstrap = try await transport.submit(
            MonasSiteRootDelegationSubmissionRequestV1(
                endpoint: delegation.submitURL,
                submission: submission
            )
        )
        // The bootstrap is deliberately stack-local. It is used immediately
        // to bind the assertion transport to Monas's exact origin and SPKI;
        // it is never projected into SwiftUI state, persistence, logs, QR,
        // browser state, or a session.
        phase = .attesting
        let appAttestTransport = try MonasAppAttestTransport(bootstrap: bootstrap)
        if registerAppAttest {
            let registration = try await appAttestClient.prepareRegistration(
                ceremonyID: Self.base64URL(bootstrap.ceremonyID),
                siteTrustDomain: delegation.siteTrustDomain,
                clientDataHash: bootstrap.challengeDigest
            )
            try await appAttestTransport.submitRegistration(registration)
        }
        let now = try Self.nowUnixSeconds()
        let challenge = try await appAttestTransport.fetchCustodyRotationAssertionChallengeV2(
            nowUnixSeconds: now
        )
        let assertion = try await appAttestClient.prepareCustodyRotationAssertion(
            challenge: challenge
        )
        try await appAttestTransport.submitAssertion(assertion)
        phase = .rewrappingCustody
        let rotation = try SecureEnclaveFirstAuthorityCustodyProducerV2(
            authenticationReason: "Approve this exact first-authority custody rotation"
        )
        switch authorityCustodyMode {
        case .rotation:
            let commitment = try rotation.prepareInitialRotation()
            let presentation = try await appAttestTransport.beginFirstAuthorityCustodyRotationV2(
                commitment, nowUnixSeconds: Self.nowUnixSeconds()
            )
            let submission = try rotation.completeInitialRotation(presentation)
            _ = try await appAttestTransport.completeFirstAuthorityCustodyRotationV2(submission)
        case .recovery:
            let commitment = try rotation.retainedRecoveryCommitment()
            let presentation = try await appAttestTransport.beginFirstAuthorityCustodyRecoveryV2(
                expectedCommitment: commitment, nowUnixSeconds: Self.nowUnixSeconds()
            )
            let submission = try rotation.completeRecovery(presentation)
            _ = try await appAttestTransport.completeFirstAuthorityCustodyRecoveryV2(submission)
        }
        if let review = presentedReview {
            try SiteRootInstallationRepository.shared.recordAuthorityCustodyCompleted(
                authorityHost: review.destination
            )
        }
        recordCompletion(review: presentedReview)
        phase = .submitted(.sessionEstablished)
    }

    /// Completes the attended initial Site Root ceremony.  It has a separate
    /// terminal response from the later App Attest bootstrap transaction: the
    /// server has created custody and Site Trust authority, but no retained
    /// Monas session exists yet.  Record that real, incomplete installation
    /// rather than presenting a successful proof as an unavailable authority.
    private func completeInitialStaticDelegation(
        _ delegation: SiteRootDelegationPresentationV1,
        producer: SecureEnclaveSiteRootProofProducer
    ) async throws {
        phase = .signing
        let submission = try producer.prove(delegation)
        try await transport.submitInitialStaticCompletion(
            MonasSiteRootDelegationSubmissionRequestV1(
                endpoint: delegation.submitURL,
                submission: submission
            )
        )
        if let review = presentedReview {
            try? SiteRootInstallationRepository.shared.recordCompletedFirstCeremony(review)
        }
        recordHistory(
            review: presentedReview,
            decision: "Verified — setup continues",
            signature: "Secure Enclave Site Root proof produced",
            transfer: "Accepted by fixed Monas Site Root authority",
            verification: "Site Trust and custody were created; App Attest session setup remains"
        )
        phase = .submitted(.siteTrustEstablished)
    }

    private func recordCompletion(review: SiteRootDelegationReview?) {
        if let review {
            // This record intentionally captures setup progress only. It is
            // never an input to authentication, Site Trust, custody or a
            // Monas session; the server remains authoritative for all of
            // those states.
            try? SiteRootInstallationRepository.shared
                .recordCompletedFirstCeremony(review)
        }
        recordHistory(
            review: review,
            decision: "Verified",
            signature: "Secure Enclave Site Root proof produced",
            transfer: "Submitted to fixed Monas authority",
            verification: "Site Root proof accepted; v2 authority custody rotation completed"
        )
    }

    private func recordFailure(_ failure: PlatformFailure, review: SiteRootDelegationReview?) {
        recordHistory(
            review: review,
            decision: "Not completed",
            signature: "No completed Site Root proof retained",
            transfer: "Ceremony did not complete",
            verification: failure.safeUserMessage
        )
    }

    private func recordHistory(
        review: SiteRootDelegationReview?,
        decision: String,
        signature: String,
        transfer: String,
        verification: String
    ) {
        try? LocalHistoryRepository.shared.record(
            HistoryEvent(
                id: UUID(),
                action: review?.isFirstDevice == true
                    ? "First Site Root ceremony"
                    : "Site Root delegation",
                installation: review?.destination ?? "Monas Site Root authority",
                occurredAt: Date().formatted(date: .abbreviated, time: .standard),
                decision: decision,
                signature: signature,
                transfer: transfer,
                verification: verification
            )
        )
    }

    private static func nowUnixSeconds() throws -> UInt64 {
        let value = Date().timeIntervalSince1970
        guard value.isFinite, value >= 0, value <= Double(UInt64.max) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return UInt64(value)
    }

    private static func nowUnixMillis() throws -> UInt64 {
        let value = Date().timeIntervalSince1970 * 1_000
        guard value.isFinite, value >= 0, value <= Double(UInt64.max) else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        return UInt64(value)
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Redacted, non-secret facts permitted in the iPhone confirmation screen.
struct SiteRootDelegationReview: Equatable, Identifiable {
    var id: String { reference + deviceKeyFingerprint + destination }
    let reference: String
    let deviceKeyFingerprint: String
    let destination: String
    let isFirstDevice: Bool

    init(presentation: SiteRootDelegationPresentationV1) {
        reference = Self.redact(presentation.reference)
        deviceKeyFingerprint = Self.redact(presentation.deviceKeyID)
        destination = presentation.submitURL.host ?? "unavailable"
        isFirstDevice = false
    }

    init(firstDevice: SiteRootGenesisRegistrationPresentationV1) {
        reference = Self.redact(firstDevice.reference)
        deviceKeyFingerprint = "Created with Face ID"
        destination = firstDevice.registrationURL.host ?? "unavailable"
        isFirstDevice = true
    }

    private static func redact(_ value: String) -> String {
        guard value.count > 12 else { return "redacted" }
        return "\(value.prefix(6))…\(value.suffix(4))"
    }
}
