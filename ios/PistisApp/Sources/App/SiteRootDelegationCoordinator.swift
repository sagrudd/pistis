import Foundation

/// UI state for the distinct, attended iPhone Site Root ceremony.
///
/// This coordinator is intentionally separate from `ProductionCeremonyCoordinator`:
/// v2 Pistis authentication must not acquire Site Root semantics by accident.
@MainActor
final class SiteRootDelegationCoordinator: ObservableObject {
    enum Phase: Equatable {
        case idle
        case review(SiteRootDelegationReview)
        case registeringFirstDevice
        case signing
        case attesting
        case rewrappingCustody
        case submitted
        case failed(PlatformFailure)
    }

    @Published private(set) var phase: Phase = .idle
    private let transport: any MonasSiteRootCeremonyTransport
    private let appAttestClient: AppleAppAttestClient
    private var pending: PendingPresentation?

    private enum PendingPresentation {
        case delegation(SiteRootDelegationQRPresentationV1)
        case firstDevice(SiteRootGenesisRegistrationPresentationV1)
    }

    init(
        transport: any MonasSiteRootCeremonyTransport = UnavailableMonasSiteRootDelegationTransport(),
        appAttestClient: AppleAppAttestClient = AppleAppAttestClient()
    ) {
        self.transport = transport
        self.appAttestClient = appAttestClient
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
                phase = .review(SiteRootDelegationReview(firstDevice: firstDevice))
                return
            }
            let scanned = try SiteRootDelegationQRPresentationV1(qrText: qrText)
            pending = .delegation(scanned)
            phase = .review(SiteRootDelegationReview(presentation: scanned.presentation))
        } catch let failure as PlatformFailure {
            phase = .failed(failure)
        } catch {
            phase = .failed(.qrPayloadUnsupported)
        }
    }

    func approve() async {
        guard let pending else {
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
                try await completeDelegation(
                    delegation,
                    producer: producer,
                    registerAppAttest: false
                )
            }
        } catch let failure as PlatformFailure {
            phase = .failed(failure)
        } catch {
            phase = .failed(.productionEnvelopeUnavailable)
        }
    }

    func reset() {
        pending = nil
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
        let assertion = try await appAttestClient.prepareAssertion(bootstrap: bootstrap)
        let presentation = try await appAttestTransport.submitAssertionForCustodyPresentation(
            assertion,
            nowUnixSeconds: Self.nowUnixSeconds()
        )
        phase = .rewrappingCustody
        let rewrap = try SecureEnclaveIphoneMediatedCustodyRewrapProducer(
            authenticationReason: "Unlock and rewrap the exact Thesaurophylax custody record"
        )
        let rewrapSubmission = try rewrap.produce(presentation: presentation)
        try await appAttestTransport.submitCustodyRewrap(rewrapSubmission)
        phase = .submitted
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
