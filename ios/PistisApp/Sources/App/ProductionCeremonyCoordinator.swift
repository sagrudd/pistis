import Foundation
import PistisCore

private func installationNamespace(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

enum ProductionCeremonyStage: String, Equatable, Sendable {
    case challengeVerification = "QR and installation verification"
    case responsePreparation = "signed response preparation"
    case deviceSignature = "Face ID and device signature"
    case responseDelivery = "signed response delivery"
    case authorityVerification = "installation authority verification"
}

@MainActor
final class ProductionCeremonyCoordinator: ObservableObject {
    enum Phase: Equatable {
        case idle
        case verifying
        case review(ApprovalRequest)
        case submitting(AuthenticationDecision)
        case terminal(AuthoritativeCeremonyStatus)
        case failed(PlatformFailure)
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var failureStage: ProductionCeremonyStage?
    private let trustStore: any InstallationTrustStoring
    private let now: @Sendable () -> Date
    private var challenge: VerifiedAuthenticationChallenge?
    private var enrollment: AuthenticatedEnrollmentOutput?
    private var retainedRequest: ApprovalRequest?

    var presentedRequest: ApprovalRequest? {
        Self.presentationRequest(retainedRequest, during: phase)
    }

    init(
        trustStore: any InstallationTrustStoring = InstallationTrustKeychain.shared,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.trustStore = trustStore
        self.now = now
    }

    func accept(qrText: String) async {
        phase = .verifying
        retainedRequest = nil
        failureStage = nil
        do {
            guard let enrollment = try await trustStore.activeEnrollment() else {
                throw PlatformFailure.enrolmentRequired
            }
            let verified = try await ProductionChallengeVerifier.verify(
                qrText: qrText,
                trustRepository: trustStore,
                expectedExternalIdentityID: enrollment.trust.externalIdentityID,
                now: now()
            )
            self.enrollment = enrollment
            challenge = verified
            let request = Self.request(from: verified, trust: enrollment.trust, now: now())
            retainedRequest = request
            phase = .review(request)
        } catch let failure as PlatformFailure {
            fail(failure, at: .challengeVerification)
        } catch let failure as ProductionCeremonyError {
            fail(Self.classifiedFailure(failure), at: .challengeVerification)
        } catch {
            fail(.qrPayloadUnsupported, at: .challengeVerification)
        }
    }

    func decide(_ decision: AuthenticationDecision) async {
        guard let challenge, let enrollment else {
            fail(.invalidConfiguration, at: .responsePreparation)
            return
        }
        phase = .submitting(decision)
        failureStage = nil
        var stage = ProductionCeremonyStage.responsePreparation
        do {
            let timestamp = UInt64(now().timeIntervalSince1970 * 1_000)
            let payload = try AuthenticationResponseEncoder.payload(
                challenge: challenge,
                context: enrollment.responseContext,
                decision: decision,
                issuedAtMilliseconds: timestamp,
                userVerifiedAtMilliseconds: timestamp
            )
            stage = .deviceSignature
            let signer = try SecureEnclaveSigner(
                namespace: installationNamespace(enrollment.trust.installationID),
                authenticationReason: decision == .approved
                    ? "Approve this Pistis authentication request"
                    : "Deny this Pistis authentication request"
            )
            let producer = try SecureEnclaveProductionEnvelope(
                signer: signer,
                deviceKeyID: enrollment.responseContext.deviceKeyID
            )
            let envelope = try await producer.produceEnvelope(canonicalPayload: payload)
            guard envelope.count <= AuthenticationResponseTransport.maximumEnvelopeBytes,
                  let submitEndpoint = challenge.endpointHints.first
            else { throw PlatformFailure.invalidConfiguration }
            stage = .responseDelivery
            let transport = try AuthenticationResponseTransport(
                allowedHosts: enrollment.allowedHosts,
                httpsOrigin: enrollment.httpsOrigin,
                tlsSPKISHA256: enrollment.tlsSPKISHA256
            )
            var status = try await transport.submit(envelope: envelope, to: submitEndpoint)
            let statusEndpoint = challenge.endpointHints.dropFirst().first
            var attempts = 0
            stage = .authorityVerification
            while !status.state.isTerminal, let statusEndpoint, attempts < 10 {
                try await Task.sleep(for: .milliseconds(300))
                status = try await transport.status(at: statusEndpoint)
                attempts += 1
            }
            guard status.state.isTerminal else {
                throw PlatformFailure.productionEnvelopeUnavailable
            }
            phase = .terminal(status)
            record(status: status)
        } catch let failure as PlatformFailure {
            fail(failure, at: stage)
        } catch {
            fail(.productionEnvelopeUnavailable, at: stage)
        }
    }

    func reset() {
        challenge = nil
        enrollment = nil
        retainedRequest = nil
        failureStage = nil
        phase = .idle
    }

    private func fail(_ failure: PlatformFailure, at stage: ProductionCeremonyStage) {
        failureStage = stage
        phase = .failed(failure)
        guard let request = presentedRequest else { return }
        try? LocalHistoryRepository.shared.record(
            Self.failureHistoryEvent(
                request: request,
                failure: failure,
                stage: stage,
                occurredAt: now().formatted(date: .abbreviated, time: .shortened)
            )
        )
    }

    private func record(status: AuthoritativeCeremonyStatus) {
        guard let request = presentedRequest else { return }
        let completed = status.state == .completed
        try? LocalHistoryRepository.shared.record(
            HistoryEvent(
                id: UUID(),
                action: "Pistis sign-in",
                installation: request.installation,
                occurredAt: now().formatted(date: .abbreviated, time: .shortened),
                decision: completed ? "Approved" : status.state.rawValue.capitalized,
                signature: "Secure Enclave response produced",
                transfer: "Installation authority returned \(status.state.rawValue)",
                verification: completed
                    ? "Authority completion verified"
                    : "No authenticated session was issued"
            )
        )
    }

    static func presentationRequest(
        _ request: ApprovalRequest?,
        during phase: Phase
    ) -> ApprovalRequest? {
        switch phase {
        case .idle, .verifying:
            nil
        case .review, .submitting, .terminal, .failed:
            request
        }
    }

    static func failureHistoryEvent(
        request: ApprovalRequest,
        failure: PlatformFailure,
        stage: ProductionCeremonyStage,
        occurredAt: String
    ) -> HistoryEvent {
        HistoryEvent(
            id: UUID(),
            action: "Pistis sign-in",
            installation: request.installation,
            occurredAt: occurredAt,
            decision: "Not completed",
            signature: "Stopped at \(stage.rawValue)",
            transfer: "No authoritative completion recorded",
            verification: failure.safeUserMessage
        )
    }

    static func classifiedFailure(_ failure: ProductionCeremonyError) -> PlatformFailure {
        switch failure {
        case .oversizedFrame:
            .qrPayloadTooLarge
        case .malformedFrame, .invalidChecksum, .wrongTransferKind, .invalidChallenge:
            .qrPayloadUnsupported
        case .unknownInstallation:
            .enrolmentRequired
        case .expired:
            .authenticationRequestExpired
        case .invalidEndpoint:
            .authenticationEndpointInvalid
        case .inactiveInstallation, .keyMismatch, .invalidSignature, .wrongAudience,
             .wrongIdentity:
            .authenticationRequestInvalid
        }
    }

    private static func request(
        from challenge: VerifiedAuthenticationChallenge,
        trust: InstallationTrustRecord,
        now: Date
    ) -> ApprovalRequest {
        let remaining = max(
            0,
            Int((Double(challenge.expiresAtMilliseconds) / 1_000) - now.timeIntervalSince1970)
        )
        return ApprovalRequest(
            id: UUID(),
            action: "Authenticate session",
            subject: challenge.audience,
            installation: challenge.installationName,
            localUser: challenge.localUsername,
            externalIdentity: challenge.externalIdentityID.hexFingerprint,
            fingerprint: challenge.installationFingerprint.hexFingerprint,
            expiry: "\(remaining) seconds",
            route: "Scanned QR code",
            trustState: trust.active ? "Enrolled installation verified" : "Inactive"
        )
    }
}

private extension Data {
    var hexFingerprint: String {
        map { String(format: "%02X", $0) }
            .chunked(into: 4)
            .joined(separator: " ")
    }
}

private extension Array where Element == String {
    func chunked(into size: Int) -> [String] {
        stride(from: 0, to: count, by: size).map {
            self[$0 ..< Swift.min($0 + size, count)].joined()
        }
    }
}
