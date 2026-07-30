import Foundation
import PistisCore

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
    private let trustStore: any InstallationTrustStoring
    private let now: @Sendable () -> Date
    private var challenge: VerifiedAuthenticationChallenge?
    private var enrollment: AuthenticatedEnrollmentOutput?

    init(
        trustStore: any InstallationTrustStoring = InstallationTrustKeychain.shared,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.trustStore = trustStore
        self.now = now
    }

    func accept(qrText: String) async {
        phase = .verifying
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
            phase = .review(Self.request(from: verified, trust: enrollment.trust, now: now()))
        } catch let failure as PlatformFailure {
            phase = .failed(failure)
        } catch {
            phase = .failed(.qrPayloadUnsupported)
        }
    }

    func decide(_ decision: AuthenticationDecision) async {
        guard let challenge, let enrollment else {
            phase = .failed(.invalidConfiguration)
            return
        }
        phase = .submitting(decision)
        do {
            let timestamp = UInt64(now().timeIntervalSince1970 * 1_000)
            let payload = try AuthenticationResponseEncoder.payload(
                challenge: challenge,
                context: enrollment.responseContext,
                decision: decision,
                issuedAtMilliseconds: timestamp,
                userVerifiedAtMilliseconds: timestamp
            )
            let signer = try SecureEnclaveSigner(
                namespace: "primary",
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
            let transport = try AuthenticationResponseTransport(
                allowedHosts: enrollment.allowedHosts
            )
            var status = try await transport.submit(envelope: envelope, to: submitEndpoint)
            let statusEndpoint = challenge.endpointHints.dropFirst().first
            var attempts = 0
            while !status.state.isTerminal, let statusEndpoint, attempts < 10 {
                try await Task.sleep(for: .milliseconds(300))
                status = try await transport.status(at: statusEndpoint)
                attempts += 1
            }
            guard status.state.isTerminal else {
                throw PlatformFailure.productionEnvelopeUnavailable
            }
            phase = .terminal(status)
        } catch let failure as PlatformFailure {
            phase = .failed(failure)
        } catch {
            phase = .failed(.productionEnvelopeUnavailable)
        }
    }

    func reset() {
        challenge = nil
        enrollment = nil
        phase = .idle
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
