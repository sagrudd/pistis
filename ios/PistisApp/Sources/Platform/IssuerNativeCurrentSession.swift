import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import CryptoKit
import UIKit

/// The phone's own completed AuthenticateSession. Private constructor, no
/// Codable/raw-token adapter, persistence or desktop credential ingestion.
@MainActor
final class IssuerNativeCurrentSession {
    let sessionID: UUID
    let enrollment: AuthenticatedEnrollmentOutput
    let policyGeneration: UInt64
    let revocationGeneration: UInt64
    private let expiresAt: Date
    private var secret: Data
    private var terminal = false
    private var lastWall: Date

    private init(enrollment: AuthenticatedEnrollmentOutput,
                 finalized: IssuerNativeSessionWire.Finalized, secret: Data) {
        self.enrollment = enrollment; sessionID = finalized.sessionID
        policyGeneration = finalized.policyGeneration; revocationGeneration = finalized.revocationGeneration
        expiresAt = min(finalized.expiresAt, enrollment.trust.expiresAt)
        self.secret = secret
        lastWall = Date()
    }
    /// Sole ingress: actual retained enrolment, pinned native begin, existing
    /// signed AuthenticateSession and enrolled device key, then one-use finalize.
    static func authenticateCurrent() async throws -> IssuerNativeCurrentSession {
        let clock = ContinuousClock()
        let attempt = IssuerNativeAttemptGuard()
        let observer = NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil
        ) { _ in attempt.invalidate() }
        defer { NotificationCenter.default.removeObserver(observer); attempt.invalidate() }
        let started = Date()
        let originalEnd = clock.now.advanced(by: .seconds(30))
        try Task.checkCancellation()
        guard UIApplication.shared.applicationState == .active,
              let enrollment = try await InstallationTrustKeychain.shared.activeEnrollment(),
              enrollment.trust.active, started < enrollment.trust.expiresAt,
              enrollment.trust.authorisedProductAudiences.contains("propylaion") else { throw IssuerPhoneError.unavailable }
        let transport = try IssuerNativeSessionTransport(enrollment: enrollment)
        let beginBytes = try await transport.begin(enrollment: enrollment, deadline: originalEnd)
        let begin = try IssuerNativeSessionWire.begin(beginBytes, now: Date())
        var secret = try begin.takeInitiatorSecret()
        defer { secret.resetBytes(in: secret.startIndex..<secret.endIndex) }
        let challenge = try await ProductionChallengeVerifier.verify(qrText: begin.transfer,
            trustRepository: InstallationTrustKeychain.shared,
            expectedExternalIdentityID: enrollment.trust.externalIdentityID, now: Date())
        let challengeID = try IssuerNativeSessionWire.uuid(challenge.challengeID)
        let expectedSubmit = try transport.expectedSubmit(challengeID: challengeID)
        guard challenge.installationID == enrollment.trust.installationID,
              challenge.userID == enrollment.trust.userID,
              challenge.externalIdentityID == enrollment.trust.externalIdentityID,
              challenge.audience == "propylaion", challenge.endpointHints.first == expectedSubmit,
              challenge.endpointHints.allSatisfy({ CanonicalHTTPSOrigin.from($0) == enrollment.httpsOrigin }),
              try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment else { throw IssuerPhoneError.binding }
        let challengeExpiry = Date(timeIntervalSince1970: Double(challenge.expiresAtMilliseconds) / 1_000)
        let end = try boundedEnd(originalEnd, expiresAt: min(begin.expiresAt, min(challengeExpiry, enrollment.trust.expiresAt)))
        try Task.checkCancellation()
        try attempt.check()
        let signer = try SecureEnclaveSigner(namespace: IssuerNativeSessionWire.hex(enrollment.trust.installationID),
            authenticationReason: "Authenticate this phone for the issuer root operation")
        guard try signer.hasExistingKey() else { throw IssuerPhoneError.unavailable }
        let responseIssuedMilliseconds = UInt64(Date().timeIntervalSince1970 * 1_000)
        let ceremony = try await FaceIDCeremonyContext.authenticate(reason: "Authenticate this phone for the issuer root operation")
        defer { ceremony.invalidate() }
        let lifecycle = IssuerCeremonyLifecycle(ceremony: ceremony)
        try attempt.bind(lifecycle)
        return try await withTaskCancellationHandler {
            try checkLive(end, since: started)
            try attempt.check()
            try lifecycle.check()
            let publicKey = try signer.publicKey(using: ceremony).compressedSEC1
            let actualID = Data(SHA256.hash(data: Data("pistis:key-id:v1\0".utf8) + publicKey))
            guard actualID == enrollment.responseContext.deviceKeyID else { throw IssuerPhoneError.binding }
            let wall = Date()
            let elapsed = ceremony.authenticatedAt.duration(to: clock.now).components
            let verifiedWall = wall.timeIntervalSince1970 - Double(elapsed.seconds) - Double(elapsed.attoseconds) / 1e18
            guard verifiedWall >= 0 else { throw IssuerPhoneError.expired }
            let verifiedMilliseconds = UInt64(verifiedWall * 1_000)
            guard verifiedMilliseconds >= responseIssuedMilliseconds,
                  verifiedMilliseconds < challenge.expiresAtMilliseconds else { throw IssuerPhoneError.expired }
            let payload = try AuthenticationResponseEncoder.payload(challenge: challenge,
                context: enrollment.responseContext, decision: .approved,
                issuedAtMilliseconds: responseIssuedMilliseconds, userVerifiedAtMilliseconds: verifiedMilliseconds)
            let structure = try CoseSign1.signatureStructure(keyID: actualID, payload: payload)
            try checkLive(end, since: started)
            let signature = try signer.sign(message: structure, using: ceremony,
                originalDeadline: end, cancellation: lifecycle)
            let envelope = try CoseSign1(keyID: actualID, payload: payload, signature: signature).encoded()
            try checkLive(end, since: started)
            guard try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment else { throw IssuerPhoneError.binding }
            let statusRaw = try await transport.submit(envelope, challengeID: challengeID, deadline: end)
            try IssuerNativeSessionWire.completedStatus(statusRaw)
            try checkLive(end, since: started)
            let finalizedBytes = try await transport.finalize(reference: begin.reference, secret: secret, deadline: end)
            let finalized = try IssuerNativeSessionWire.finalized(finalizedBytes, now: Date())
            try IssuerNativeSessionWire.checkFinalized(finalized, enrollment: enrollment,
                challengeID: challengeID, actualDeviceKeyID: actualID)
            guard try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment else { throw IssuerPhoneError.binding }
            try lifecycle.check()
            try checkLive(end, since: started)
            return IssuerNativeCurrentSession(enrollment: enrollment, finalized: finalized, secret: secret)
        } onCancel: { attempt.invalidate() }
        // Any ambiguous invocation/delivery/finalize error exits this flow. There
        // is no status credential recovery, retry, new secret or fallback.
    }
    /// A credential is attached only here, to the fixed R2 issuer origin/paths.
    /// A returned JSON metadata object cannot call the private constructor.
    func authorizedIssuerRequest(_ request: URLRequest, deadline: ContinuousClock.Instant) async throws -> URLRequest {
        do {
            try Task.checkCancellation()
            let before = Date()
            guard !terminal, ContinuousClock().now < deadline, before >= lastWall, before < expiresAt,
                  let url = request.url, CanonicalHTTPSOrigin.from(url) == enrollment.httpsOrigin,
                  [IssuerPhoneWire.readinessPath, IssuerPhoneWire.exchangePath, ExactSourceACKWire.preparePath, ExactSourceACKWire.submitPath, IssuerSiteRootTransport.currentPreparationPath, "/v1/pistis/issuer-site-root/joint/prepare"].contains(url.path),
                  url.query == nil, url.fragment == nil, request.httpMethod == "POST",
                  request.value(forHTTPHeaderField: "Content-Type") == "application/cbor",
                  request.value(forHTTPHeaderField: "Cookie") == nil,
                  request.value(forHTTPHeaderField: "Authorization") == nil,
                  request.value(forHTTPHeaderField: "Origin") == nil,
                  try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment else { throw IssuerPhoneError.binding }
            let after = Date()
            guard !terminal, ContinuousClock().now < deadline, after >= before, after < expiresAt else { throw IssuerPhoneError.expired }
            lastWall = after
            return try IssuerNativeSessionWire.issuerRequestData(request, sessionID: sessionID,
                secret: secret, enrolledOrigin: enrollment.httpsOrigin)
        } catch { invalidate(); throw error }
    }
    func invalidate() {
        terminal = true
        secret.resetBytes(in: secret.startIndex..<secret.endIndex)
        secret.removeAll(keepingCapacity: false)
    }
    private static func checkLive(_ end: ContinuousClock.Instant, since started: Date) throws {
        try Task.checkCancellation()
        guard ContinuousClock().now < end, Date() >= started,
              UIApplication.shared.applicationState == .active else { throw IssuerPhoneError.expired }
    }
    private static func boundedEnd(_ original: ContinuousClock.Instant, expiresAt: Date) throws -> ContinuousClock.Instant {
        let before = ContinuousClock().now
        let left = expiresAt.timeIntervalSince(Date())
        guard before < original, left.isFinite, left > 0 else { throw IssuerPhoneError.expired }
        // Sample monotonic before wall time; queueing/serialization cannot extend.
        let nanos = Int64((min(left, 30) * 1_000_000_000).rounded(.down))
        return min(original, before.advanced(by: .nanoseconds(nanos)))
    }
    deinit { secret.resetBytes(in: secret.startIndex..<secret.endIndex) }
}
/// Sticky cancellation/background fence, created before begin or Face ID.
/// It owns no key/session authority and cannot approve or restart an attempt.
private final class IssuerNativeAttemptGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    private var lifecycle: IssuerCeremonyLifecycle?
    func bind(_ current: IssuerCeremonyLifecycle) throws {
        lock.lock()
        let cancelled = stopped
        if !cancelled { lifecycle = current }
        lock.unlock()
        if cancelled { current.invalidate(); throw IssuerPhoneError.uncertain }
    }
    func invalidate() {
        lock.lock(); stopped = true; let current = lifecycle; lock.unlock()
        current?.invalidate()
    }
    func check() throws {
        lock.lock(); let cancelled = stopped; lock.unlock()
        guard !cancelled else { throw IssuerPhoneError.uncertain }
    }
}

#endif
