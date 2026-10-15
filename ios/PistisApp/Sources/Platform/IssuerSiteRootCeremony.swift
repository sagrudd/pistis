import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import CryptoKit
import Security
import UIKit

/// Private immutable handoff, deliberately without a raw/public constructor.
/// A real producer must bind these facts to existing Site owner, current session,
/// device, mode-specific permission and exact originals before presentation.
/// Pinned TLS, a response DTO or redacted installation history cannot do that.
@MainActor
final class IssuerSiteRootPreparedHandoff {
    let readiness: IssuerPhoneReadiness
    let preparedAt: ContinuousClock.Instant
    let sitePublicKey: Data
    let rootAdmissionReference: Data?
    let expectedAdmissionBody: Data?
    let revocationRevision: UInt64?
    let keyState: UInt64?
    let summary: String
    fileprivate let transport: IssuerSiteRootTransport
    private let nativeSession: IssuerNativeCurrentSession
    private let ack: SiteRootConvergenceAckRecordV2
    private let lifecycle: ExactSourceACKLifecycle
    private var consumed = false

    private init(readiness: IssuerPhoneReadiness, preparedAt: ContinuousClock.Instant,
                 sitePublicKey: Data, rootAdmissionReference: Data?, expectedAdmissionBody: Data?,
                 revocationRevision: UInt64?, keyState: UInt64?, summary: String,
                 transport: IssuerSiteRootTransport, nativeSession: IssuerNativeCurrentSession,
                 ack: SiteRootConvergenceAckRecordV2, lifecycle: ExactSourceACKLifecycle) {
        self.readiness = readiness
        self.preparedAt = preparedAt
        self.sitePublicKey = sitePublicKey
        self.rootAdmissionReference = rootAdmissionReference
        self.expectedAdmissionBody = expectedAdmissionBody
        self.revocationRevision = revocationRevision
        self.keyState = keyState
        self.summary = summary; self.transport = transport; self.nativeSession = nativeSession
        self.ack = ack; self.lifecycle = lifecycle
    }
    /// Fixed independently pinned own-session ingress plus full approval and
    /// IADM proof verification. No caller can provide a DTO/token or key here.
    static func current() async throws -> IssuerSiteRootPreparedHandoff {
        let lifecycle = ExactSourceACKLifecycle()
        do {
            try lifecycle.observe()
            let (transport, current) = try await IssuerSiteRootTransport.authenticatedRootNative()
            try lifecycle.observe()
            let sampled = ContinuousClock().now
            let deadline = sampled.advanced(by: .seconds(30))
            let record = try SiteRootConvergenceAckStoreV2().current()
            guard let target = SiteRootConvergenceEncoding.base64URL(record.targetIDB64URL), target.count == 32 else {
                throw IssuerPhoneError.binding
            }
            var nonce = Data(count: 32)
            let status = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
            guard status == errSecSuccess, !nonce.allSatisfy({ $0 == 0 }) else { throw IssuerPhoneError.unavailable }
            let request = try IssuerPhoneWire.currentSitePreparationRequest(
                nonce: nonce, currentACKTarget: target)
            let raw = try await transport.prepareSiteCurrent(request, deadline: deadline)
            let now = try lifecycle.observe()
            guard now.timeIntervalSince1970 >= 0 else { throw IssuerPhoneError.expired }
            let readiness = try IssuerPhoneReadiness(canonicalBytes: raw)
            let evidence = try IssuerSiteCurrentPermissionEvidence(readiness: readiness,
                trust: current.enrollment.trust, responseContext: current.enrollment.responseContext,
                currentACKTarget: target, policyGeneration: current.policyGeneration,
                revocationGeneration: current.revocationGeneration,
                nowMilliseconds: UInt64(now.timeIntervalSince1970 * 1000))
            guard readiness.challenge == nonce,
                  try IssuerNativeSessionWire.uuid(readiness.siteID).uuidString.lowercased() == record.siteUUID,
                  ContinuousClock().now < deadline else { throw IssuerPhoneError.binding }
            let value = IssuerSiteRootPreparedHandoff(readiness: readiness, preparedAt: sampled,
                sitePublicKey: evidence.sitePublicKey, rootAdmissionReference: evidence.rootAdmissionReference,
                expectedAdmissionBody: nil, revocationRevision: evidence.revocationRevision,
                keyState: evidence.keyState,
                summary: "One current issuer check for \(current.enrollment.trust.displayName). Two Site Root signatures surround one protected read. Permission expires at \(evidence.expiresAt).",
                transport: transport, nativeSession: current, ack: record, lifecycle: lifecycle)
            try await value.checkCurrent(); return value
        } catch { lifecycle.invalidate(); throw error }
    }
    func cancel() { consumed = true; lifecycle.invalidate(); nativeSession.invalidate() }
    func checkCurrent() async throws {
        do {
            try Task.checkCancellation(); let now = try lifecycle.observe()
            guard UIApplication.shared.applicationState == .active,
                  ContinuousClock().now < preparedAt.advanced(by: .seconds(30)),
                  now.timeIntervalSince1970 < Double(readiness.serverExpiry),
                  try SiteRootConvergenceAckStoreV2().current() == ack,
                  try await InstallationTrustKeychain.shared.activeEnrollment() == nativeSession.enrollment
            else { throw IssuerPhoneError.binding }
            try lifecycle.observe()
        } catch { lifecycle.invalidate(); nativeSession.invalidate(); throw error }
    }
    func bind(_ current: IssuerCeremonyLifecycle) throws { try lifecycle.bind(current) }
    @MainActor
    func consume() async throws {
        try await checkCurrent()
        let now = ContinuousClock().now
        let wallNow = Date().timeIntervalSince1970
        guard !consumed else { throw IssuerPhoneError.order }
        consumed = true
        guard now >= preparedAt, now < preparedAt.advanced(by: .seconds(30)),
              sitePublicKey.count == 33,
              IssuerPhoneWire.sha256(sitePublicKey) == readiness.siteKeyID,
              !summary.isEmpty,
              wallNow >= 0, wallNow < Double(readiness.serverExpiry),
              (readiness.mode == .admission && rootAdmissionReference == nil && expectedAdmissionBody != nil && revocationRevision == nil && keyState == nil)
                || (readiness.mode == .currentStatusPair && rootAdmissionReference?.count == 32 && expectedAdmissionBody == nil && revocationRevision != nil && keyState != nil)
        else { throw IssuerPhoneError.binding }
    }
}

/// Concrete existing-key invocation and fixed endpoint flow. Only the private
/// prepared handoff reaches it; this is neither a generic signing API nor an
/// owner factory. The same fresh context stays local to this one awaited call.
@MainActor
final class IssuerSiteRootCeremony {
    private let transport: IssuerSiteRootTransport
    private let ledger = IssuerSiteRootAttemptLedger()
    private var running = false

    init(configuration: MonasSiteRootAuthorityConfiguration) throws {
        transport = try IssuerSiteRootTransport(configuration: configuration)
    }

    private init(transport: IssuerSiteRootTransport) { self.transport = transport }
    static func prepareCurrentPair() async throws -> (IssuerSiteRootCeremony, IssuerSiteRootPreparedHandoff) {
        let prepared = try await IssuerSiteRootPreparedHandoff.current()
        return (IssuerSiteRootCeremony(transport: prepared.transport), prepared)
    }
    func prepareCurrent() async throws -> IssuerSiteRootPreparedHandoff {
        try await IssuerSiteRootPreparedHandoff.current()
    }

    /// Called only after the full prepared summary has been explicitly shown
    /// and the user chooses the separate confirmation action.
    func confirm(_ prepared: IssuerSiteRootPreparedHandoff) async throws {
        guard !running else { throw IssuerPhoneError.order }
        running = true
        // This attempt exclusively owns the prepared native session now.
        // Every exit, including pre-FaceID failure and success, wipes it.
        // The !running rejection above must not cancel another live attempt.
        defer { running = false; prepared.cancel() }
        try await prepared.consume()
        let transport = prepared.transport
        let readiness = prepared.readiness
        let clock = ContinuousClock()
        let signer = try SecureEnclaveSigner(namespace: "site-root-delegation-v1",
            authenticationReason: readiness.mode == .admission
                ? "Approve this exact issuer root admission"
                : "Approve one current issuer check: two signatures, before and after the protected read")
        // Coarse existence only, before biometric access; no creation/fallback.
        guard try signer.hasExistingKey() else { throw IssuerPhoneError.unavailable }
        try ledger.begin(readiness)
        var operation = try IssuerPhoneOperation(readiness: readiness,
            rootAdmissionReference: prepared.rootAdmissionReference, preparedAt: prepared.preparedAt)
        let reason = readiness.mode == .admission
            ? "Approve this exact issuer root admission"
            : "Approve one current issuer check: two signatures, before and after the protected read"
        let ceremony = try await FaceIDCeremonyContext.authenticate(reason: reason)
        defer { ceremony.invalidate() }
        let lifecycle = IssuerCeremonyLifecycle(ceremony: ceremony)
        try prepared.bind(lifecycle)
        try await prepared.checkCurrent()
        let observer = NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil
        ) { _ in lifecycle.invalidate() }
        defer { NotificationCenter.default.removeObserver(observer) }
        do {
            try Task.checkCancellation()
            try lifecycle.check()
            guard UIApplication.shared.applicationState == .active else { throw IssuerPhoneError.uncertain }
            // The post-Face ID timing bound begins at authentication completion,
            // before public lookup, ledger work, scheduling or network dispatch.
            try operation.faceAuthenticated(at: ceremony.authenticatedAt)
            let publicKey = try signer.publicKey(using: ceremony).compressedSEC1
            guard publicKey == prepared.sitePublicKey,
                  IssuerPhoneWire.sha256(publicKey) == readiness.siteKeyID else {
                throw IssuerPhoneError.binding
            }
            try lifecycle.check()
            try Task.checkCancellation()
            try operation.arm(at: clock.now)
            guard let deadline = operation.originalDeadline else { throw IssuerPhoneError.order }
            try await withTaskCancellationHandler {
                try await prepared.checkCurrent()
                let firstRaw = try await transport.exchange(try IssuerPhoneWire.arm(readiness), deadline: deadline)
                try await prepared.checkCurrent()
                let first = try IssuerPhoneTask(canonicalBytes: firstRaw)
                try signAndFence(first, prepared: prepared, operation: &operation,
                    signer: signer, ceremony: ceremony, lifecycle: lifecycle)
                let firstEnvelope = try operation.exactCompletedReply(for: first, at: clock.now)
                try await prepared.checkCurrent()
                let next = try await transport.exchange(try IssuerPhoneWire.signature(task: first, envelope: firstEnvelope), deadline: deadline)
                if readiness.mode == .admission {
                    try lifecycle.check()
                    try operation.finish(next, at: clock.now)
                } else {
                    try await prepared.checkCurrent()
                    let post = try IssuerPhoneTask(canonicalBytes: next)
                    try signAndFence(post, prepared: prepared, operation: &operation,
                        signer: signer, ceremony: ceremony, lifecycle: lifecycle)
                    let envelope = try operation.exactCompletedReply(for: post, at: clock.now)
                    try await prepared.checkCurrent()
                    let terminal = try await transport.exchange(try IssuerPhoneWire.signature(task: post, envelope: envelope), deadline: deadline)
                    try lifecycle.check()
                    try await prepared.checkCurrent()
                    try operation.finish(terminal, at: clock.now)
                }
                try Task.checkCancellation()
            } onCancel: {
                lifecycle.invalidate()
            }
        } catch {
            operation.lock()
            prepared.cancel()
            lifecycle.invalidate()
            // No post-expiry cancel, new query, invocation or automatic retry.
            // The durable attempt fences remain even on ambiguous completion.
            throw error
        }
    }

    private func signAndFence(_ task: IssuerPhoneTask, prepared: IssuerSiteRootPreparedHandoff,
                              operation: inout IssuerPhoneOperation, signer: SecureEnclaveSigner,
                              ceremony: FaceIDCeremonyContext, lifecycle: IssuerCeremonyLifecycle) throws {
        try Task.checkCancellation()
        try lifecycle.check()
        let wallNow = Date().timeIntervalSince1970
        guard wallNow >= 0, wallNow < Double(prepared.readiness.serverExpiry) else { throw IssuerPhoneError.expired }
        try task.body.compare(to: prepared.readiness, rootAdmissionReference: prepared.rootAdmissionReference)
        if prepared.readiness.mode == .admission {
            guard let expected = prepared.expectedAdmissionBody, task.body.canonicalBytes == expected else { throw IssuerPhoneError.binding }
        } else {
            try task.body.compareCurrentFacts(revocationRevision: prepared.revocationRevision, keyState: prepared.keyState)
        }
        try operation.beginSignature(task, at: ContinuousClock().now)
        try ledger.beforeInvocation(prepared.readiness, task: task)
        // A slow Keychain operation consumes the same original two seconds.
        try operation.checkCurrent(at: ContinuousClock().now)
        try Task.checkCancellation()
        try lifecycle.check()
        // Existing message primitive performs SHA256 exactly once. Never COSE,
        // pre-hashed input, a newly allocated key, or an authentication key.
        guard let originalDeadline = operation.originalDeadline else { throw IssuerPhoneError.order }
        let signature = try signer.sign(message: task.body.signaturePreimage, using: ceremony,
            originalDeadline: originalDeadline, cancellation: lifecycle)
        try lifecycle.check()
        let envelope = try IssuerCheckpointEnvelope.encode(body: task.body, sitePublicKey: prepared.sitePublicKey, signature: signature)
        try operation.signatureCompleted(task: task, envelope: envelope,
            sitePublicKey: prepared.sitePublicKey, at: ContinuousClock().now)
    }
}

#endif
