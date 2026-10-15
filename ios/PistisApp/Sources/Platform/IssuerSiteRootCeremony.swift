import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import CryptoKit
import UIKit

/// Private immutable handoff, deliberately without a raw/public constructor.
/// A real producer must bind these facts to existing Site owner, current session,
/// device, mode-specific permission and exact originals before presentation.
/// Pinned TLS, a response DTO or redacted installation history cannot do that.
final class IssuerSiteRootPreparedHandoff {
    let readiness: IssuerPhoneReadiness
    let preparedAt: ContinuousClock.Instant
    let sitePublicKey: Data
    let rootAdmissionReference: Data?
    let expectedAdmissionBody: Data?
    let revocationRevision: UInt64?
    let keyState: UInt64?
    let summary: String
    private var consumed = false

    private init(readiness: IssuerPhoneReadiness, preparedAt: ContinuousClock.Instant,
                 sitePublicKey: Data, rootAdmissionReference: Data?, expectedAdmissionBody: Data?,
                 revocationRevision: UInt64?, keyState: UInt64?, summary: String) {
        self.readiness = readiness
        self.preparedAt = preparedAt
        self.sitePublicKey = sitePublicKey
        self.rootAdmissionReference = rootAdmissionReference
        self.expectedAdmissionBody = expectedAdmissionBody
        self.revocationRevision = revocationRevision
        self.keyState = keyState
        self.summary = summary
    }
    /// There is no implemented independently admitted owner-evidence port in
    /// the adopted baseline. Keep this fixed ingress closed until its genuine
    /// producer is linked; never substitute a callback, body flag or TLS pin.
    static func current() throws -> IssuerSiteRootPreparedHandoff {
        throw IssuerPhoneError.unavailable
    }
    @MainActor
    func consume() throws {
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

    func prepareCurrent() throws -> IssuerSiteRootPreparedHandoff {
        try IssuerSiteRootPreparedHandoff.current()
    }

    /// Called only after the full prepared summary has been explicitly shown
    /// and the user chooses the separate confirmation action.
    func confirm(_ prepared: IssuerSiteRootPreparedHandoff) async throws {
        guard !running else { throw IssuerPhoneError.order }
        running = true
        defer { running = false }
        try prepared.consume()
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
                let firstRaw = try await transport.exchange(try IssuerPhoneWire.arm(readiness), deadline: deadline)
                let first = try IssuerPhoneTask(canonicalBytes: firstRaw)
                try signAndFence(first, prepared: prepared, operation: &operation,
                    signer: signer, ceremony: ceremony, lifecycle: lifecycle)
                let firstEnvelope = try operation.exactCompletedReply(for: first, at: clock.now)
                let next = try await transport.exchange(try IssuerPhoneWire.signature(task: first, envelope: firstEnvelope), deadline: deadline)
                if readiness.mode == .admission {
                    try lifecycle.check()
                    try operation.finish(next, at: clock.now)
                } else {
                    let post = try IssuerPhoneTask(canonicalBytes: next)
                    try signAndFence(post, prepared: prepared, operation: &operation,
                        signer: signer, ceremony: ceremony, lifecycle: lifecycle)
                    let envelope = try operation.exactCompletedReply(for: post, at: clock.now)
                    let terminal = try await transport.exchange(try IssuerPhoneWire.signature(task: post, envelope: envelope), deadline: deadline)
                    try lifecycle.check()
                    try operation.finish(terminal, at: clock.now)
                }
                try Task.checkCancellation()
            } onCancel: {
                lifecycle.invalidate()
            }
        } catch {
            operation.lock()
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
