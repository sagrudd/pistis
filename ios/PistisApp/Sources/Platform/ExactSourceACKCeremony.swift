import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import CryptoKit
import Security
import UIKit

enum ExactSourceACKPreparationError: Error { case witnessesPending(ExactSourceACKPendingReview) }
/// Keeps the actual existing native authentication session, never a server
/// generation/ACK lease. Every retry obtains fresh owners under the old end.
@MainActor
final class ExactSourceACKPendingReview {
    fileprivate let transport: IssuerSiteRootTransport
    fileprivate let enrollment: AuthenticatedEnrollmentOutput
    fileprivate let record: SiteRootConvergenceAckRecordV2
    fileprivate let lifecycle: ExactSourceACKLifecycle
    fileprivate let end: ContinuousClock.Instant
    fileprivate let receipt: ExactSourceACKWire.PendingReviewData
    fileprivate init(transport: IssuerSiteRootTransport, enrollment: AuthenticatedEnrollmentOutput,
                     record: SiteRootConvergenceAckRecordV2, lifecycle: ExactSourceACKLifecycle,
                     end: ContinuousClock.Instant, receipt: ExactSourceACKWire.PendingReviewData) {
        self.transport = transport; self.enrollment = enrollment; self.record = record
        self.lifecycle = lifecycle; self.end = end; self.receipt = receipt
    }
    func cancel() { lifecycle.invalidate() }
}

/// One explicit, existing ACK-key operation. No raw body/token constructor,
/// registration, new key, generic signing callback or portable role owner.
@MainActor
final class ExactSourceACKCeremony {
    let summary: String
    private let task: ExactSourceACKWire.TaskData
    private let enrollment: AuthenticatedEnrollmentOutput
    private let record: SiteRootConvergenceAckRecordV2
    private let transport: IssuerSiteRootTransport
    private let end: ContinuousClock.Instant
    private let lifecycle: ExactSourceACKLifecycle
    private var consumed = false

    private init(task: ExactSourceACKWire.TaskData, enrollment: AuthenticatedEnrollmentOutput,
                 record: SiteRootConvergenceAckRecordV2, transport: IssuerSiteRootTransport,
                 end: ContinuousClock.Instant, lifecycle: ExactSourceACKLifecycle) {
        self.task = task; self.enrollment = enrollment; self.record = record
        self.transport = transport; self.end = end; self.lifecycle = lifecycle
        // Show every signed field, including the exact target, review/action,
        // installed measurement and issuer originals' digests; no hash-only title.
        summary = task.body.fields.keys.sorted().map { "\($0): \(task.body.fields[$0]!)" }.joined(separator: "\n")
            + (task.body.kind == .enrollment
               ? [("Current role", 0), ("Exact action", 1), ("Source admission", 2), ("Technical review", 3), ("Installed measurement", 4)]
               : [("Current reviewer role", 0), ("Exact reviewer action", 1), ("Admission intent", 2), ("Independent original review", 3), ("Governance witness", 4), ("Owner approval and merge witness", 5)]).map {
                "\n\n\($0.0)\n" + (String(data: task.originals[$0.1], encoding: .utf8) ?? "Bound binary original")
            }.joined()
    }
    static func prepareCurrent(kind: ExactSourceACKBody.Kind) async throws -> ExactSourceACKCeremony {
        let lifecycle = ExactSourceACKLifecycle()
        return try await withTaskCancellationHandler {
            do { return try await prepareCurrent(kind: kind, lifecycle: lifecycle) }
            catch let pending as ExactSourceACKPreparationError { throw pending }
            catch { lifecycle.invalidate(); throw error }
        } onCancel: { lifecycle.invalidate() }
    }
    static func resumeCurrent(_ pending: ExactSourceACKPendingReview) async throws -> ExactSourceACKCeremony {
        let lifecycle = pending.lifecycle
        return try await withTaskCancellationHandler {
            do { return try await prepareCurrent(kind: .technicalReview, lifecycle: lifecycle, pending: pending) }
            catch let pending as ExactSourceACKPreparationError { throw pending }
            catch { lifecycle.invalidate(); throw error }
        } onCancel: { lifecycle.invalidate() }
    }
    private static func prepareCurrent(kind: ExactSourceACKBody.Kind, lifecycle: ExactSourceACKLifecycle,
                                       pending: ExactSourceACKPendingReview? = nil) async throws -> ExactSourceACKCeremony {
        try lifecycle.observe()
        guard UIApplication.shared.applicationState == .active else { throw IssuerPhoneError.uncertain }
        let transport: IssuerSiteRootTransport
        let enrollment: AuthenticatedEnrollmentOutput
        if let pending {
            transport = pending.transport; enrollment = pending.enrollment
        } else {
            let authenticated = try await IssuerSiteRootTransport.authenticatedACKNative()
            transport = authenticated.0; enrollment = authenticated.1
        }
        try lifecycle.observe()
        let original = pending?.end ?? ContinuousClock().now.advanced(by: .seconds(30))
        guard ContinuousClock().now < original else { throw IssuerPhoneError.expired }
        let record = try SiteRootConvergenceAckStoreV2().current()
        if let pending {
            guard record == pending.record,
                  try await InstallationTrustKeychain.shared.activeEnrollment() == pending.enrollment else { throw IssuerPhoneError.binding }
            try lifecycle.observe()
        }
        guard let target = SiteRootConvergenceEncoding.base64URL(record.targetIDB64URL), target.count == 32,
              let ack = SiteRootConvergenceEncoding.base64URL(record.ackPublicKeyB64URL), ack.count == 33,
              record.siteUUID == UUID(uuidString: record.siteUUID)?.uuidString.lowercased() else { throw IssuerPhoneError.binding }
        var challenge = Data(count: 32)
        let status = challenge.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard status == errSecSuccess, !challenge.allSatisfy({ $0 == 0 }) else { throw IssuerPhoneError.unavailable }
        let request = try ExactSourceACKWire.prepare(challenge: challenge, kind: kind, target: target, generation: record.generation)
        try lifecycle.observe()
        let raw = try await transport.prepareACK(request, deadline: original)
        try lifecycle.observe()
        if let receipt = try ExactSourceACKWire.pendingReview(raw, challenge: challenge, now: unix()) {
            guard kind == .technicalReview else { throw IssuerPhoneError.binding }
            if let pending {
                guard receipt.draftID == pending.receipt.draftID,
                      receipt.subjectDigest == pending.receipt.subjectDigest,
                      receipt.expiresAt <= pending.receipt.expiresAt else { throw IssuerPhoneError.binding }
            }
            try lifecycle.observe()
            let sampled = ContinuousClock().now
            let remaining = Date(timeIntervalSince1970: Double(receipt.expiresAt)).timeIntervalSinceNow
            guard remaining > 0 else { throw IssuerPhoneError.expired }
            let end = min(original, sampled.advanced(by: .seconds(remaining)))
            throw ExactSourceACKPreparationError.witnessesPending(ExactSourceACKPendingReview(
                transport: transport, enrollment: enrollment, record: record, lifecycle: lifecycle, end: end, receipt: receipt))
        }
        let task = try ExactSourceACKWire.task(raw, challenge: challenge, kind: kind, now: unix())
        if let pending {
            guard try ExactSourceACKWire.reviewSubjectDigest(task.body) == pending.receipt.subjectDigest else { throw IssuerPhoneError.binding }
        }
        let install = try IssuerNativeSessionWire.uuid(enrollment.trust.installationID).uuidString.lowercased()
        let targetField = kind == .enrollment ? "device_target" : "reviewer_device_target"
        let generationField = kind == .enrollment ? "device_generation" : "reviewer_device_generation"
        guard task.body.fields["installation_id"] == install,
              task.body.fields["site_uuid"] == record.siteUUID,
              task.body.fields[targetField] == hex(target),
              task.body.fields[generationField] == String(record.generation),
              try SiteRootConvergenceAckStoreV2().current() == record,
              try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment else { throw IssuerPhoneError.binding }
        // Instant sampled before wall time: never extend the original window.
        let sampled = ContinuousClock().now
        let remaining = Date(timeIntervalSince1970: Double(task.expiresAt)).timeIntervalSinceNow
        guard remaining > 0 else { throw IssuerPhoneError.expired }
        try lifecycle.observe()
        let end = min(original, sampled.advanced(by: .seconds(remaining)))
        return ExactSourceACKCeremony(task: task, enrollment: enrollment, record: record,
                                      transport: transport, end: end, lifecycle: lifecycle)
    }
    /// The caller presents summary first; this separate action always requires
    /// a fresh Face ID context and consumes the operation even on ambiguity.
    func confirm() async throws {
        guard !consumed else { throw IssuerPhoneError.order }
        consumed = true
        let lifecycle = self.lifecycle
        try await withTaskCancellationHandler {
            do { try await performConfirmation(); lifecycle.invalidate() }
            catch { lifecycle.invalidate(); throw error }
        } onCancel: { lifecycle.invalidate() }
    }
    /// Explicit view dismissal terminalizes even when no async task is running.
    func cancel() { consumed = true; lifecycle.invalidate() }
    private func performConfirmation() async throws {
        try await check()
        let reason = task.body.kind == .enrollment ? "Approve this exact source issuer enrollment" : "Sign this exact source technical review"
        let signer = try SecureEnclaveSigner(namespace: "site-root-convergence-ack-v2", authenticationReason: reason)
        let root = try SecureEnclaveSigner(namespace: "site-root-delegation-v1", authenticationReason: reason)
        guard try signer.hasExistingKey(), try root.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let ceremony = try await FaceIDCeremonyContext.authenticate(reason: reason)
        defer { ceremony.invalidate() }
        let invocation = IssuerCeremonyLifecycle(ceremony: ceremony)
        try lifecycle.bind(invocation)
        defer { invocation.invalidate() }
        try await withTaskCancellationHandler {
            try await check(); try invocation.check()
            let publicKey = try signer.publicKey(using: ceremony).compressedSEC1
            let rootPublic = try root.publicKey(using: ceremony).compressedSEC1
            guard SiteRootConvergenceEncoding.base64URL(record.ackPublicKeyB64URL) == publicKey,
                  SiteRootConvergenceEncoding.base64URL(record.targetIDB64URL) == Data(SHA256.hash(data: rootPublic)) else { throw IssuerPhoneError.binding }
            let protected = try DetachedES256Cose.protectedHeaders(ackGeneration: record.generation)
            let structure = try DetachedES256Cose.signatureStructure(protected: protected, payload: task.body.original)
            try await check(); try invocation.check()
            try retainInvocation()
            let signature = try signer.sign(message: structure, using: ceremony, originalDeadline: end, cancellation: invocation)
            let proof = try DetachedES256Cose.envelope(protected: protected, signature: signature)
            guard proof.count <= 8192 else { throw IssuerPhoneError.bound }
            try await check(); try invocation.check()
            let response = try await transport.submitACK(ExactSourceACKWire.submission(task, proof: proof), deadline: end)
            try ExactSourceACKWire.accepted(response, task: task)
            try await check(); try invocation.check()
        } onCancel: { invocation.invalidate() }
    }
    private func check() async throws {
        try Task.checkCancellation()
        guard let issued = UInt64(task.body.fields["issued_at"] ?? ""),
              let bodyExpiry = UInt64(task.body.fields["expires_at"] ?? "") else { throw IssuerPhoneError.expired }
        try lifecycle.validate(issuedAt: issued, expiresAt: bodyExpiry, actionIssuedAt: task.actionIssuedAt,
            actionExpiresAt: task.actionExpiresAt, taskExpiresAt: task.expiresAt)
        guard UIApplication.shared.applicationState == .active, ContinuousClock().now < end,
              try SiteRootConvergenceAckStoreV2().current() == record,
              try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment else { throw IssuerPhoneError.expired }
        try lifecycle.validate(issuedAt: issued, expiresAt: bodyExpiry, actionIssuedAt: task.actionIssuedAt,
            actionExpiresAt: task.actionExpiresAt, taskExpiresAt: task.expiresAt)
        guard UIApplication.shared.applicationState == .active, ContinuousClock().now < end else { throw IssuerPhoneError.expired }
    }
    private func retainInvocation() throws {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
            kSecAttrService: "org.mnemosyne.pistis.exact-source-ack-invocation.v1",
            kSecAttrAccount: Self.hex(task.correlation) + "-" + Self.hex(task.challenge),
            kSecAttrSynchronizable: false, kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: task.digest]
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw IssuerPhoneError.uncertain }
    }
    private static func unix() throws -> UInt64 {
        let now = Date().timeIntervalSince1970
        guard now > 0, now < Double(UInt64.max) else { throw IssuerPhoneError.expired }
        return UInt64(now)
    }
    private static func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
}
#endif
