import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import CryptoKit
import Security
import UIKit

/// One explicit native-purpose ACK operation. The public task never appoints
/// its signing key: retained enrollment, existing ACK and existing SiteRoot are
/// compared independently before and after the attended signing effect.
@MainActor
final class IssuerNativePurposeApproval {
    let task: NativeInstallApprovalTask
    let installationName: String
    let summary: String
    private let enrollment: AuthenticatedEnrollmentOutput
    private let ack: SiteRootConvergenceAckRecordV2
    private let lifecycle: ExactSourceACKLifecycle
    private let end: ContinuousClock.Instant
    private let transport: IssuerSiteRootTransport
    private let phoneNonce: Data
    private var consumed = false

    private init(task: NativeInstallApprovalTask, enrollment: AuthenticatedEnrollmentOutput,
                 ack: SiteRootConvergenceAckRecordV2, lifecycle: ExactSourceACKLifecycle,
                 end: ContinuousClock.Instant, transport: IssuerSiteRootTransport, phoneNonce: Data) {
        self.task = task; self.enrollment = enrollment; self.ack = ack
        self.lifecycle = lifecycle; self.end = end
        self.transport = transport; self.phoneNonce = phoneNonce
        installationName = enrollment.trust.displayName
        summary = "Install new native issuer purposes for \(installationName) / \(task.siteLabel)."
            + "\nSource: \(task.sourceRepository) @ \(Self.hex(task.sourceRevision))"
            + "\nInstallation: \(Self.hex(task.installationID))\nSite: \(Self.hex(task.siteID))"
            + "\nNative target: \(Self.hex(task.nativeTarget))"
            + "\nLifecycle: \(Self.hex(task.lifecycle))"
            + task.requestedKeys.map { "\n\($0.role): ES256, requested generation 1, \($0.purposes.joined(separator: ", "))\nPublic key: \(Self.hex($0.publicKey))" }.joined()
            + "\nInitialize only through this fresh approval and an independent existing issuance checkpoint at commit."
            + "\nRecovery is not authorized. Restart, loss, rollback or uncertain consumption must remain locked."
            + "\nInstalled measurement\n" + String(decoding: task.measurementOriginal, as: UTF8.self)
            + "\nCustody placement (canonical CBOR)\n" + Self.hex(task.placementOriginal)
            + "\nExact approval body SHA-256: \(Self.hex(task.bodyDigest))"
    }

    static func prepareCurrent(plan: NativeInstallApprovalWire.Plan) async throws -> IssuerNativePurposeApproval {
        let lifecycle = ExactSourceACKLifecycle()
        do {
            try Task.checkCancellation(); try lifecycle.observe()
            guard UIApplication.shared.applicationState == .active else { throw IssuerPhoneError.unavailable }
            let authenticated = try await IssuerSiteRootTransport.authenticatedACKNative()
            let transport = authenticated.0, enrollment = authenticated.1
            guard try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment else { throw IssuerPhoneError.binding }
            try Task.checkCancellation(); try lifecycle.observe()
            let originalEnd = ContinuousClock().now.advanced(by: .seconds(30))
            var phoneNonce = Data(count: 32)
            let randomStatus = phoneNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
            guard randomStatus == errSecSuccess, !phoneNonce.allSatisfy({ $0 == 0 }) else { throw IssuerPhoneError.unavailable }
            let request = try NativeInstallApprovalWire.prepare(plan: plan, phoneNonce: phoneNonce)
            let taskBytes = try await transport.prepareNativePurpose(request, deadline: originalEnd)
            try Task.checkCancellation(); try lifecycle.observe()
            let sampled = ContinuousClock().now
            let wall = try lifecycle.observe()
            let now = try unix(wall)
            let task = try NativeInstallApprovalTask(canonicalBytes: taskBytes, now: now)
            guard task.nonce != phoneNonce else { throw IssuerPhoneError.binding }
            let ack = try SiteRootConvergenceAckStoreV2().current()
            guard task.installationID == enrollment.trust.installationID,
                  try IssuerNativeSessionWire.uuid(task.siteID).uuidString.lowercased() == ack.siteUUID,
                  SiteRootConvergenceEncoding.base64URL(ack.targetIDB64URL) == task.acknowledgementTarget,
                  ack.generation == task.acknowledgementGeneration,
                  SiteRootConvergenceEncoding.base64URL(ack.ackPublicKeyB64URL) == task.acknowledgementPublicKey else { throw IssuerPhoneError.binding }
            // Sample monotonic time before wall time and preserve this end
            // across review and Face ID; neither activity renews the task.
            let remaining = Date(timeIntervalSince1970: Double(task.expiresAt)).timeIntervalSince(wall)
            guard remaining > 0, remaining <= 30 else { throw IssuerPhoneError.expired }
            let value = IssuerNativePurposeApproval(task: task, enrollment: enrollment, ack: ack,
                lifecycle: lifecycle, end: min(originalEnd, sampled.advanced(by: .seconds(remaining))),
                transport: transport, phoneNonce: phoneNonce)
            try await value.check(); return value
        } catch { lifecycle.invalidate(); throw error }
    }
    func cancel() { consumed = true; lifecycle.invalidate() }
    private func check() async throws {
        try Task.checkCancellation(); try lifecycle.observe()
        guard UIApplication.shared.applicationState == .active, ContinuousClock().now < end,
              try Self.unix(lifecycle.observe()) < task.expiresAt,
              try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment,
              try SiteRootConvergenceAckStoreV2().current() == ack else { throw IssuerPhoneError.expired }
        try Task.checkCancellation(); try lifecycle.observe()
        guard UIApplication.shared.applicationState == .active, ContinuousClock().now < end else { throw IssuerPhoneError.expired }
    }

    /// The review UI must call this separate action. An error or cancellation
    /// consumes the operation; no cached proof or retry resurrects it.
    func approve() async throws {
        guard !consumed else { throw IssuerPhoneError.order }
        consumed = true
        let lifecycle = self.lifecycle
        try await withTaskCancellationHandler {
            do {
                let proof = try await signExactBody()
                try await check()
                let submission = try NativeInstallApprovalWire.submission(task: task,
                    phoneNonce: phoneNonce, detachedACKProof: proof)
                // The retained native session authenticates again on the same
                // session UUID; this does not perform another login or renew
                // the public task. The server must acquire new short owners.
                let receipt = try await transport.submitNativePurpose(submission, deadline: end)
                try NativeInstallApprovalWire.accepted(receipt, task: task, phoneNonce: phoneNonce)
                try await check()
                lifecycle.invalidate()
            } catch { lifecycle.invalidate(); throw error }
        } onCancel: { lifecycle.invalidate() }
    }
    private func signExactBody() async throws -> Data {
        try await check()
        let reason = "Approve these new native issuer purposes"
        let signer = try SecureEnclaveSigner(namespace: "site-root-convergence-ack-v2", authenticationReason: reason)
        let root = try SecureEnclaveSigner(namespace: "site-root-delegation-v1", authenticationReason: reason)
        guard try signer.hasExistingKey(), try root.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let ceremony = try await FaceIDCeremonyContext.authenticate(reason: reason)
        defer { ceremony.invalidate() }
        let invocation = IssuerCeremonyLifecycle(ceremony: ceremony)
        try lifecycle.bind(invocation); defer { invocation.invalidate() }
        let signingEnd = min(end, ceremony.authenticatedAt.advanced(by: .seconds(2)))
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd,
              try signer.publicKey(using: ceremony).compressedSEC1 == task.acknowledgementPublicKey,
              try root.publicKey(using: ceremony).compressedSEC1 == task.siteRootPublicKey else { throw IssuerPhoneError.binding }
        let headers = try DetachedES256Cose.protectedHeaders(ackGeneration: ack.generation)
        let structure = try DetachedES256Cose.signatureStructure(protected: headers, payload: task.bodyOriginal)
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd else { throw IssuerPhoneError.expired }
        try claimAttempt()
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd else { throw IssuerPhoneError.expired }
        let signature = try signer.sign(message: structure, using: ceremony,
            originalDeadline: signingEnd, cancellation: invocation,
            expectedPublicKey: task.acknowledgementPublicKey)
        let proof = try DetachedES256Cose.envelope(protected: headers, signature: signature)
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd, proof.count == 83 else { throw IssuerPhoneError.uncertain }
        return proof
    }
    private func claimAttempt() throws {
        // Stable lifecycle, rather than a fresh task/grant/key UUID, prevents
        // another native initialization attempt from escaping uncertainty.
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
            kSecAttrService: "org.mnemosyne.pistis.native-purpose-invocation.v1",
            kSecAttrAccount: Self.hex(task.lifecycle), kSecAttrSynchronizable: false,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: task.bodyDigest]
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw IssuerPhoneError.uncertain }
    }
    private static func unix(_ wall: Date) throws -> UInt64 {
        let seconds = wall.timeIntervalSince1970
        guard seconds.isFinite, seconds > 0, seconds < Double(UInt64.max) else { throw IssuerPhoneError.expired }
        return UInt64(seconds)
    }
    private static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
}
#endif
