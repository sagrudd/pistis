import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import CryptoKit
import Security
import UIKit

/// An offline attendance operation verified against the already retained
/// installation pin. No HTTPS session, owner or secret is imported from a file.
@MainActor
final class IssuerJointRootApproval {
    let attendance: IssuerJointRootAttendance
    let installationName: String
    private let enrollment: AuthenticatedEnrollmentOutput
    private let ack: SiteRootConvergenceAckRecordV2
    private let lifecycle: ExactSourceACKLifecycle
    private let end: ContinuousClock.Instant
    private var consumed = false

    private init(attendance: IssuerJointRootAttendance, enrollment: AuthenticatedEnrollmentOutput,
                 ack: SiteRootConvergenceAckRecordV2, lifecycle: ExactSourceACKLifecycle,
                 end: ContinuousClock.Instant) {
        self.attendance = attendance; self.enrollment = enrollment; self.ack = ack
        self.lifecycle = lifecycle; self.end = end; installationName = enrollment.trust.displayName
    }
    static func prepare(fileBytes: Data) async throws -> IssuerJointRootApproval {
        let lifecycle = ExactSourceACKLifecycle()
        do {
            try Task.checkCancellation(); try lifecycle.observe()
            guard UIApplication.shared.applicationState == .active,
                  let enrollment = try await InstallationTrustKeychain.shared.activeEnrollment() else { throw IssuerPhoneError.unavailable }
            let sampled = ContinuousClock().now
            let wall = try lifecycle.observe()
            let now = try milliseconds(wall)
            let attendance = try IssuerJointRootAttendance(fileBytes: fileBytes, trust: enrollment.trust,
                responseContext: enrollment.responseContext, nowMilliseconds: now)
            let ack = try SiteRootConvergenceAckStoreV2().current()
            guard try IssuerNativeSessionWire.uuid(attendance.siteID).uuidString.lowercased() == ack.siteUUID,
                  SiteRootConvergenceEncoding.base64URL(ack.targetIDB64URL) == Data(SHA256.hash(data: attendance.sitePublicKey)),
                  attendance.expiresAtMilliseconds > now else { throw IssuerPhoneError.binding }
            let remaining = min(UInt64(30_000), attendance.expiresAtMilliseconds - now)
            let value = IssuerJointRootApproval(attendance: attendance, enrollment: enrollment,
                ack: ack, lifecycle: lifecycle, end: sampled.advanced(by: .milliseconds(Int64(remaining))))
            try await value.check(); return value
        } catch { lifecycle.invalidate(); throw error }
    }
    func cancel() { consumed = true; lifecycle.invalidate() }
    func check() async throws {
        do {
            try Task.checkCancellation(); try lifecycle.observe()
            let current = try await InstallationTrustKeychain.shared.activeEnrollment()
            let currentACK = try SiteRootConvergenceAckStoreV2().current()
            try Task.checkCancellation()
            let now = try Self.milliseconds(lifecycle.observe())
            guard UIApplication.shared.applicationState == .active, ContinuousClock().now < end,
                  attendance.issuedAtMilliseconds <= now, now < attendance.expiresAtMilliseconds,
                  current == enrollment, currentACK == ack else { throw IssuerPhoneError.binding }
        } catch { lifecycle.invalidate(); throw error }
    }
    func approve() async throws -> Data {
        guard !consumed else { throw IssuerPhoneError.order }
        consumed = true
        let lifecycle = self.lifecycle
        return try await withTaskCancellationHandler {
            do { return try await signExistingAction() }
            catch { lifecycle.invalidate(); throw error }
        } onCancel: { lifecycle.invalidate() }
    }
    private func signExistingAction() async throws -> Data {
        try await check()
        let reason = "Approve current issuer status and continue the unchanged Root permission"
        let signer = try SecureEnclaveSigner(namespace: IssuerNativeSessionWire.hex(enrollment.trust.installationID), authenticationReason: reason)
        let root = try SecureEnclaveSigner(namespace: "site-root-delegation-v1", authenticationReason: reason)
        guard try signer.hasExistingKey(), try root.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let issued = try Self.milliseconds(lifecycle.observe())
        let ceremony = try await FaceIDCeremonyContext.authenticate(reason: reason)
        defer { ceremony.invalidate() }
        let invocation = IssuerCeremonyLifecycle(ceremony: ceremony)
        try lifecycle.bind(invocation); defer { invocation.invalidate() }
        // Existing-key lookup and one signature share the unchanged post-FaceID
        // bound. The public response remains a bounded offline DATA carrier.
        let signingEnd = min(end, ceremony.authenticatedAt.advanced(by: .seconds(2)))
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd,
              try signer.publicKey(using: ceremony).compressedSEC1 == attendance.devicePublicKey,
              try root.publicKey(using: ceremony).compressedSEC1 == attendance.sitePublicKey else { throw IssuerPhoneError.binding }
        let verified = try Self.milliseconds(lifecycle.observe())
        let payload = try attendance.approvedResponsePayload(issuedAt: issued, verifiedAt: verified)
        let structure = try CoseSign1.signatureStructure(keyID: attendance.deviceKeyID, payload: payload)
        // Exact final wire capacity is checked before the signing fence/effect.
        var placeholder = Data(repeating: 0, count: 64); placeholder[31] = 1; placeholder[63] = 1
        let sized = try CoseSign1(keyID: attendance.deviceKeyID, payload: payload, signature: placeholder).encoded()
        _ = try attendance.original(signedResponse: sized)
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd else { throw IssuerPhoneError.expired }
        try claimAttempt()
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd else { throw IssuerPhoneError.expired }
        let signature = try signer.sign(message: structure, using: ceremony,
            originalDeadline: signingEnd, cancellation: invocation)
        let response = try CoseSign1(keyID: attendance.deviceKeyID, payload: payload, signature: signature).encoded()
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd else { throw IssuerPhoneError.uncertain }
        return try attendance.original(signedResponse: response)
    }
    private func claimAttempt() throws {
        let digest = Data(SHA256.hash(data: attendance.controlOriginal + attendance.signedChallenge))
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "org.mnemosyne.pistis.issuer-joint-root-attendance.v1",
            kSecAttrAccount: IssuerNativeSessionWire.hex(digest),
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: digest,
        ]
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw IssuerPhoneError.uncertain }
    }
    private static func milliseconds(_ wall: Date) throws -> UInt64 {
        let value = wall.timeIntervalSince1970 * 1000
        guard value.isFinite, value >= 0, value < Double(UInt64.max) else { throw IssuerPhoneError.expired }
        return UInt64(value)
    }
}
#endif
