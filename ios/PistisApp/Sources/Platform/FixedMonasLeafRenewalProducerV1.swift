import CryptoKit
import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import Security
import UIKit

/// One fresh, no-create, three-key authorization for the exact v2 transcript.
@MainActor
final class FixedMonasLeafRenewalProducerV2 {
    func produce(_ presentation: FixedMonasLeafRenewalPresentationV2,
                 independentlyReadDigest: String) async throws -> Data {
        let digest = Data(SHA256.hash(data: presentation.exactBytes))
        guard digest.map({ String(format: "%02x", $0) }).joined() == independentlyReadDigest,
              let enrollment = try await InstallationTrustKeychain.shared.activeEnrollment() else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let statement = presentation.statement
        let sampled = ContinuousClock().now
        let wall = Date().timeIntervalSince1970
        guard wall.isFinite, wall >= Double(statement.prior.issuedAt), wall < Double(statement.prior.expiresAt) else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let remaining = Double(statement.prior.expiresAt) - wall
        let operationEnd = sampled.advanced(by: .milliseconds(Int64(remaining * 1000)))
        let ackStore = SiteRootConvergenceAckStoreV2()
        let ack = try ackStore.current(siteUUID: statement.prior.siteUUID)
        try statement.prior.validateCurrentSigner(ack)
        guard enrollment.trust.installationID == statement.installationUUID,
              enrollment.responseContext.userID == statement.prior.subjectUUID,
              enrollment.responseContext.deviceID == statement.prior.deviceUUID,
              enrollment.responseContext.deviceKeyID == Data(SHA256.hash(data: Data("pistis:key-id:v1\u{0}".utf8) + statement.devicePoint)),
              enrollment.trust.revocationGeneration == statement.prior.ownerGenerations[2],
              enrollment.trust.policyGeneration == statement.prior.ownerGenerations[4],
              SiteRootConvergenceEncoding.base64URL(ack.targetIDB64URL) == Data(SHA256.hash(data: statement.rootPoint)),
              SiteRootConvergenceEncoding.base64URL(ack.ackPublicKeyB64URL) == statement.ackPoint else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let lifecycle = ExactSourceACKLifecycle()
        defer { lifecycle.invalidate() }
        return try await withTaskCancellationHandler {
        var claimed = false
        do {
        @MainActor func check() async throws {
            try Task.checkCancellation(); try lifecycle.observe()
            let now = Date().timeIntervalSince1970
            guard UIApplication.shared.applicationState == .active,
                  try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment,
                  try ackStore.current(siteUUID: statement.prior.siteUUID) == ack,
                  ContinuousClock().now < operationEnd,
                  now >= Double(statement.prior.issuedAt), now < Double(statement.prior.expiresAt) else {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
        }
        try await check()
        let reason = "Approve the displayed Monas HTTPS certificate successor"
        let signers = try [
            SecureEnclaveSigner(namespace: IssuerNativeSessionWire.hex(enrollment.trust.installationID), authenticationReason: reason),
            SecureEnclaveSigner(namespace: "site-root-delegation-v1", authenticationReason: reason),
            SecureEnclaveSigner(namespace: "site-root-convergence-ack-v2", authenticationReason: reason)
        ]
        guard try signers.allSatisfy({ try $0.hasExistingKey() }) else { throw PlatformFailure.keyNotFound }
        let ceremony = try await FaceIDCeremonyContext.authenticate(reason: reason)
        defer { ceremony.invalidate() }
        let invocation = IssuerCeremonyLifecycle(ceremony: ceremony)
        try lifecycle.bind(invocation); defer { invocation.invalidate() }
        let signingEnd = min(operationEnd, ceremony.authenticatedAt.advanced(by: .seconds(2)))
        let points = [statement.devicePoint, statement.rootPoint, statement.ackPoint]
        for (signer, expected) in zip(signers, points) {
            try await check(); try invocation.check()
            guard ContinuousClock().now < signingEnd,
                  try signer.publicKey(using: ceremony).compressedSEC1 == expected else { throw IssuerPhoneError.binding }
        }
        let claim = Data(SHA256.hash(data: statement.exactBytes))
        let claimIdentity = Data(SHA256.hash(data: statement.prior.siteUUID + statement.prior.transaction))
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
            kSecAttrService: "org.mnemosyne.pistis.fixed-monas-renewal.v2",
            kSecAttrAccount: IssuerNativeSessionWire.hex(claimIdentity),
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecValueData: claim]
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw IssuerPhoneError.uncertain }
        claimed = true
        var proof = Data("PXRP/v2\u{1}".utf8)
        for (index, role) in [FixedMonasLeafRenewalV2.Role.device, .root, .ack].enumerated() {
            try await check(); try invocation.check()
            guard ContinuousClock().now < signingEnd else { throw IssuerPhoneError.uncertain }
            let signature = try signers[index].sign(message: statement.rolePayload(role), using: ceremony,
                originalDeadline: signingEnd, cancellation: invocation, expectedPublicKey: points[index])
            proof.append(signature)
            try await check(); try invocation.check()
            guard ContinuousClock().now < signingEnd else { throw IssuerPhoneError.uncertain }
            for (signer, expected) in zip(signers, points) {
                guard try signer.publicKey(using: ceremony).compressedSEC1 == expected,
                      ContinuousClock().now < signingEnd else { throw IssuerPhoneError.uncertain }
            }
        }
        try await check(); try invocation.check()
        guard ContinuousClock().now < signingEnd else { throw IssuerPhoneError.uncertain }
        return proof
        } catch {
            if claimed { throw IssuerPhoneError.uncertain }
            throw error
        }
        } onCancel: { lifecycle.invalidate() }
    }
}
#endif

/// Produces only the offline renewal proof. It does not perform App Attest,
/// connect to the expired service, or establish issuer/activation readiness.
final class FixedMonasLeafRenewalProducerV1: @unchecked Sendable {
    private let store: SiteRootConvergenceAckStoreV2

    init(store: SiteRootConvergenceAckStoreV2 = SiteRootConvergenceAckStoreV2()) {
        self.store = store
    }

    static func matchesIndependentDigest(_ supplied: String,
                                         presentation: FixedMonasLeafRenewalPresentationV1) -> Bool {
        supplied == SHA256.hash(data: presentation.exactBytes)
            .map { String(format: "%02x", $0) }.joined()
    }

    func produce(_ presentation: FixedMonasLeafRenewalPresentationV1,
                 independentlyReadDigest: String) async throws -> Data {
        guard Self.matchesIndependentDigest(independentlyReadDigest, presentation: presentation) else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let first = try store.current(siteUUID: presentation.statement.siteUUID)
        try presentation.statement.validateCurrentSigner(first)
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Approve the displayed Monas HTTPS certificate successor"
        )
        let current = try store.current(siteUUID: presentation.statement.siteUUID)
        guard current == first else { throw PlatformFailure.siteRootAuthorityUnavailable }
        try presentation.statement.validateCurrentSigner(current)
        let time = Date().timeIntervalSince1970
        guard time >= 0, time < Double(presentation.statement.expiresAt) else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let signer = try SecureEnclaveSigner(
            namespace: "site-root-convergence-ack-v2",
            authenticationReason: "Approve this exact Monas HTTPS certificate successor"
        )
        guard try signer.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let publicKey = try signer.publicKey(using: ceremony).compressedSEC1
        guard SiteRootConvergenceEncoding.base64URL(current.ackPublicKeyB64URL) == publicKey else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let protected = try DetachedES256Cose.protectedHeaders(
            kid: current.generation.bigEndianData,
            contentType: FixedMonasLeafRenewalV1.contentType
        )
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: presentation.statement.exactBytes
        )
        let signature = try signer.sign(message: structure, using: ceremony)
        guard try store.current(siteUUID: presentation.statement.siteUUID) == current,
              Date().timeIntervalSince1970 < Double(presentation.statement.expiresAt) else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        return try DetachedES256Cose.envelope(protected: protected, signature: signature)
    }
}
