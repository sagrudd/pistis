import CryptoKit
import Foundation

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
