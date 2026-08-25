import CryptoKit
import Foundation

protocol SiteX509BrokerContinuationAuthorizingV2: Sendable {
    func attendedUnlock(
        _ payload: Data, role: SiteX509AttendedUnlockRoleV2
    ) throws -> Data
    func prepareAckRegistration(expectedSiteUUID: String) throws
    func ackRegistration(_ payload: Data) throws -> Data
    func leafApproval(_ payload: Data) throws -> Data
}

private struct PendingBrokerAckRegistrationV2: Sendable {
    let siteUUID: String
    let siteUUIDBytes: Data
    let targetID: Data
    let ackPublicKeyCompressedSEC1: Data
}

struct SiteRootAckRegistrationBrokerPresentationV2: Sendable {
    let siteUUID: String
    let siteUUIDBytes: Data
    let targetID: Data

    init(data: Data, expectedSiteUUID: String, expectedTargetID: Data) throws {
        let object: [String: StrictJSONObject.Value]
        do { object = try StrictJSONObject(data: data, maximumBytes: 2_048).values }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
        guard Set(object.keys) == [
            "schema", "site_uuid", "target_id_b64url", "purpose",
        ], SiteRootConvergenceEncoding.string(object, "schema")
            == "monas.site-root-convergence-ack-registration-presentation.v2",
        SiteRootConvergenceEncoding.string(object, "purpose")
            == SiteRootConvergenceProfileV2.ackPurpose,
        let site = SiteRootConvergenceEncoding.string(object, "site_uuid"),
        site == expectedSiteUUID,
        let siteBytes = SiteRootConvergenceEncoding.uuidBytes(site),
        let target = SiteRootConvergenceEncoding.bytes(
            object, "target_id_b64url", count: 32, nonzero: true
        ), target == expectedTargetID
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        siteUUID = site
        siteUUIDBytes = siteBytes
        targetID = target
    }
}

final class SecureEnclaveSiteX509BrokerContinuationAuthorizerV2:
    SiteX509BrokerContinuationAuthorizingV2, @unchecked Sendable
{
    private let ceremony: FaceIDCeremonyContext
    private let store: SiteRootConvergenceAckStoreV2
    private var pendingAck: PendingBrokerAckRegistrationV2?

    init(ceremony: FaceIDCeremonyContext, store: SiteRootConvergenceAckStoreV2) {
        self.ceremony = ceremony
        self.store = store
    }

    func attendedUnlock(
        _ payload: Data, role: SiteX509AttendedUnlockRoleV2
    ) throws -> Data {
        let presentation = try SiteX509AttendedUnlockPresentationV2(
            data: payload, expectedRole: role,
            nowUnixSeconds: SiteRootConvergenceServiceV2.nowUnixSeconds()
        )
        let submission = try SecureEnclaveSiteX509AttendedUnlockProducerV2(role: role)
            .produce(presentation, using: ceremony)
        return try JSONEncoder().encode(submission)
    }

    func prepareAckRegistration(expectedSiteUUID: String) throws {
        guard pendingAck == nil,
              let siteUUIDBytes = SiteRootConvergenceEncoding.uuidBytes(expectedSiteUUID)
        else {
            if pendingAck?.siteUUID == expectedSiteUUID { return }
            throw PlatformFailure.invalidConfiguration
        }
        let siteRoot = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Register the Site Root acknowledgement key"
        )
        let ack = try SecureEnclaveSigner(
            namespace: "site-root-convergence-ack-v2",
            authenticationReason: "Register the Site Root acknowledgement key"
        )
        guard try siteRoot.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let siteRootPublic = try siteRoot.publicKey(using: ceremony)
        let target = Data(SHA256.hash(data: siteRootPublic.compressedSEC1))
        let ackPublic = try ack.create(using: ceremony).compressedSEC1
        pendingAck = PendingBrokerAckRegistrationV2(
            siteUUID: expectedSiteUUID,
            siteUUIDBytes: siteUUIDBytes,
            targetID: target,
            ackPublicKeyCompressedSEC1: ackPublic
        )
    }

    func ackRegistration(_ payload: Data) throws -> Data {
        guard let pendingAck else { throw PlatformFailure.invalidConfiguration }
        let presentation = try SiteRootAckRegistrationBrokerPresentationV2(
            data: payload,
            expectedSiteUUID: pendingAck.siteUUID,
            expectedTargetID: pendingAck.targetID
        )
        let siteRoot = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Register the Site Root acknowledgement key"
        )
        let registrationPayload = Data("PXAK/v2".utf8) + presentation.siteUUIDBytes
            + presentation.targetID + pendingAck.ackPublicKeyCompressedSEC1
        guard registrationPayload.count == 88 else {
            throw PlatformFailure.invalidConfiguration
        }
        let protected = try DetachedES256Cose.protectedHeaders(
            kid: presentation.targetID,
            contentType: SiteRootConvergenceProfileV2.pxakContentType
        )
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: registrationPayload
        )
        let signature = try siteRoot.sign(message: structure, using: ceremony)
        let proof = try DetachedES256Cose.envelope(
            protected: protected, signature: signature
        )
        let body: [String: Any] = [
            "schema": "monas.site-root-convergence-ack-registration.v2",
            "site_uuid": presentation.siteUUID,
            "target_id_b64url": SiteRootConvergenceEncoding.encode(presentation.targetID),
            "purpose": SiteRootConvergenceProfileV2.ackPurpose,
            "ack_public_key_compressed_sec1_b64url": SiteRootConvergenceEncoding.encode(
                pendingAck.ackPublicKeyCompressedSEC1
            ),
            "enrolled_device_proof_cose_b64url": SiteRootConvergenceEncoding.encode(proof),
        ]
        guard JSONSerialization.isValidJSONObject(body) else {
            throw PlatformFailure.invalidConfiguration
        }
        let encoded = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        guard !encoded.isEmpty, encoded.count <= 2_048 else {
            throw PlatformFailure.invalidConfiguration
        }
        return encoded
    }

    func leafApproval(_ payload: Data) throws -> Data {
        guard let pendingAck else { throw PlatformFailure.invalidConfiguration }
        let presentation = try SiteX509LeafApprovalPresentationV1(
            data: payload,
            nowUnixSeconds: SiteRootConvergenceServiceV2.nowUnixSeconds()
        )
        let record = SiteRootConvergenceAckRecordV2(
            siteUUID: pendingAck.siteUUID,
            targetIDB64URL: SiteRootConvergenceEncoding.encode(pendingAck.targetID),
            ackPublicKeyB64URL: SiteRootConvergenceEncoding.encode(
                pendingAck.ackPublicKeyCompressedSEC1
            ),
            generation: presentation.deviceKeyGeneration
        )
        try presentation.validateCurrentSigner(record)
        try store.retain(record)
        let submission = try SecureEnclaveSiteX509LeafApprovalProducerV1(store: store)
            .produce(presentation, using: ceremony)
        return try JSONEncoder().encode(submission)
    }
}
