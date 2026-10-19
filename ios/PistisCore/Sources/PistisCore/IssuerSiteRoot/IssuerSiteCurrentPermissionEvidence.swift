import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Complete cryptographic comparison DATA. This is not a current Core owner:
/// the fixed server pipeline must still hold the real permission/native owners
/// before dispatching each task, and the phone retains its actual own session.
public struct IssuerSiteCurrentPermissionEvidence: Sendable {
    public let sitePublicKey: Data
    public let rootAdmissionOriginal: Data
    public let rootAdmissionReference: Data
    public let revocationRevision: UInt64
    public let keyState: UInt64
    public let expiresAt: UInt64
    public init(readiness: IssuerPhoneReadiness, trust: InstallationTrustRecord,
                responseContext: DeviceResponseContext, currentACKTarget: Data,
                policyGeneration: UInt64, revocationGeneration: UInt64,
                nowMilliseconds: UInt64) throws {
        guard readiness.mode == .currentStatusPair, trust.active,
              Date(timeIntervalSince1970: Double(nowMilliseconds) / 1000) < trust.expiresAt
        else { throw IssuerPhoneError.expired }
        let evidence = try IssuerCBOR.decode(readiness.ownerEvidence, maximum: 65_536).array(7)
        guard evidence[0] == .unsigned(1),
              try evidence[1].bytes() == Data("issuer-site-current-owner-evidence-v1".utf8)
        else { throw IssuerPhoneError.binding }
        let admission = try evidence[2].bytes(range: 1 ... 16_384)
        let original = try evidence[3].bytes(range: 1 ... 16_384)
        let scopeBytes = try evidence[4].bytes(range: 1 ... 2048)
        let approval = try Self.verifyApproval(original, trust: trust, context: responseContext)
        let joint = try IssuerCBOR.decode(approval.controlOriginal).array(13)
        let status = try IssuerCBOR.decode(joint[3].bytes()).array(7)
        guard try status[2].bytes() == scopeBytes else { throw IssuerPhoneError.binding }
        let scope = try IssuerCBOR.decode(scopeBytes).array(16)
        let end = try scope[13].uint()
        guard try scope[3].bytes(16) == trust.userID,
              try scope[4].bytes() == readiness.installation,
              try scope[5].bytes(16) == readiness.siteID,
              try scope[6].bytes(32) == readiness.siteKeyID,
              try scope[7].bytes(32) == Data(SHA256.hash(data: admission)),
              try scope[8].bytes(16) == readiness.authorityID,
              try scope[9].uint() == readiness.authorityEpoch,
              try scope[10].uint() == readiness.keyGeneration,
              try scope[11].bytes(32) == readiness.keyID,
              try scope[12].uint() <= nowMilliseconds / 1000,
              nowMilliseconds / 1000 < end, readiness.serverExpiry <= end,
              try scope[14].uint() == policyGeneration,
              try scope[15].uint() == revocationGeneration,
              currentACKTarget.count == 32,
              currentACKTarget == Data(SHA256.hash(data: approval.sitePublicKey)),
              currentACKTarget == readiness.siteKeyID,
              approval.siteID == readiness.siteID
        else { throw IssuerPhoneError.binding }
        let envelope = try IssuerCBOR.decode(admission, maximum: 16_384).array(3)
        let body = try IssuerCheckpointBody(canonicalBytes: envelope[0].encoded(maximum: 8192), kind: .admission)
        try IssuerCheckpointEnvelope.verify(admission, body: body, sitePublicKey: approval.sitePublicKey)
        guard try body.fields[1].bytes(16) == readiness.authorityID,
              try body.fields[2].bytes() == readiness.installation,
              try body.fields[3].bytes() == readiness.siteLabel,
              try body.fields[6].uint() == readiness.authorityEpoch,
              try body.fields[13].bytes(32) == joint[5].bytes(32),
              try joint[7].bytes(32) == Data(SHA256.hash(data: admission)),
              readiness.keyGeneration == 1,
              IssuerPhoneWire.sha256(try body.fields[8].bytes(33)) == readiness.keyID
        else { throw IssuerPhoneError.binding }
        // Initial W is the supported admitted generation. Later rotations need
        // their actual retained transition history, never a relabeled IADM.
        sitePublicKey = approval.sitePublicKey; rootAdmissionOriginal = admission
        rootAdmissionReference = IssuerCheckpointEnvelope.reference(admission, kind: .admission)
        revocationRevision = try evidence[5].uint(); keyState = try evidence[6].uint(1 ... 3)
        expiresAt = end
    }
    private static func verifyApproval(_ raw: Data, trust: InstallationTrustRecord,
                                       context: DeviceResponseContext) throws -> IssuerJointRootAttendance {
        let original = try IssuerCBOR.decode(raw, maximum: 16_384).array(4)
        guard original[0] == .unsigned(1) else { throw IssuerPhoneError.binding }
        let control = try original[1].bytes(), challengeBytes = try original[2].bytes()
        let challenge = try CoseSign1.decode(challengeBytes)
        let challengeFields = try JointActionCBOR.decode(challenge.payload).map(15)
        let issued = try challengeFields[2].number()
        // Verify historical attendance at its signed creation time. This
        // returns comparison DATA only; currentness comes from the new actual
        // session, current permission and scope expiry checked by the caller.
        let wrapper = try IssuerCBOR.array([.unsigned(1),
            .bytes(Data("pistis-issuer-joint-root-attendance.v1".utf8)),
            .bytes(control), .bytes(challengeBytes)]).encoded(maximum: 24_576)
        let approval = try IssuerJointRootAttendance(fileBytes: wrapper, trust: trust,
            responseContext: context, nowMilliseconds: issued)
        let response = try CoseSign1.decode(original[3].bytes())
        let fields = try JointActionCBOR.decode(response.payload).map(13)
        guard response.keyID == approval.deviceKeyID,
              response.payload == (try approval.approvedResponsePayload(
                issuedAt: fields[2].number(), verifiedAt: fields[3].number()))
        else { throw IssuerPhoneError.binding }
        let key = try P256.Signing.PublicKey(compressedRepresentation: approval.devicePublicKey)
        guard key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: response.signature),
                                  for: response.signatureStructure()) else { throw IssuerPhoneError.binding }
        return approval
    }
}
