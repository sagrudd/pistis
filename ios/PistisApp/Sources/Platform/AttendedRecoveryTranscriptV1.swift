import CryptoKit
import Foundation

/// Inactive encoding primitive; the transcript and QR are not host authority.
struct AttendedRecoveryTranscriptV1 {
    let nonce: Data
    let operation: Data
    let correlation: Data
    let reference: String
    let site: String
    let installation: Data
    let appAttestKeyID: Data
    let siteRootPublicKey: Data
    let ownerTransaction: Data
    let ownerResult: Data
    let endpointCommitment: Data
    let rendezvousCommitment: Data
    let expiry: UInt64

    func bytes() throws -> Data {
        let fixed: [(Data, Int)] = [(nonce, 32), (operation, 16), (correlation, 32),
            (installation, 16), (appAttestKeyID, 32), (ownerTransaction, 16),
            (ownerResult, 32), (endpointCommitment, 32), (rendezvousCommitment, 32)]
        guard fixed.allSatisfy({ $0.0.count == $0.1 && !$0.0.allSatisfy({ $0 == 0 }) }),
              SiteRootBrokerPresentationV2.identifier(reference, maximum: 128),
              site.hasPrefix("site-"), let siteID = UUID(uuidString: String(site.dropFirst(5))),
              site == "site-" + siteID.uuidString.lowercased(),
              siteRootPublicKey.count == 33,
              (try? P256.Signing.PublicKey(compressedRepresentation: siteRootPublicKey)) != nil,
              expiry > 0 else { throw PlatformFailure.appAttestInvalidInput }
        func digest(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
        var result = Data("mnemosyne.monas.attended-recovery.v1\0".utf8)
        result.append(nonce); result.append(operation)
        result.append(digest(Data("mnemosyne.monas.first-device.correlation.v2\0".utf8) + correlation))
        result.append(digest(Data(reference.utf8))); result.append(digest(Data(site.utf8)))
        result.append(installation); result.append(appAttestKeyID); result.append(digest(siteRootPublicKey))
        result.append(ownerTransaction); result.append(ownerResult); result.append(endpointCommitment)
        result.append(rendezvousCommitment)
        var bigEndian = expiry.bigEndian
        withUnsafeBytes(of: &bigEndian) { result.append(contentsOf: $0) }
        return result
    }

    func digest() throws -> Data { Data(SHA256.hash(data: try bytes())) }
    func comparison() throws -> Data {
        Data(SHA256.hash(data: Data("mnemosyne.monas.attended-recovery.compare.v1\0".utf8) + (try bytes())).prefix(8))
    }
    func signingMessage() throws -> Data {
        Data("mnemosyne.monas.attended-recovery.site-root.v1\0".utf8) + (try digest())
    }
    func assertionHash(signature: Data) throws -> Data {
        guard P256Format.isCanonicalRawSignature(signature) else { throw PlatformFailure.malformedSignature }
        return Data(SHA256.hash(data: Data("mnemosyne.monas.attended-recovery.app-attest.v1\0".utf8)
            + (try digest()) + signature))
    }
}

/// Inactive signer primitive. Call only after exact transcript comparison and
/// while the caller holds the reset/cancellation lifetime claim.
enum AttendedRecoveryRootProofV1 {
    static func sign(_ transcript: AttendedRecoveryTranscriptV1,
                     ceremony: FaceIDCeremonyContext) throws -> Data {
        let signer = try SecureEnclaveSigner(namespace: "site-root-delegation-v1",
            authenticationReason: "Approve recovery of this Pistis installation")
        guard try signer.hasExistingKey(),
              try signer.publicKey(using: ceremony).compressedSEC1 == transcript.siteRootPublicKey
        else { throw PlatformFailure.appAttestInvalidInput }
        let signature = try signer.sign(message: transcript.signingMessage(), using: ceremony)
        guard P256Format.isCanonicalRawSignature(signature) else { throw PlatformFailure.malformedSignature }
        return signature
    }
}
