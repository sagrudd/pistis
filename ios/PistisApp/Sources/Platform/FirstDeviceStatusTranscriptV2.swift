import CryptoKit
import Foundation

/// Server-owned facts supplied by the separately authenticated status join.
/// This digest alone is not authority, a session, or installation acceptance.
struct FirstDeviceStatusTranscriptV2 {
    let nonce: Data
    let operationID: Data
    let correlationDigest: Data
    let reference: String
    let installationID: Data
    let site: String
    let presentationDigest: Data
    let receiptDigest: Data
    let tlsSPKIDigest: Data
    let appAttestKeyID: Data
    let siteRootKeyDigest: Data
    let deviceKeyDigest: Data
    let expiry: UInt64

    func clientDataHash() throws -> Data {
        guard nonce.count == 32, operationID.count == 16, installationID.count == 16,
              [nonce, operationID, installationID].allSatisfy({ !$0.allSatisfy({ $0 == 0 }) }),
              [correlationDigest, presentationDigest, receiptDigest, tlsSPKIDigest,
               appAttestKeyID, siteRootKeyDigest, deviceKeyDigest].allSatisfy({
                   $0.count == 32 && !$0.allSatisfy({ $0 == 0 })
               }),
              SiteRootBrokerPresentationV2.identifier(reference, maximum: 128),
              SiteRootBrokerPresentationV2.identifier(site, maximum: 255), expiry > 0
        else { throw PlatformFailure.appAttestInvalidInput }
        var bytes = Data("mnemosyne.monas.first-device.status.v2\0".utf8)
        bytes.append(nonce); bytes.append(operationID); bytes.append(correlationDigest)
        bytes.append(contentsOf: SHA256.hash(data: Data(reference.utf8)))
        bytes.append(installationID); bytes.append(contentsOf: SHA256.hash(data: Data(site.utf8)))
        bytes.append(presentationDigest); bytes.append(receiptDigest); bytes.append(tlsSPKIDigest)
        bytes.append(appAttestKeyID); bytes.append(siteRootKeyDigest); bytes.append(deviceKeyDigest)
        var value = expiry.bigEndian
        withUnsafeBytes(of: &value) { bytes.append(contentsOf: $0) }
        return Data(SHA256.hash(data: bytes))
    }
}

/// The signer receives these exact messages and hashes once internally.
enum FirstDeviceStatusProofV2 {
    static func messages(statusHash: Data) throws -> (siteRoot: Data, device: Data) {
        guard statusHash.count == 32, !statusHash.allSatisfy({ $0 == 0 }) else {
            throw PlatformFailure.invalidConfiguration
        }
        return (Data("mnemosyne.monas.first-device.status.site-root.v2\0".utf8) + statusHash,
                Data("mnemosyne.monas.first-device.status.device.v2\0".utf8) + statusHash)
    }

    static func signDevice(transcript: FirstDeviceStatusTranscriptV2) throws -> Data {
        let namespace = transcript.installationID.map { String(format: "%02x", $0) }.joined()
        let signer = try SecureEnclaveSigner(namespace: namespace,
            authenticationReason: "Confirm this Pistis installation")
        let key = try signer.publicKey().compressedSEC1
        guard Data(SHA256.hash(data: key)) == transcript.deviceKeyDigest else {
            throw PlatformFailure.invalidConfiguration
        }
        return try signer.sign(message: messages(statusHash: transcript.clientDataHash()).device)
    }
}
