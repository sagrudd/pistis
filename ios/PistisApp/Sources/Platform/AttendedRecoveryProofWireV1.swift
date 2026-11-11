#if DEBUG
import CryptoKit
import Foundation

/// Closed, no-escape ASCII grammar; this encoding does not prove host acceptance.
enum AttendedRecoveryProofWireV1 {
    static func encode(transcript: AttendedRecoveryTranscriptV1, signature: Data,
                       assertion: Data) throws -> Data {
        guard !assertion.isEmpty, assertion.count <= 5_200,
              P256Format.isCanonicalRawSignature(signature) else { throw PlatformFailure.invalidConfiguration }
        let root = try P256.Signing.PublicKey(compressedRepresentation: transcript.siteRootPublicKey)
        let proof = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        guard root.isValidSignature(proof, for: try transcript.signingMessage())
        else { throw PlatformFailure.invalidConfiguration }
        let b64 = SiteRootBrokerPresentationV2.encode
        let object: [String: String] = ["schema": "mnemosyne.monas.attended-recovery.proof.v1",
            "assertion_b64url": b64(assertion), "correlation_b64url": b64(transcript.correlation),
            "signature_b64url": b64(signature), "transcript_b64url": b64(try transcript.bytes())]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard data.count <= 8_192 else { throw PlatformFailure.invalidConfiguration }
        return data
    }
}
#endif
