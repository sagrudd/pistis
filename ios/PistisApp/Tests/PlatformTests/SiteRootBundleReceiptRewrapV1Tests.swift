import CryptoKit
import XCTest

@testable import Pistis

final class SiteRootBundleReceiptRewrapV1Tests: XCTestCase {
    func testReceiptPresentationRequiresDistinctChallengeAndGeneration() throws {
        let data = try responseData(challengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema)
        let response = try MonasRetainedCustodyPresentationResponseV1(
            data: data,
            nowUnixSeconds: 1_000,
            expectedChallengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema,
            requiredGenerationPrefix: "site-root-bundle-receipt-"
        )
        XCTAssertTrue(response.presentation.keyGeneration.hasPrefix("site-root-bundle-receipt-"))

        XCTAssertThrowsError(try MonasRetainedCustodyPresentationResponseV1(
            data: try responseData(
                challengeSchema: SecureEnclaveIphoneMediatedCustodyRewrapProducer.challengeSchema
            ),
            nowUnixSeconds: 1_000,
            expectedChallengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema,
            requiredGenerationPrefix: "site-root-bundle-receipt-"
        ))
    }

    func testReceiptAADCannotEqualGenericRewrapAAD() throws {
        let presentation = try MonasRetainedCustodyPresentationResponseV1(
            data: responseData(challengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema),
            nowUnixSeconds: 1_000,
            expectedChallengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema,
            requiredGenerationPrefix: "site-root-bundle-receipt-"
        ).presentation
        let receipt = SecureEnclaveSiteRootBundleReceiptRewrapProducerV1.aad(
            presentation, host: presentation.freshHostEphemeralPublicSEC1
        )
        let generic = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapAADDigest(
            siteTrustDomain: presentation.siteTrustDomain,
            keyGeneration: presentation.keyGeneration,
            deviceKeyID: presentation.deviceKeyID,
            hostEphemeralPublicSEC1: presentation.freshHostEphemeralPublicSEC1
        )
        XCTAssertNotEqual(receipt, generic)
    }

    private func responseData(challengeSchema: Data) throws -> Data {
        let record = Data(repeating: 0x44, count: 60)
        let digest = Data(SHA256.hash(data: record))
        let expected = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 7, count: 32)
        ).publicKey.rawRepresentation
        let existing = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 2, count: 32)
        ).publicKey.compressedRepresentation
        let fresh = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 3, count: 32)
        ).publicKey.compressedRepresentation
        var challenge = challengeSchema
        let fields: [Data] = [
            Data("site-fixture".utf8), Data("site-root-bundle-receipt-1".utf8),
            Data("site-root-device-fixture".utf8), expected, digest,
            Data(UInt64(7).be), Data("delegation-fixture".utf8),
            Data(UInt64(1_100).be), fresh,
        ]
        for (offset, field) in fields.enumerated() {
            challenge.append(UInt8(offset + 1))
            challenge.append(contentsOf: UInt16(field.count).be)
            challenge.append(field)
        }
        let body: [String: Any] = [
            "schema": MonasRetainedCustodyPresentationResponseV1.schema,
            "correlation_b64url": Data(repeating: 1, count: 16).url,
            "canonical_challenge_b64url": challenge.url,
            "site_trust_domain": "site-fixture",
            "key_generation": "site-root-bundle-receipt-1",
            "device_key_id": "site-root-device-fixture",
            "expected_ed25519_public_key_b64url": expected.url,
            "encrypted_record_digest_b64url": digest.url,
            "current_revocation_generation": 7,
            "delegation_serial": "delegation-fixture",
            "expires_at_unix_seconds": 1_100,
            "existing_host_public_sec1_b64url": existing.url,
            "existing_encrypted_record_b64url": record.url,
            "fresh_host_public_sec1_b64url": fresh.url,
        ]
        return try JSONSerialization.data(withJSONObject: body)
    }
}

private extension Data {
    var url: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private extension FixedWidthInteger {
    var be: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
}
