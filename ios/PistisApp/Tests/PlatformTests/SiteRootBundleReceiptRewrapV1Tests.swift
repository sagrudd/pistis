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

    func testReceiptWrappingDomainIsIndependentOfExternalProofPurpose() throws {
        let presentation = try MonasRetainedCustodyPresentationResponseV1(
            data: responseData(challengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema),
            nowUnixSeconds: 1_000,
            expectedChallengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema,
            requiredGenerationPrefix: "site-root-bundle-receipt-"
        ).presentation
        XCTAssertEqual(
            SiteRootBundleReceiptRewrapV1.purpose,
            "thesaurophylax.site-root-bundle-receipt-rewrap.v1"
        )
        for host in [
            presentation.existingHostEphemeralPublicSEC1,
            presentation.freshHostEphemeralPublicSEC1,
        ] {
            let fields = [
                Data("site-root-bundle-receipt".utf8),
                Data(presentation.siteTrustDomain.utf8),
                Data(presentation.keyGeneration.utf8),
                Data(presentation.deviceKeyID.utf8), host,
            ]
            let actual = SecureEnclaveSiteRootBundleReceiptRewrapProducerV1.aad(
                presentation, host: host
            )
            XCTAssertEqual(actual, digest(fields))
            for index in fields.indices {
                var changed = fields
                changed[index].append(0)
                XCTAssertNotEqual(actual, digest(changed))
            }
            var wrongDomain = fields
            wrongDomain[0] = Data(SiteRootBundleReceiptRewrapV1.purpose.utf8)
            XCTAssertNotEqual(actual, digest(wrongDomain))
        }
    }

    private func digest(_ fields: [Data]) -> Data {
        var bytes = Data()
        for field in fields {
            bytes.append(contentsOf: UInt32(field.count).be)
            bytes.append(field)
        }
        return Data(SHA256.hash(data: bytes))
    }

    func testActualThesProvisionedRecordOpensAndRewrapsWithRetainedDomain() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0 ..< 4 { root.deleteLastPathComponent() }
        let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(
            contentsOf: root.appendingPathComponent("fixtures/receipt-wrap-v1/provisioned.json")
        )) as? [String: String])
        func value(_ key: String) throws -> String { try XCTUnwrap(fixture[key]) }
        func bytes(_ key: String) throws -> Data {
            let text = try value(key)
            XCTAssertEqual(text.count % 2, 0)
            var result = Data()
            var cursor = text.startIndex
            while cursor < text.endIndex {
                let end = text.index(cursor, offsetBy: 2)
                result.append(try XCTUnwrap(UInt8(text[cursor ..< end], radix: 16)))
                cursor = end
            }
            return result
        }
        let device = try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes("device_private_hex"))
        let oldHost = try bytes("host_public_hex")
        let freshHost = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let freshPublic = freshHost.publicKey.compressedRepresentation
        let presentation = try MonasRetainedCustodyPresentationResponseV1(
            data: responseData(
                challengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema,
                record: bytes("record_hex"), expected: bytes("public_hex"), existing: oldHost,
                fresh: freshPublic, site: value("site"), deviceID: value("device_id")
            ),
            nowUnixSeconds: 1_000,
            expectedChallengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema,
            requiredGenerationPrefix: "site-root-bundle-receipt-"
        ).presentation
        XCTAssertEqual(presentation.keyGeneration, try value("generation"))
        let oldShared = try device.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(
            compressedRepresentation: oldHost
        )).withUnsafeBytes { Data($0) }
        XCTAssertEqual(oldShared, try bytes("shared_hex"))
        let oldAAD = SecureEnclaveSiteRootBundleReceiptRewrapProducerV1.aad(presentation, host: oldHost)
        XCTAssertEqual(oldAAD, try bytes("aad_hex"))
        let oldKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: oldShared, aadDigest: oldAAD
        )
        let seed = try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
            presentation.existingEncryptedRecord, key: oldKey, aadDigest: oldAAD
        )
        XCTAssertEqual(seed, try bytes("seed_hex"))
        XCTAssertEqual(try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation,
                       presentation.expectedEd25519PublicKey)
        let freshShared = try device.sharedSecretFromKeyAgreement(with: freshHost.publicKey)
            .withUnsafeBytes { Data($0) }
        let freshAAD = SecureEnclaveSiteRootBundleReceiptRewrapProducerV1.aad(presentation, host: freshPublic)
        let freshKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: freshShared, aadDigest: freshAAD
        )
        let fresh = try SecureEnclaveIphoneMediatedCustodyRewrapProducer.seal(seed, key: freshKey, aadDigest: freshAAD)
        XCTAssertEqual(try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
            fresh, key: freshKey, aadDigest: freshAAD
        ), seed)
        for (host, shared, record) in [(oldHost, oldShared, presentation.existingEncryptedRecord),
                                      (freshPublic, freshShared, fresh)] {
            let wrongAAD = digest([
                Data(SiteRootBundleReceiptRewrapV1.purpose.utf8), Data(presentation.siteTrustDomain.utf8),
                Data(presentation.keyGeneration.utf8), Data(presentation.deviceKeyID.utf8), host,
            ])
            let wrongKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
                sharedSecret: shared, aadDigest: wrongAAD
            )
            XCTAssertThrowsError(try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
                record, key: wrongKey, aadDigest: wrongAAD
            ))
        }
        // Fixed nonce exists only in this synthetic cross-language vector, never production.
        let fixed = try XCTUnwrap(AES.GCM.seal(seed, using: freshKey,
            nonce: AES.GCM.Nonce(data: Data(repeating: 0xa5, count: 12)), authenticating: freshAAD).combined)
        XCTAssertEqual(fixed, try bytes("swift_fresh_record_hex"))
    }

    private func responseData(
        challengeSchema: Data, record: Data = Data(repeating: 0x44, count: 60),
        expected: Data? = nil, existing: Data? = nil, fresh: Data? = nil,
        site: String = "site-fixture", deviceID: String = "site-root-device-fixture"
    ) throws -> Data {
        let digest = Data(SHA256.hash(data: record))
        let expected = try expected ?? Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 7, count: 32)
        ).publicKey.rawRepresentation
        let existing = try existing ?? P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 2, count: 32)
        ).publicKey.compressedRepresentation
        let fresh = try fresh ?? P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 3, count: 32)
        ).publicKey.compressedRepresentation
        var challenge = challengeSchema
        let fields: [Data] = [
            Data(site.utf8), Data("site-root-bundle-receipt-1".utf8),
            Data(deviceID.utf8), expected, digest,
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
            "site_trust_domain": site,
            "key_generation": "site-root-bundle-receipt-1",
            "device_key_id": deviceID,
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
