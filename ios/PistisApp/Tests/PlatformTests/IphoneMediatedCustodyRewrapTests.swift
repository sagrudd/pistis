import CryptoKit
import XCTest

@testable import Pistis

final class IphoneMediatedCustodyRewrapTests: XCTestCase {
    func testCanonicalChallengeMatchesThesaurophylaxTagOrder() throws {
        let record = Data(repeating: 0x44, count: 60)
        let presentation = try presentation(record: record)

        let challenge = try SecureEnclaveIphoneMediatedCustodyRewrapProducer
            .canonicalChallenge(for: presentation)

        var expected = Data("thesaurophylax.iphone-mediated-custody-rewrap.v1\0".utf8)
        append(1, Data("site-1".utf8), to: &expected)
        append(2, Data("generation-1".utf8), to: &expected)
        append(3, Data("site-root-fixture".utf8), to: &expected)
        append(4, Data(repeating: 0x11, count: 32), to: &expected)
        append(5, Data(SHA256.hash(data: record)), to: &expected)
        append(6, Data([0, 0, 0, 0, 0, 0, 0, 7]), to: &expected)
        append(7, Data("serial-1".utf8), to: &expected)
        append(8, Data([0, 0, 0, 0, 0, 0, 4, 76]), to: &expected)
        append(9, publicKey(3), to: &expected)
        XCTAssertEqual(challenge, expected)
    }

    func testPortableRewrapUsesCompatibleNonceCiphertextTagFrame() throws {
        let shared = Data(repeating: 0x22, count: 32)
        let aad = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapAADDigest(
            siteTrustDomain: "site-1",
            keyGeneration: "generation-1",
            deviceKeyID: "site-root-fixture",
            hostEphemeralPublicSEC1: publicKey(2)
        )
        let key = SecureEnclaveIphoneMediatedCustodyRewrapProducer
            .portableWrapKey(sharedSecret: shared, aadDigest: aad)
        let seed = Data(repeating: 0x55, count: 32)

        let record = try SecureEnclaveIphoneMediatedCustodyRewrapProducer
            .seal(seed, key: key, aadDigest: aad)

        XCTAssertEqual(record.count, 60)
        XCTAssertEqual(
            try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
                record, key: key, aadDigest: aad
            ),
            seed
        )
        XCTAssertThrowsError(try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
            record, key: key, aadDigest: Data(repeating: 1, count: 32)
        ))
    }

    func testPresentationRejectsRecordDigestAndKeyDrift() throws {
        let record = Data(repeating: 0x44, count: 60)
        XCTAssertThrowsError(try IphoneMediatedCustodyRewrapPresentationV1(
            correlation: Data(repeating: 0x01, count: 16),
            canonicalChallenge: Data([0x01]),
            siteTrustDomain: "site-1",
            keyGeneration: "generation-1",
            deviceKeyID: "site-root-fixture",
            expectedEd25519PublicKey: Data(repeating: 0x11, count: 32),
            encryptedRecordDigest: Data(repeating: 0x22, count: 32),
            currentRevocationGeneration: 7,
            delegationSerial: "serial-1",
            expiresAtUnixSeconds: 1_100,
            existingHostEphemeralPublicSEC1: publicKey(2),
            existingEncryptedRecord: record,
            freshHostEphemeralPublicSEC1: publicKey(3)
        ))
        XCTAssertThrowsError(try presentation(
            record: record,
            freshHostEphemeralPublicSEC1: publicKey(2)
        ))
    }

    private func presentation(
        record: Data,
        freshHostEphemeralPublicSEC1: Data? = nil
    ) throws -> IphoneMediatedCustodyRewrapPresentationV1 {
        let siteTrustDomain = "site-1"
        let keyGeneration = "generation-1"
        let deviceKeyID = "site-root-fixture"
        let expectedEd25519PublicKey = Data(repeating: 0x11, count: 32)
        let encryptedRecordDigest = Data(SHA256.hash(data: record))
        let currentRevocationGeneration: UInt64 = 7
        let delegationSerial = "serial-1"
        let expiresAtUnixSeconds: UInt64 = 1_100
        let existingHostEphemeralPublicSEC1 = publicKey(2)
        let freshHostEphemeralPublicSEC1 = freshHostEphemeralPublicSEC1 ?? publicKey(3)
        var canonicalChallenge = Data(
            "thesaurophylax.iphone-mediated-custody-rewrap.v1\0".utf8
        )
        append(1, Data(siteTrustDomain.utf8), to: &canonicalChallenge)
        append(2, Data(keyGeneration.utf8), to: &canonicalChallenge)
        append(3, Data(deviceKeyID.utf8), to: &canonicalChallenge)
        append(4, expectedEd25519PublicKey, to: &canonicalChallenge)
        append(5, encryptedRecordDigest, to: &canonicalChallenge)
        append(6, Data([0, 0, 0, 0, 0, 0, 0, 7]), to: &canonicalChallenge)
        append(7, Data(delegationSerial.utf8), to: &canonicalChallenge)
        append(8, Data([0, 0, 0, 0, 0, 0, 4, 76]), to: &canonicalChallenge)
        append(9, freshHostEphemeralPublicSEC1, to: &canonicalChallenge)
        return try IphoneMediatedCustodyRewrapPresentationV1(
            correlation: Data(repeating: 0x01, count: 16),
            canonicalChallenge: canonicalChallenge,
            siteTrustDomain: siteTrustDomain,
            keyGeneration: keyGeneration,
            deviceKeyID: deviceKeyID,
            expectedEd25519PublicKey: expectedEd25519PublicKey,
            encryptedRecordDigest: encryptedRecordDigest,
            currentRevocationGeneration: currentRevocationGeneration,
            delegationSerial: delegationSerial,
            expiresAtUnixSeconds: expiresAtUnixSeconds,
            existingHostEphemeralPublicSEC1: existingHostEphemeralPublicSEC1,
            existingEncryptedRecord: record,
            freshHostEphemeralPublicSEC1: freshHostEphemeralPublicSEC1
        )
    }

    private func publicKey(_ scalar: UInt8) -> Data {
        switch scalar {
        case 2:
            Data(hex: "024acd4082da3869662d207679722cd21093984ce1b7b620cef262aac23213e5f7")
        case 3:
            Data(hex: "0218987f7c40c73b9d4688a6c2de172790f6b2b1499bfd9544f7af2b05d2d0770b")
        default:
            fatalError("test fixture scalar is not defined")
        }
    }

    private func append(_ tag: UInt8, _ value: Data, to output: inout Data) {
        output.append(tag)
        output.append(contentsOf: withUnsafeBytes(of: UInt16(value.count).bigEndian, Array.init))
        output.append(value)
    }
}

private extension Data {
    init(hex: String) {
        self = Data(stride(from: 0, to: hex.count, by: 2).map {
            UInt8(hex[hex.index(hex.startIndex, offsetBy: $0) ... hex.index(hex.startIndex, offsetBy: $0 + 1)], radix: 16)!
        })
    }
}
