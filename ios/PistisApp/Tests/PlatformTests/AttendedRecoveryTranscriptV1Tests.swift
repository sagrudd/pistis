import CryptoKit
import XCTest
@testable import Pistis

final class AttendedRecoveryTranscriptV1Tests: XCTestCase {
    private func hex(_ value: String) -> Data {
        var result = Data(); var index = value.startIndex
        while index < value.endIndex {
            let end = value.index(index, offsetBy: 2)
            result.append(UInt8(value[index..<end], radix: 16)!)
            index = end
        }
        return result
    }
    private func fixture() -> AttendedRecoveryTranscriptV1 {
        AttendedRecoveryTranscriptV1(nonce: Data(1...32), operation: Data(33...48),
            correlation: Data(49...80), reference: "reg-001",
            site: "site-12345678-1234-1234-1234-123456789abc", installation: Data(81...96),
            appAttestKeyID: Data(97...128),
            siteRootPublicKey: hex("02591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf"),
            ownerTransaction: Data(161...176), ownerResult: Data(177...208),
            endpointCommitment: Data(209...240), rendezvousCommitment: Data(1...32), expiry: 2_000_000_000)
    }
    func testIndependentValidPointTranscriptVector() throws {
        let value = fixture()
        XCTAssertEqual(try value.digest(), hex("73d2dfcd20d7b23a4a7d16ca821e47bb7d9c5de2eaf7b1d32365e4cc723dfb49"))
        XCTAssertEqual(try value.comparison(), hex("1ddc4925c3cd80f2"))
        let signature = Data(repeating: 0, count: 31) + Data([1]) + Data(repeating: 0, count: 31) + Data([1])
        XCTAssertEqual(try value.assertionHash(signature: signature), hex("cbf93c35cf6e8f6b903f50411c8e4b0b4ee620f5784fb7e360bb92f8f6ab3e94"))
        XCTAssertThrowsError(try value.assertionHash(signature: Data(repeating: 0, count: 64)))
    }
    func testRealKnownGoodP256ProofAndWrongMessage() throws {
        let key = try P256.Signing.PublicKey(compressedRepresentation: hex("02591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf"))
        let raw = hex("3bb8281d1b2c12df3e192707e92886c747d983ae4e814d05e257cba25c75872c375a51e2c94350f5243a175b05420ebd099f1fcbff2e74487b9730e7a5eea554")
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        let message = Data("mnemosyne.monas.first-device.status.site-root.v2\0".utf8) + Data(repeating: 9, count: 32)
        XCTAssertTrue(P256Format.isCanonicalRawSignature(raw))
        XCTAssertTrue(key.isValidSignature(signature, for: message))
        XCTAssertFalse(key.isValidSignature(signature, for: message + Data([0])))
    }
}
