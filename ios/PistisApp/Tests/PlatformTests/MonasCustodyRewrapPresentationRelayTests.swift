import CryptoKit
import Foundation
import XCTest

@testable import Pistis

final class MonasCustodyRewrapPresentationRelayTests: XCTestCase {
    func testAcceptsOnlyExactTerminalPresentation() throws {
        let response = try validResponse()
        let presentation = try MonasRetainedCustodyPresentationResponseV1(
            data: response, nowUnixSeconds: 1_000
        ).presentation

        XCTAssertEqual(presentation.correlation, Data(repeating: 0x01, count: 16))
        XCTAssertEqual(presentation.delegationSerial, "serial-1")
        XCTAssertEqual(presentation.canonicalChallenge, canonicalChallenge(record: record()))
    }

    func testRejectsUnknownFieldAndCanonicalChallengeDrift() throws {
        let base = try JSONSerialization.jsonObject(with: validResponse()) as! [String: Any]
        var unknown = base
        unknown["cookie"] = "forbidden"
        XCTAssertThrowsError(try MonasRetainedCustodyPresentationResponseV1(
            data: JSONSerialization.data(withJSONObject: unknown), nowUnixSeconds: 1_000
        ))

        var drift = base
        drift["canonical_challenge_b64url"] = base64URL(Data([0x01]))
        XCTAssertThrowsError(try MonasRetainedCustodyPresentationResponseV1(
            data: JSONSerialization.data(withJSONObject: drift), nowUnixSeconds: 1_000
        ))
    }

    private func validResponse() throws -> Data {
        let encryptedRecord = record()
        let object: [String: Any] = [
            "schema": MonasRetainedCustodyPresentationResponseV1.schema,
            "correlation_b64url": base64URL(Data(repeating: 0x01, count: 16)),
            "canonical_challenge_b64url": base64URL(canonicalChallenge(record: encryptedRecord)),
            "site_trust_domain": "site-1",
            "key_generation": "generation-1",
            "device_key_id": "site-root-fixture",
            "expected_ed25519_public_key_b64url": base64URL(Data(repeating: 0x11, count: 32)),
            "encrypted_record_digest_b64url": base64URL(Data(SHA256.hash(data: encryptedRecord))),
            "current_revocation_generation": 7,
            "delegation_serial": "serial-1",
            "expires_at_unix_seconds": 1_100,
            "existing_host_public_sec1_b64url": base64URL(publicKey(2)),
            "existing_encrypted_record_b64url": base64URL(encryptedRecord),
            "fresh_host_public_sec1_b64url": base64URL(publicKey(3)),
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func canonicalChallenge(record: Data) -> Data {
        var result = Data("thesaurophylax.iphone-mediated-custody-rewrap.v1\0".utf8)
        append(1, Data("site-1".utf8), to: &result)
        append(2, Data("generation-1".utf8), to: &result)
        append(3, Data("site-root-fixture".utf8), to: &result)
        append(4, Data(repeating: 0x11, count: 32), to: &result)
        append(5, Data(SHA256.hash(data: record)), to: &result)
        append(6, Data([0, 0, 0, 0, 0, 0, 0, 7]), to: &result)
        append(7, Data("serial-1".utf8), to: &result)
        append(8, Data([0, 0, 0, 0, 0, 0, 4, 76]), to: &result)
        append(9, publicKey(3), to: &result)
        return result
    }

    private func record() -> Data { Data(repeating: 0x44, count: 60) }

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

    private func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private extension Data {
    init(hex: String) {
        self = Data(stride(from: 0, to: hex.count, by: 2).map {
            UInt8(hex[hex.index(hex.startIndex, offsetBy: $0) ... hex.index(hex.startIndex, offsetBy: $0 + 1)], radix: 16)!
        })
    }
}
