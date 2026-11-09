import Foundation
import CryptoKit
import XCTest
@testable import Pistis

final class FirstDeviceStatusTranscriptV2Tests: XCTestCase {
    func testActualSyntheticHostResponseUsesLowercaseWireEnvironment() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Fixtures/status-v2-host-response.json")
        let data = try Data(contentsOf: url)
        let fields = try StrictJSONObject(data: data, maximumBytes: 4_096).values
        func bytes(_ key: String, _ count: Int) throws -> Data {
            guard case let .string(value)? = fields[key],
                  let data = SiteRootBrokerPresentationV2.base64(value, exact: count) else { throw PlatformFailure.invalidConfiguration }
            return data
        }
        let transcript = FirstDeviceStatusTranscriptV2(nonce: Data(repeating: 3, count: 32),
            operationID: try bytes("operation_b64url", 16), correlationDigest: try bytes("correlation_digest_b64url", 32),
            reference: "ref", installationID: try bytes("installation_id_b64url", 16), site: "site-trust-test",
            presentationDigest: try bytes("presentation_digest_b64url", 32), receiptDigest: try bytes("receipt_digest_b64url", 32),
            tlsSPKIDigest: try bytes("tls_spki_sha256_b64url", 32), appAttestKeyID: try bytes("app_attest_key_id_b64url", 32),
            siteRootKeyDigest: Data(repeating: 4, count: 32), deviceKeyDigest: Data(repeating: 5, count: 32), expiry: 200)
        try FirstDeviceStatusResponseV2.validate(data, transcript: transcript,
            appIdentifier: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environment: "Production", policyGeneration: 1, revocationGeneration: 1)
        var wrong = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        wrong["environment"] = "Production"
        XCTAssertThrowsError(try FirstDeviceStatusResponseV2.validate(JSONSerialization.data(withJSONObject: wrong),
            transcript: transcript, appIdentifier: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environment: "Production", policyGeneration: 1, revocationGeneration: 1))
    }
    func testStatusChallengeRequiresFreshBoundedNonce() throws {
        let nonce = SiteRootBrokerPresentationV2.encode(Data(repeating: 5, count: 32))
        func response(_ expiry: Int) -> Data {
            Data("{\"schema\":\"monas.first-device.status.challenge.v2\",\"nonce_b64url\":\"\(nonce)\",\"expires_unix_seconds\":\(expiry)}".utf8)
        }
        XCTAssertEqual(try FirstDeviceStatusResponseV2.challenge(response(160), now: 100).expiry, 160)
        XCTAssertThrowsError(try FirstDeviceStatusResponseV2.challenge(response(161), now: 100))
        XCTAssertThrowsError(try FirstDeviceStatusResponseV2.challenge(response(100), now: 100))
        let duplicate = Data("{\"schema\":\"monas.first-device.status.challenge.v2\",\"nonce_b64url\":\"\(nonce)\",\"nonce_b64url\":\"\(nonce)\",\"expires_unix_seconds\":120}".utf8)
        XCTAssertThrowsError(try FirstDeviceStatusResponseV2.challenge(duplicate, now: 100))
    }
    func testSharedStatusVector() throws {
        let value = FirstDeviceStatusTranscriptV2(
            nonce: Data(96...127), operationID: Data(1...16),
            correlationDigest: Data([0xf8,0x46,0xc9,0x78,0xde,0xdf,0x75,0xc3,0x07,0x9b,0x33,0x6f,0x7b,0xae,0xc0,0xce,0x62,0xed,0xb2,0x94,0x00,0x27,0xcc,0x25,0x1c,0xd0,0x63,0x28,0x50,0xee,0x23,0xcd]),
            reference: "genesis-reference-1", installationID: Data(160...175),
            site: "site-6073349b-e7f6-420f-ba7c-586b6d9ad78e", presentationDigest: Data(176...207),
            receiptDigest: Data(208...239), tlsSPKIDigest: Data(repeating: 0x10, count: 32),
            appAttestKeyID: Data(repeating: 0x11, count: 32), siteRootKeyDigest: Data(repeating: 0x12, count: 32),
            deviceKeyDigest: Data(repeating: 0x13, count: 32), expiry: 1_900_000_060)
        XCTAssertEqual(try value.clientDataHash().map { String(format: "%02x", $0) }.joined(),
                       "e00ad831caab2341c8d2ced32915570555bc3359dc26f60318527c588bef330b")
        let encode = SiteRootBrokerPresentationV2.encode
        var result: [String: Any] = [
            "schema": "monas.first-device.status.result.v2", "state": "accepted",
            "operation_b64url": encode(value.operationID), "reference": value.reference,
            "correlation_digest_b64url": encode(value.correlationDigest),
            "installation_id_b64url": encode(value.installationID), "site_trust_domain": value.site,
            "app_attest_key_id_b64url": encode(value.appAttestKeyID),
            "app_identifier": AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            "environment": "production", "policy_generation": 1, "revocation_generation": 2,
            "presentation_digest_b64url": encode(value.presentationDigest),
            "receipt_digest_b64url": encode(value.receiptDigest), "tls_spki_sha256_b64url": encode(value.tlsSPKIDigest),
        ]
        let app = AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier
        let valid = try JSONSerialization.data(withJSONObject: result)
        try FirstDeviceStatusResponseV2.validate(valid, transcript: value, appIdentifier: app,
                                                 environment: "Production", policyGeneration: 1, revocationGeneration: 2)
        result["site_trust_domain"] = "different-site"
        XCTAssertThrowsError(try FirstDeviceStatusResponseV2.validate(JSONSerialization.data(withJSONObject: result),
            transcript: value, appIdentifier: app, environment: "Production", policyGeneration: 1, revocationGeneration: 2))
        result["site_trust_domain"] = value.site; result["extra"] = true
        XCTAssertThrowsError(try FirstDeviceStatusResponseV2.validate(JSONSerialization.data(withJSONObject: result),
            transcript: value, appIdentifier: app, environment: "Production", policyGeneration: 1, revocationGeneration: 2))
    }
    func testSyntheticHostProofVectorsUseDistinctDomainsAndLowS() throws {
        func hex(_ value: String) throws -> Data {
            guard value.count.isMultiple(of: 2) else { throw PlatformFailure.invalidConfiguration }
            var result = Data(); var cursor = value.startIndex
            while cursor < value.endIndex {
                let end = value.index(cursor, offsetBy: 2)
                guard let byte = UInt8(value[cursor..<end], radix: 16) else { throw PlatformFailure.invalidConfiguration }
                result.append(byte); cursor = end
            }
            return result
        }
        let root = try P256.Signing.PublicKey(compressedRepresentation: hex(
            "02591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf"))
        let device = try P256.Signing.PublicKey(compressedRepresentation: hex(
            "0273103ec30b3ccf57daae08e93534aef144a35940cf6bbba12a0cf7cbd5d65a64"))
        let rootBytes = try hex("3bb8281d1b2c12df3e192707e92886c747d983ae4e814d05e257cba25c75872c375a51e2c94350f5243a175b05420ebd099f1fcbff2e74487b9730e7a5eea554")
        let deviceBytes = try hex("562a132a9e628165d2cddba16c316034a6b76c8731f5234d0f7d3bf06730ab7a75a23c6e9c345b8529d8104418024b06d7f1d90c4be7213cff6997e3795332fd")
        XCTAssertTrue(P256Format.isCanonicalRawSignature(rootBytes)); XCTAssertTrue(P256Format.isCanonicalRawSignature(deviceBytes))
        let rootSignature = try P256.Signing.ECDSASignature(rawRepresentation: rootBytes)
        let deviceSignature = try P256.Signing.ECDSASignature(rawRepresentation: deviceBytes)
        let messages = try FirstDeviceStatusProofV2.messages(statusHash: Data(repeating: 9, count: 32))
        let rootMessage = messages.siteRoot, deviceMessage = messages.device
        XCTAssertTrue(root.isValidSignature(rootSignature, for: rootMessage))
        XCTAssertTrue(device.isValidSignature(deviceSignature, for: deviceMessage))
        XCTAssertFalse(root.isValidSignature(rootSignature, for: deviceMessage))
        XCTAssertFalse(device.isValidSignature(rootSignature, for: deviceMessage))
    }

}
