import CryptoKit
import XCTest

@testable import Pistis

final class SiteX509AttendedUnlockV2Tests: XCTestCase {
    func testRootAndIssuerDecodeOnlyTheirExactTHESXIR2Transcript() throws {
        for role in SiteX509AttendedUnlockRoleV2.allCases {
            let fixture = try Fixture(role: role)
            let decoded = try SiteX509AttendedUnlockPresentationV2(
                data: fixture.data, expectedRole: role, nowUnixSeconds: 1_000
            )
            XCTAssertEqual(decoded.role, role)
            XCTAssertEqual(decoded.purpose, role.purpose)
            XCTAssertEqual(decoded.canonicalChallenge, fixture.challenge)
            XCTAssertEqual(decoded.expectedP256PublicSEC1, fixture.generationPublic)
            XCTAssertEqual(decoded.currentRevocationGeneration, 7)
        }
    }

    func testRolePurposeRouteAndGenerationCannotCross() throws {
        for mutation in ["role", "purpose", "submission_path", "key_generation"] {
            var fixture = try Fixture(role: .root)
            switch mutation {
            case "role": fixture.object[mutation] = "issuer"
            case "purpose": fixture.object[mutation] = SiteX509AttendedUnlockRoleV2.issuer.purpose
            case "submission_path": fixture.object[mutation] = SiteX509AttendedUnlockRoleV2.issuer.submissionPath
            default: fixture.object[mutation] = "x509-issuing-generation-1"
            }
            XCTAssertThrowsError(try SiteX509AttendedUnlockPresentationV2(
                data: fixture.encoded(), expectedRole: .root, nowUnixSeconds: 1_000
            ), mutation)
        }
    }

    func testChallengeCiphertextAndUnknownFieldDriftAreDenied() throws {
        var badChallenge = try Fixture(role: .root)
        badChallenge.object["canonical_challenge_b64url"] = Data([1]).b64
        XCTAssertThrowsError(try badChallenge.decode())

        var badRecord = try Fixture(role: .root)
        badRecord.object["existing_encrypted_record_b64url"] = Data(repeating: 9, count: 60).b64
        XCTAssertThrowsError(try badRecord.decode())

        var unknown = try Fixture(role: .root)
        unknown.object["fallback"] = "legacy"
        XCTAssertThrowsError(try unknown.decode())

        var ed25519Shape = try Fixture(role: .root)
        ed25519Shape.object["expected_p256_public_sec1_b64url"] = Data(repeating: 4, count: 32).b64
        XCTAssertThrowsError(try ed25519Shape.decode())
    }

    func testPurposeSpecificP256ScalarRecordCannotCrossRoles() throws {
        let root = try Fixture(role: .root).decode()
        let issuer = try Fixture(role: .issuer).decode()
        let rootAAD = SecureEnclaveSiteX509AttendedUnlockProducerV2.aad(
            root, hostPublic: root.freshHostPublicSEC1
        )
        let issuerAAD = SecureEnclaveSiteX509AttendedUnlockProducerV2.aad(
            issuer, hostPublic: issuer.freshHostPublicSEC1
        )
        XCTAssertNotEqual(rootAAD, issuerAAD)

        let key = SecureEnclaveSiteX509AttendedUnlockProducerV2.wrapKey(
            shared: Data(repeating: 8, count: 32), aad: rootAAD
        )
        let scalar = Data(repeating: 4, count: 32)
        let record = try SecureEnclaveSiteX509AttendedUnlockProducerV2.seal(
            scalar, key: key, aad: rootAAD
        )
        XCTAssertEqual(
            try SecureEnclaveSiteX509AttendedUnlockProducerV2.open(record, key: key, aad: rootAAD),
            scalar
        )
        XCTAssertThrowsError(try SecureEnclaveSiteX509AttendedUnlockProducerV2.open(
            record, key: key, aad: issuerAAD
        ))
    }

    func testAcceptedBodyIsExactAndRoleBound() throws {
        let accepted: [String: Any] = [
            "schema": SiteX509AttendedUnlockRoleV2.acceptedSchema,
            "role": "root",
            "purpose": SiteX509AttendedUnlockRoleV2.root.purpose,
            "state": "accepted",
        ]
        let value = try SiteX509AttendedUnlockAcceptedV2(
            data: JSONSerialization.data(withJSONObject: accepted)
        )
        XCTAssertEqual(value.role, "root")

        var expanded = accepted
        expanded["token"] = "forbidden"
        XCTAssertThrowsError(try SiteX509AttendedUnlockAcceptedV2(
            data: JSONSerialization.data(withJSONObject: expanded)
        ))
    }
}

private struct Fixture {
    var object: [String: Any]
    let challenge: Data
    let generationPublic: Data
    let role: SiteX509AttendedUnlockRoleV2

    init(role: SiteX509AttendedUnlockRoleV2) throws {
        self.role = role
        let record = Data(repeating: 0x44, count: 60)
        let digest = Data(SHA256.hash(data: record))
        let generation = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 4, count: 32))
        generationPublic = generation.publicKey.compressedRepresentation
        let existing = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 2, count: 32))
            .publicKey.compressedRepresentation
        let fresh = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
            .publicKey.compressedRepresentation
        let generationID = role == .root ? "x509-root-generation-1" : "x509-issuing-generation-1"
        var transcript = Data("thesaurophylax.site-x509-iphone-rewrap.v2\0".utf8)
        append(1, Data([role.challengeCode]), to: &transcript)
        append(2, Data("site-fixture".utf8), to: &transcript)
        append(3, Data(generationID.utf8), to: &transcript)
        append(4, Data("site-root-device-fixture".utf8), to: &transcript)
        append(5, generationPublic, to: &transcript)
        append(6, digest, to: &transcript)
        append(7, Data(UInt64(7).bigEndianBytes), to: &transcript)
        append(8, Data("delegation-fixture".utf8), to: &transcript)
        append(9, Data(UInt64(1_100).bigEndianBytes), to: &transcript)
        append(10, fresh, to: &transcript)
        challenge = transcript
        object = [
            "schema": SiteX509AttendedUnlockRoleV2.presentationSchema,
            "role": role.rawValue,
            "purpose": role.purpose,
            "correlation_b64url": Data(repeating: 1, count: 16).b64,
            "canonical_challenge_b64url": transcript.b64,
            "fresh_host_public_sec1_b64url": fresh.b64,
            "site_trust_domain": "site-fixture",
            "key_generation": generationID,
            "device_key_id": "site-root-device-fixture",
            "expected_p256_public_sec1_b64url": generationPublic.b64,
            "encrypted_record_digest_b64url": digest.b64,
            "current_revocation_generation": 7,
            "delegation_serial": "delegation-fixture",
            "expires_at_unix_seconds": 1_100,
            "existing_host_public_sec1_b64url": existing.b64,
            "existing_encrypted_record_b64url": record.b64,
            "submission_path": role.submissionPath,
        ]
    }

    var data: Data { get throws { try encoded() } }

    func encoded() throws -> Data { try JSONSerialization.data(withJSONObject: object) }

    func decode() throws -> SiteX509AttendedUnlockPresentationV2 {
        try SiteX509AttendedUnlockPresentationV2(
            data: encoded(), expectedRole: role, nowUnixSeconds: 1_000
        )
    }
}

private func append(_ tag: UInt8, _ value: Data, to output: inout Data) {
    output.append(tag)
    output.append(contentsOf: UInt16(value.count).bigEndianBytes)
    output.append(value)
}

private extension Data {
    var b64: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
}
