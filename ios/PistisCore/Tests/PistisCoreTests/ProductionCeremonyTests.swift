import Foundation
@testable import PistisCore
import XCTest

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#else
#error("PistisCoreTests require CryptoKit or Apple Swift Crypto")
#endif

final class ProductionCeremonyTests: XCTestCase {
    func testProductionChallengeRequiresEnrolledKeyAndVerifiesExactPayload() async throws {
        let key = P256.Signing.PrivateKey()
        let material = try Fixture(key: key)
        let trust = FixedTrust(record: material.trust)

        let verified = try await ProductionChallengeVerifier.verify(
            qrText: material.qr,
            trustRepository: trust,
            expectedAudience: "jenkins.mnemosyne.test",
            expectedExternalIdentityID: Data(repeating: 0x44, count: 16),
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )

        XCTAssertEqual(verified.installationName, "Mnemosyne Jenkins")
        XCTAssertEqual(verified.localUsername, "stephen")
        XCTAssertEqual(verified.exactPayload, material.payload)
    }

    func testUnknownInstallationFailsClosedInsteadOfTrustingScannedKey() async throws {
        let material = try Fixture(key: P256.Signing.PrivateKey())
        do {
            _ = try await ProductionChallengeVerifier.verify(
                qrText: material.qr,
                trustRepository: FixedTrust(record: nil),
                expectedAudience: "jenkins.mnemosyne.test",
                expectedExternalIdentityID: Data(repeating: 0x44, count: 16),
                now: Date(timeIntervalSince1970: 1_700_000_001)
            )
            XCTFail("an unremembered QR key must never establish trust")
        } catch {
            XCTAssertEqual(error as? ProductionCeremonyError, .unknownInstallation)
        }
    }

    func testTrustKeySubstitutionFailsBeforePresentation() async throws {
        let material = try Fixture(key: P256.Signing.PrivateKey())
        let replacement = P256.Signing.PrivateKey()
        let substituted = try InstallationTrustRecord(
            installationID: material.trust.installationID,
            displayName: material.trust.displayName,
            audience: material.trust.audience,
            userID: material.trust.userID,
            externalIdentityID: material.trust.externalIdentityID,
            fingerprint: material.trust.fingerprint,
            installationKeyID: material.trust.installationKeyID,
            installationPublicKey: replacement.publicKey.compressedRepresentation,
            authorityKeyID: material.trust.authorityKeyID,
            authorityReceipt: material.trust.authorityReceipt,
            policyGeneration: 1,
            revocationGeneration: 1,
            expiresAt: material.trust.expiresAt,
            active: true
        )
        do {
            _ = try await ProductionChallengeVerifier.verify(
                qrText: material.qr,
                trustRepository: FixedTrust(record: substituted),
                expectedAudience: "jenkins.mnemosyne.test",
                expectedExternalIdentityID: Data(repeating: 0x44, count: 16),
                now: Date(timeIntervalSince1970: 1_700_000_001)
            )
            XCTFail("signature under a scanned key must not replace enrolled authority")
        } catch {
            XCTAssertEqual(error as? ProductionCeremonyError, .invalidSignature)
        }
    }

    func testDeniedResponseIsARealCanonicalSignedPayloadInput() async throws {
        let material = try Fixture(key: P256.Signing.PrivateKey())
        let challenge = try await ProductionChallengeVerifier.verify(
            qrText: material.qr,
            trustRepository: FixedTrust(record: material.trust),
            expectedAudience: "jenkins.mnemosyne.test",
            expectedExternalIdentityID: Data(repeating: 0x44, count: 16),
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )
        let context = try DeviceResponseContext(
            deviceID: Data(repeating: 0xaa, count: 16),
            deviceKeyID: Data(repeating: 0xbb, count: 32),
            userID: challenge.userID,
            externalIdentityID: challenge.externalIdentityID
        )
        let payload = try AuthenticationResponseEncoder.payload(
            challenge: challenge,
            context: context,
            decision: .denied,
            issuedAtMilliseconds: 1_700_000_001_000,
            userVerifiedAtMilliseconds: 1_700_000_001_001
        )

        XCTAssertNoThrow(try CoseSign1.signatureStructure(
            keyID: context.deviceKeyID,
            payload: payload
        ))
        XCTAssertTrue(payload.contains(Data("denied".utf8)))
    }

    func testPersistedTrustIsRevalidatedDuringDecode() throws {
        let record = try Fixture(key: P256.Signing.PrivateKey()).trust
        let encoded = try JSONEncoder().encode(record)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        object["installationID"] = Data(repeating: 0, count: 15).base64EncodedString()
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                InstallationTrustRecord.self,
                from: JSONSerialization.data(withJSONObject: object)
            )
        )

        object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        object["unexpected"] = true
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                InstallationTrustRecord.self,
                from: JSONSerialization.data(withJSONObject: object)
            )
        )
    }

    func testChallengeRejectsNonCanonicalHTTPSHosts() async throws {
        for endpoint in [
            "https://Jenkins.mnemosyne.test/auth/pistis",
            "https://jenkins.mnemosyne.test./auth/pistis",
            "https://jenkins..mnemosyne.test/auth/pistis",
            "https://%6aenkins.mnemosyne.test/auth/pistis",
            "https://127.0.0.1/auth/pistis",
            "https://2130706433/auth/pistis",
            "https://0x7f000001/auth/pistis",
            "https://0177.0.0.1/auth/pistis",
            "https://127.1/auth/pistis",
            "https://[::1]/auth/pistis",
        ] {
            let material = try Fixture(
                key: P256.Signing.PrivateKey(),
                endpoint: endpoint
            )
            do {
                _ = try await ProductionChallengeVerifier.verify(
                    qrText: material.qr,
                    trustRepository: FixedTrust(record: material.trust),
                    expectedAudience: "jenkins.mnemosyne.test",
                    expectedExternalIdentityID: Data(repeating: 0x44, count: 16),
                    now: Date(timeIntervalSince1970: 1_700_000_001)
                )
                XCTFail("non-canonical endpoint unexpectedly accepted: \(endpoint)")
            } catch {
                XCTAssertEqual(error as? ProductionCeremonyError, .invalidEndpoint)
            }
        }
    }
}

private actor FixedTrust: InstallationTrustReading {
    let stored: InstallationTrustRecord?
    init(record: InstallationTrustRecord?) { stored = record }
    func record(installationID: Data) -> InstallationTrustRecord? {
        stored?.installationID == installationID ? stored : nil
    }
}

private struct Fixture {
    let payload: Data
    let qr: String
    let trust: InstallationTrustRecord

    init(
        key: P256.Signing.PrivateKey,
        endpoint: String = "https://jenkins.mnemosyne.test/auth/pistis"
    ) throws {
        let installationID = Data(repeating: 0x11, count: 16)
        let keyID = Data(repeating: 0x22, count: 32)
        let fingerprint = Data(repeating: 0x33, count: 32)
        payload = Self.challenge(
            installationID: installationID,
            keyID: keyID,
            fingerprint: fingerprint,
            endpoint: endpoint
        )
        let structure = try CoseSign1.signatureStructure(keyID: keyID, payload: payload)
        let signature = Self.lowS(try key.signature(for: structure).rawRepresentation)
        let cose = try CoseSign1(keyID: keyID, payload: payload, signature: signature).encoded()
        qr = Self.qr(cose: cose)
        trust = try InstallationTrustRecord(
            installationID: installationID,
            displayName: "Mnemosyne Jenkins",
            audience: "jenkins.mnemosyne.test",
            userID: Data(repeating: 0x88, count: 16),
            externalIdentityID: Data(repeating: 0x44, count: 16),
            fingerprint: fingerprint,
            installationKeyID: keyID,
            installationPublicKey: key.publicKey.compressedRepresentation,
            authorityKeyID: Data(repeating: 0x55, count: 32),
            authorityReceipt: Data([0x01]),
            policyGeneration: 1,
            revocationGeneration: 1,
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            active: true
        )
    }

    private static func challenge(
        installationID: Data,
        keyID: Data,
        fingerprint: Data,
        endpoint: String
    ) -> Data {
        var output = Data([0xb1])
        output += uint(0) + uint(1)
        output += uint(1) + text("pistis.authentication-challenge.v1")
        output += uint(2) + uint(1_700_000_000_000)
        output += uint(3) + uint(1_700_000_060_000)
        output += uint(4) + bytes(installationID)
        output += uint(5) + bytes(keyID)
        output += uint(6) + bytes(Data(repeating: 0x66, count: 16))
        output += uint(7) + bytes(Data(repeating: 0x77, count: 32))
        output += uint(8) + bytes(Data(repeating: 0x88, count: 16))
        output += uint(9) + bytes(Data(repeating: 0x44, count: 16))
        output += uint(10) + text("authenticate-session")
        output += uint(11) + text("jenkins.mnemosyne.test")
        output += uint(12) + text("Mnemosyne Jenkins")
        output += uint(13) + text("stephen")
        output += uint(14) + bytes(Data(repeating: 0x99, count: 32))
        output += uint(15) + bytes(fingerprint)
        output += uint(16) + Data([0x81]) + text(endpoint)
        return output
    }

    private static func qr(cose: Data) -> String {
        let frame = Data([0xa3, 0x00, 0x02, 0x01, 0x01, 0x02]) + bytes(cose)
        let body = frame.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let checksum = SHA256.hash(data: Data(body.utf8)).prefix(8)
            .map { String(format: "%02x", $0) }.joined()
        return "PISTIS1:\(body).\(checksum)"
    }

    private static func bytes(_ value: Data) -> Data {
        argument(major: 2, UInt64(value.count)) + value
    }

    private static func lowS(_ signature: Data) -> Data {
        let halfOrder = Data([
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
            0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
        ])
        let s = signature.suffix(32)
        guard s.lexicographicallyPrecedes(halfOrder) || s == halfOrder else {
            let order: [UInt8] = [
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
            ]
            let scalar = Array(s)
            var result = [UInt8](repeating: 0, count: 32)
            var borrow = 0
            for index in stride(from: 31, through: 0, by: -1) {
                var value = Int(order[index]) - Int(scalar[index]) - borrow
                if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }
                result[index] = UInt8(value)
            }
            return signature.prefix(32) + Data(result)
        }
        return signature
    }
    private static func text(_ value: String) -> Data {
        argument(major: 3, UInt64(value.utf8.count)) + Data(value.utf8)
    }
    private static func uint(_ value: UInt64) -> Data { argument(major: 0, value) }
    private static func argument(major: UInt8, _ value: UInt64) -> Data {
        if value < 24 { return Data([major << 5 | UInt8(value)]) }
        if value <= UInt8.max { return Data([major << 5 | 24, UInt8(value)]) }
        if value <= UInt16.max {
            let v = UInt16(value).bigEndian
            return Data([major << 5 | 25]) + withUnsafeBytes(of: v) { Data($0) }
        }
        if value <= UInt32.max {
            let v = UInt32(value).bigEndian
            return Data([major << 5 | 26]) + withUnsafeBytes(of: v) { Data($0) }
        }
        let v = value.bigEndian
        return Data([major << 5 | 27]) + withUnsafeBytes(of: v) { Data($0) }
    }
}
