import CryptoKit
import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class IssuerNativeSessionTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 100)
    private func json(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) }
    private func beginFields() throws -> [String: Any] {
        // COSE/transfer carriage fixture only. No signature/owner is admitted.
        let cose = try CoseSign1(keyID: Data(repeating: 3, count: 32), payload: Data([0x80]), signature: Data(repeating: 1, count: 64)).encoded()
        XCTAssertLessThan(cose.count, 256)
        var frame = Data([0xa3, 0, 2, 1, 1, 2, 0x58, UInt8(cose.count)])
        frame.append(cose)
        let body = IssuerNativeSessionWire.encode(frame)
        let checksum = IssuerNativeSessionWire.hex(Data(SHA256.hash(data: Data("PISTIS1:\(body)".utf8)).prefix(8)))
        return ["profile": IssuerNativeSessionWire.profile,
            "reference": IssuerNativeSessionWire.encode(Data(repeating: 7, count: 32)),
            "initiator_secret_b64url": IssuerNativeSessionWire.encode(Data(repeating: 8, count: 32)),
            "signed_challenge_b64url": IssuerNativeSessionWire.encode(cose),
            "transfer": "PISTIS1:\(body).\(checksum)", "expires_at_utc": "1970-01-01T00:03:20.123Z"]
    }
    private func finalizedFields() -> [String: Any] {
        ["profile": IssuerNativeSessionWire.profile,
            "session_id": "11111111-1111-4111-8111-111111111111",
            "principal_id": "22222222-2222-4222-8222-222222222222",
            "installation_id": "33333333-3333-4333-8333-333333333333",
            "device_id": "44444444-4444-4444-8444-444444444444",
            "device_key_id": String(repeating: "ab", count: 32),
            "binding_id": "55555555-5555-4555-8555-555555555555", "binding_generation": 1,
            "policy_generation": 2, "revocation_generation": 1,
            "completion_id": "66666666-6666-4666-8666-666666666666",
            "challenge_id": "77777777-7777-4777-8777-777777777777",
            "expires_at_utc": "1970-01-01T00:03:20Z"]
    }
    func testOwnedBeginSecretIsCanonicalOneUseAndTransferIsExact() throws {
        let fields = try beginFields()
        let begin = try IssuerNativeSessionWire.begin(json(fields), now: now)
        XCTAssertEqual(try begin.takeInitiatorSecret(), Data(repeating: 8, count: 32))
        XCTAssertThrowsError(try begin.takeInitiatorSecret())
        for (name, replacement) in [("profile", "browser"), ("initiator_secret_b64url", "AA=="),
            ("signed_challenge_b64url", "gA"), ("transfer", "PISTIS1:foreign.0000000000000000"),
            ("expires_at_utc", "1970-01-01T00:00:01Z")] {
            var changed = fields; changed[name] = replacement
            XCTAssertThrowsError(try IssuerNativeSessionWire.begin(json(changed), now: now))
        }
        var unknown = fields; unknown["session_credential"] = "forbidden"
        XCTAssertThrowsError(try IssuerNativeSessionWire.begin(json(unknown), now: now))
        let duplicate = Data(("{\"profile\":\"duplicate\"," + String(String(decoding: try json(fields), as: UTF8.self).dropFirst())).utf8)
        XCTAssertThrowsError(try IssuerNativeSessionWire.begin(duplicate, now: now))
    }
    func testFinalizeMetadataIsClosedCanonicalAndContainsNoCredential() throws {
        let fields = finalizedFields()
        let result = try IssuerNativeSessionWire.finalized(json(fields), now: now)
        XCTAssertEqual(result.bindingGeneration, 1)
        for (name, replacement) in [("profile", "browser"), ("session_id", "00000000-0000-0000-0000-000000000000"),
            ("device_key_id", "sha256:" + String(repeating: "ab", count: 32)),
            ("challenge_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")] {
            var changed = fields; changed[name] = replacement
            XCTAssertThrowsError(try IssuerNativeSessionWire.finalized(json(changed), now: now))
        }
        var unknown = fields; unknown["credential"] = "forbidden"
        XCTAssertThrowsError(try IssuerNativeSessionWire.finalized(json(unknown), now: now))
        for value in ["1", -1, 1.5, true] as [Any] {
            var changed = fields; changed["binding_generation"] = value
            XCTAssertThrowsError(try IssuerNativeSessionWire.finalized(json(changed), now: now))
        }
    }
    func testFinalizeMustJoinExactEnrolledTargetAndChallenge() throws {
        let enrollment = try nativeIssuerEnrollmentDataFixture()
        let expected = try IssuerNativeSessionWire.uuid("77777777-7777-4777-8777-777777777777")
        let fields = finalizedFields()
        let result = try IssuerNativeSessionWire.finalized(json(fields), now: now)
        try IssuerNativeSessionWire.checkFinalized(result, enrollment: enrollment,
            challengeID: expected, actualDeviceKeyID: enrollment.responseContext.deviceKeyID)
        for name in ["principal_id", "installation_id", "device_id", "challenge_id"] {
            var changed = fields; changed[name] = "99999999-9999-4999-8999-999999999999"
            let other = try IssuerNativeSessionWire.finalized(json(changed), now: now)
            XCTAssertThrowsError(try IssuerNativeSessionWire.checkFinalized(other, enrollment: enrollment,
                challengeID: expected, actualDeviceKeyID: enrollment.responseContext.deviceKeyID))
        }
        var changed = fields; changed["policy_generation"] = 1
        let old = try IssuerNativeSessionWire.finalized(json(changed), now: now)
        XCTAssertThrowsError(try IssuerNativeSessionWire.checkFinalized(old, enrollment: enrollment,
            challengeID: expected, actualDeviceKeyID: enrollment.responseContext.deviceKeyID))
        XCTAssertThrowsError(try IssuerNativeSessionWire.checkFinalized(result, enrollment: enrollment,
            challengeID: expected, actualDeviceKeyID: Data(repeating: 9, count: 32)))
    }
    func testActualIssuerRequestBuilderBindsNativeProfileAndCredentialTogether() throws {
        let session = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        let secret = Data(repeating: 8, count: 32)
        for path in [IssuerPhoneWire.readinessPath, IssuerPhoneWire.exchangePath, NativeInstallApprovalWire.preparePath, NativeInstallApprovalWire.submitPath, IssuerSiteRootTransport.currentPreparationPath, "/v1/pistis/issuer-site-root/joint/prepare"] {
            var request = URLRequest(url: URL(string: "https://monas.example.test" + path)!)
            request.httpMethod = "POST"
            request.setValue("application/cbor", forHTTPHeaderField: "Content-Type")
            let assembled = try IssuerNativeSessionWire.issuerRequestData(request, sessionID: session,
                secret: secret, enrolledOrigin: "https://monas.example.test")
            XCTAssertEqual(assembled.value(forHTTPHeaderField: "Pistis-Session-Profile"), IssuerNativeSessionWire.profile)
            XCTAssertEqual(assembled.value(forHTTPHeaderField: "Authorization"),
                "Pistis 11111111-1111-4111-8111-111111111111." + IssuerNativeSessionWire.encode(secret))
            for header in ["Pistis-Session-Profile", "Authorization", "Cookie", "Origin"] {
                var foreign = request; foreign.setValue("foreign", forHTTPHeaderField: header)
                XCTAssertThrowsError(try IssuerNativeSessionWire.issuerRequestData(foreign, sessionID: session,
                    secret: secret, enrolledOrigin: "https://monas.example.test"))
            }
            var foreign = request; foreign.url = URL(string: "https://foreign.example.test" + path)
            XCTAssertThrowsError(try IssuerNativeSessionWire.issuerRequestData(foreign, sessionID: session,
                secret: secret, enrolledOrigin: "https://monas.example.test"))
        }
    }
    func testStatusCannotRecoverCredentialOrAdvancePendingOrDuplicateCompletion() throws {
        try IssuerNativeSessionWire.completedStatus(Data("{\"state\":\"completed\",\"evidence_id\":null}".utf8))
        for value in ["{\"state\":\"pending\"}", "{\"state\":\"completed\",\"credential\":\"forbidden\"}",
            "{\"state\":\"completed\",\"state\":\"completed\"}"] {
            XCTAssertThrowsError(try IssuerNativeSessionWire.completedStatus(Data(value.utf8)))
        }
    }
    func testNativePurposeCredentialPathGateRejectsAdjacentRoutesAndQueries() throws {
        let session = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        let secret = Data(repeating: 8, count: 32)
        for path in [NativeInstallApprovalWire.preparePath + "/extra", NativeInstallApprovalWire.submitPath + "-other",
                     NativeInstallApprovalWire.preparePath + "?redirect=1", NativeInstallApprovalWire.submitPath + "#fragment",
                     "/auth/pistis/v2/issuer/native-purpose"] {
            var request = URLRequest(url: URL(string: "https://monas.example.test" + path)!)
            request.httpMethod = "POST"
            request.setValue("application/cbor", forHTTPHeaderField: "Content-Type")
            XCTAssertThrowsError(try IssuerNativeSessionWire.issuerRequestData(request, sessionID: session,
                secret: secret, enrolledOrigin: "https://monas.example.test"))
        }
        var get = URLRequest(url: URL(string: "https://monas.example.test" + NativeInstallApprovalWire.preparePath)!)
        get.httpMethod = "GET"; get.setValue("application/cbor", forHTTPHeaderField: "Content-Type")
        XCTAssertThrowsError(try IssuerNativeSessionWire.issuerRequestData(get, sessionID: session,
            secret: secret, enrolledOrigin: "https://monas.example.test"))
    }

}

/// Public DATA fixture only; never installed in Keychain or made a session owner.
func nativeIssuerEnrollmentDataFixture() throws -> AuthenticatedEnrollmentOutput {
    func raw(_ text: String) -> Data {
        let hex = Array(text.replacingOccurrences(of: "-", with: "").utf8)
        return Data(stride(from: 0, to: hex.count, by: 2).map { index in
            UInt8(String(decoding: hex[index..<index+2], as: UTF8.self), radix: 16)!
        })
    }
    let trust = try InstallationTrustRecord(installationID: raw("33333333-3333-4333-8333-333333333333"),
        displayName: "DATA fixture", audience: "prosopikon:pistis:enrolment", authorisedProductAudiences: ["propylaion"],
        userID: raw("22222222-2222-4222-8222-222222222222"), externalIdentityID: Data(repeating: 5, count: 16),
        fingerprint: Data(repeating: 6, count: 32), installationKeyID: Data(repeating: 7, count: 32),
        installationPublicKey: raw("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        authorityKeyID: Data(repeating: 8, count: 32), authorityReceipt: Data([0x80]),
        policyGeneration: 2, revocationGeneration: 1, expiresAt: Date(timeIntervalSince1970: 200), active: true)
    return try AuthenticatedEnrollmentOutput(trust: trust, responseContext: DeviceResponseContext(
        deviceID: raw("44444444-4444-4444-8444-444444444444"), deviceKeyID: Data(repeating: 0xab, count: 32),
        userID: trust.userID, externalIdentityID: trust.externalIdentityID), allowedHosts: ["monas.example.test"],
        httpsOrigin: "https://monas.example.test", tlsSPKISHA256: Data(repeating: 9, count: 32))
}
