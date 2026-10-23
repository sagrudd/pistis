import CryptoKit
import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class IssuerMacSessionTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 100)
    private func json(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func fields() throws -> [String: Any] {
        let enrollment = try nativeIssuerEnrollmentDataFixture()
        return ["schema":"mnemosyne.kleidophylax.mac-session-pending.v1",
            "operation_id":"11111111-1111-4111-8111-111111111111",
            "mac_session_id":"22222222-2222-4222-8222-222222222222",
            "mac_nonce_b64url":IssuerNativeSessionWire.encode(Data(repeating: 7, count: 32)),
            "server_nonce_b64url":IssuerNativeSessionWire.encode(Data(repeating: 8, count: 32)),
            "descriptor_sha256":"sha256:" + String(repeating: "1", count: 64),
            "policy_sha256":"sha256:" + String(repeating: "2", count: 64),
            "installation_id":try IssuerNativeSessionWire.uuid(enrollment.trust.installationID).uuidString.lowercased(),
            "site_id":"33333333-3333-4333-8333-333333333333",
            "root_origin":enrollment.httpsOrigin,
            "root_tls_spki_sha256":"sha256:" + IssuerNativeSessionWire.hex(enrollment.tlsSPKISHA256),
            "issued_at":99,"expires_at":120]
    }
    private func ack() -> SiteRootConvergenceAckRecordV2 {
        SiteRootConvergenceAckRecordV2(siteUUID: "33333333-3333-4333-8333-333333333333", targetIDB64URL: "retained-target-comparison", ackPublicKeyB64URL: "retained-key-comparison", generation: 1)
    }
    func testExactPendingUsesRetainedTargetAndEmitsOnlyClosedBindData() throws {
        let raw = try json(fields())
        let pending = try IssuerMacSessionWire.Pending(raw, now: now)
        XCTAssertEqual(pending.original, raw)
        try pending.check(enrollment: nativeIssuerEnrollmentDataFixture(), ack: ack(), now: now)
        let request = try pending.request()
        try IssuerMacSessionWire.validateRequest(request)
        let parsed = try StrictJSONObject(data: request, maximumBytes: 4096).values
        XCTAssertEqual(parsed["schema"], .string(IssuerMacSessionWire.requestSchema))
        XCTAssertEqual(parsed.count, 11)
        for name in ["session_id", "actor_id", "device_id", "device_key_id", "cookie", "credential", "issued_at", "expires_at"] { XCTAssertNil(parsed[name]) }
    }
    func testWrongInstallationSiteOriginPinAndUnknownOrNoncanonicalRecordsDeny() throws {
        let enrollment = try nativeIssuerEnrollmentDataFixture()
        for (field, replacement) in [
            ("installation_id","99999999-9999-4999-8999-999999999999"),
            ("site_id","99999999-9999-4999-8999-999999999999"),
            ("root_origin","https://foreign.example.test"),
            ("root_tls_spki_sha256","sha256:" + String(repeating: "3", count: 64))] {
            var bad = try fields(); bad[field] = replacement
            let pending = try IssuerMacSessionWire.Pending(json(bad), now: now)
            XCTAssertThrowsError(try pending.check(enrollment: enrollment, ack: ack(), now: now))
        }
        for (field, replacement) in [("schema","foreign"), ("mac_nonce_b64url",IssuerNativeSessionWire.encode(Data(repeating: 0, count: 32))), ("server_nonce_b64url","AA==")] {
            var bad = try fields(); bad[field] = replacement
            XCTAssertThrowsError(try IssuerMacSessionWire.Pending(json(bad), now: now))
        }
        var bad = try fields(); bad["actor_id"] = "claimed"
        XCTAssertThrowsError(try IssuerMacSessionWire.Pending(json(bad), now: now))
        let raw = try json(fields())
        XCTAssertThrowsError(try IssuerMacSessionWire.Pending(raw + Data([32]), now: now))
        let duplicate = Data(("{\"schema\":\"duplicate\"," + String(String(decoding: raw, as: UTF8.self).dropFirst())).utf8)
        XCTAssertThrowsError(try IssuerMacSessionWire.Pending(duplicate, now: now))
        XCTAssertThrowsError(try IssuerMacSessionWire.Pending(Data(repeating: 32, count: 4097), now: now))
    }
    func testPendingCannotRenewExpiryOrImportUnsafeNumbers() throws {
        for value in [98, 131, "120", true, 120.5, 9_007_199_254_740_992 as UInt64] as [Any] {
            var bad = try fields(); bad["expires_at"] = value
            XCTAssertThrowsError(try IssuerMacSessionWire.Pending(json(bad), now: now))
        }
        let pending = try IssuerMacSessionWire.Pending(json(fields()), now: now)
        XCTAssertThrowsError(try pending.check(enrollment: nativeIssuerEnrollmentDataFixture(), ack: ack(), now: Date(timeIntervalSince1970: 120)))
    }
    func testReceiptCorrelatesCompletePendingOriginalAndNeverBecomesCredential() throws {
        let pending = try IssuerMacSessionWire.Pending(json(fields()), now: now)
        let receipt: [String: Any] = ["schema":"monas.pistis.mac-session-bound.v1", "mac_session_id":pending.macSessionID,
            "operation_id":pending.operationID, "transcript_sha256":"sha256:" + IssuerNativeSessionWire.hex(Data(SHA256.hash(data: pending.original))), "expires_at":120]
        try IssuerMacSessionWire.receipt(json(receipt), pending: pending, now: now)
        for name in ["mac_session_id", "operation_id", "transcript_sha256"] {
            var bad = receipt; bad[name] = "substituted"
            XCTAssertThrowsError(try IssuerMacSessionWire.receipt(json(bad), pending: pending, now: now))
        }
        var bad = receipt; bad["expires_at"] = 121
        XCTAssertThrowsError(try IssuerMacSessionWire.receipt(json(bad), pending: pending, now: now))
        bad = receipt; bad["credential"] = "forbidden"
        XCTAssertThrowsError(try IssuerMacSessionWire.receipt(json(bad), pending: pending, now: now))
        bad = receipt; bad["transcript_sha256"] = "sha256:" + IssuerNativeSessionWire.hex(Data(SHA256.hash(data: try pending.request())))
        XCTAssertThrowsError(try IssuerMacSessionWire.receipt(json(bad), pending: pending, now: now))
    }
    func testExistingNativeAuthenticatorAdmitsOnlyExactJsonExchangeAndKeepsCbor() throws {
        let pending = try IssuerMacSessionWire.Pending(json(fields()), now: now)
        var request = URLRequest(url: URL(string: "https://monas.example.test" + IssuerPhoneWire.exchangePath)!)
        request.httpMethod = "POST"; request.httpBody = try pending.request()
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let secret = Data(repeating: 8, count: 32)
        let session = UUID(uuidString: "77777777-7777-4777-8777-777777777777")!
        let authorized = try IssuerNativeSessionWire.issuerRequestData(request, sessionID: session, secret: secret, enrolledOrigin: "https://monas.example.test")
        XCTAssertEqual(authorized.value(forHTTPHeaderField: "Pistis-Session-Profile"), IssuerNativeSessionWire.profile)
        XCTAssertTrue(authorized.value(forHTTPHeaderField: "Authorization")!.hasPrefix("Pistis " + session.uuidString.lowercased() + "."))
        request.url = URL(string: "https://monas.example.test" + IssuerPhoneWire.readinessPath)!
        XCTAssertThrowsError(try IssuerNativeSessionWire.issuerRequestData(request, sessionID: session, secret: secret, enrolledOrigin: "https://monas.example.test"))
        request.setValue("application/cbor", forHTTPHeaderField: "Content-Type"); request.httpBody = Data([0x80])
        _ = try IssuerNativeSessionWire.issuerRequestData(request, sessionID: session, secret: secret, enrolledOrigin: "https://monas.example.test")
    }
}
