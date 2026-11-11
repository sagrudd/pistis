import Foundation
import XCTest
@testable import Pistis

final class AttendedRecoveryQRV1Tests: XCTestCase {
    private let qr = #"{"app_attest_key_id_b64url":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A","intent_b64url":"bW5lbW9zeW5lLm1vbmFzLmF0dGVuZGVkLXJlY292ZXJ5LmludGVudC52MQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICAgICAgLQ3xIp0PVGoYEpxkKzy7itEqSZ-zV4kcfk6ofL6ZIPzAQEBAQEBAQEBAQEBAQEBASON7Sp8mXYFZjG4GNwNkyJ2khooa-j2j5at_u56W0JqwUFBQUFBQUFBQUFBQUFBQUGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgcHBwcHBwcHBwcHBwcHBwcICAgICAgICAgICAgICAgICQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQm5sH3U53GEVEdvBO3rk1Airk9NkJNKt86RP_IMi66zmfDji4MOvYpQZhXs0VQzDsB_9r9QMER7ROKX2x1LdRSsSZjFZT8MESsmrT_YsXGFeBfij9cH04sI0Jed1akjB2xwtkyct432qbY2JSKfymaFgBS0KBTpxbVlB827ql0nZQAAAABrSdIAAAAAAGtJ1Fg","phone_relay_secret_b64url":"CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo","reference":"reg-001","schema":"mnemosyne.monas.attended-recovery.qr.v1","site":"site-12345678-1234-1234-1234-123456789abc","site_root_public_key_b64url":"Al7L5NGmMwpEyPfvlR1L8WXmxrch762phftBZhvG5_1s"}"#
    private func storage() throws -> ScopedAppAttestStore {
        let store = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let id = try XCTUnwrap(UUID(uuidString: "02020202-0202-0202-0202-020202020202"))
        let pending = ScopedAppAttestPending(attemptID: id, correlation: Data(repeating: 3, count: 32),
            registrationReference: "reg-001", siteClaim: "site-12345678-1234-1234-1234-123456789abc",
            appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier, environmentClaim: "Production",
            keyID: Data(97...128).base64EncodedString(), preparedRegistration: Data([1]))
        try store.stage(pending); try store.markSubmitted(attemptID: id)
        return store
    }
    func testSharedQRAndTranscript() throws {
        let store = try storage(); defer { try? store.resetAll() }
        let value = try AttendedRecoveryQRV1(data: Data(qr.utf8), now: 1_799_999_940, storage: store)
        XCTAssertEqual(try value.transcript.digest().map { String(format: "%02x", $0) }.joined(),
            "e1ccd083edae148e685463b77fe1c2e581077b859e6ea9ed6007937e8cb6f5c1")
        XCTAssertEqual(try AttendedRecoveryComparison.format(value.transcript.comparison()), "96D9-7DA8-E53B-EDBB")
        XCTAssertEqual(value.pending.correlation, Data(repeating: 3, count: 32))
        let signature = Data(base64Encoded: "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI/EdmmXgyJVTu4KmxzymgQY6TWofxoLRwx42aw1wYf3mz/VTGpg==")!
        let proof = try AttendedRecoveryProofWireV1.encode(transcript: value.transcript,
            signature: signature, assertion: Data([0xa1, 1, 2, 3]))
        XCTAssertEqual(String(decoding: proof, as: UTF8.self), #"{"assertion_b64url":"oQECAw","correlation_b64url":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","schema":"mnemosyne.monas.attended-recovery.proof.v1","signature_b64url":"fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXgyJVTu4KmxzymgQY6TWofxoLRwx42aw1wYf3mz_VTGpg","transcript_b64url":"bW5lbW9zeW5lLm1vbmFzLmF0dGVuZGVkLXJlY292ZXJ5LnYxAAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJAgICAgICAgICAgICAgICAtDfEinQ9UahgSnGQrPLuK0SpJn7NXiRx-Tqh8vpkg_MdNgqLgnXgt8j4IHSMzxjGecIGuI64uMo67EKp26NVviON7Sp8mXYFZjG4GNwNkyJ2khooa-j2j5at_u56W0JqwQEBAQEBAQEBAQEBAQEBARhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gHAYh-3K30aS5MgE3GEc2zlBPdfzxDMKddSLQVtQPPT-BQUFBQUFBQUFBQUFBQUFBQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGcLZMnLeN9qm2NiUin8pmhYAUtCgU6cW1ZQfNu6pdJ2XaPMivGoKdmzhDAQRtymKwf3UK3bo0xKFEGog4I_sF0gAAAABrSdIA"}"#)
        XCTAssertThrowsError(try AttendedRecoveryProofWireV1.encode(transcript: value.transcript,
            signature: signature, assertion: Data(repeating: 1, count: 5_201)))
    }
    func testRejectsWrongPendingExpiryAndClosedSchema() throws {
        let store = try storage(); defer { try? store.resetAll() }
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: Data(qr.utf8), now: 1_800_000_000, storage: store))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: Data(qr.replacingOccurrences(of: "reg-001", with: "reg-002").utf8), now: 1_799_999_940, storage: store))
        let duplicate = qr.replacingOccurrences(of: "{", with: "{\"schema\":\"x\",", options: [], range: qr.startIndex..<qr.index(after: qr.startIndex))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: Data(duplicate.utf8), now: 1_799_999_940, storage: store))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: Data(qr.utf8), now: 1_799_999_940, storage: ScopedAppAttestStore(persistence: ScopedMemoryPersistence())))
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(qr.utf8)) as? [String: String])
        let encodedIntent = try XCTUnwrap(fields["intent_b64url"])
        var intent = try XCTUnwrap(SiteRootBrokerPresentationV2.base64(encodedIntent, exact: 428))
        intent[intent.count - 48] ^= 1
        fields["intent_b64url"] = SiteRootBrokerPresentationV2.encode(intent)
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: JSONSerialization.data(withJSONObject: fields), now: 1_799_999_940, storage: store))
        fields["intent_b64url"] = encodedIntent
        fields["phone_relay_secret_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 9, count: 32))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: JSONSerialization.data(withJSONObject: fields), now: 1_799_999_940, storage: store))
        fields["phone_relay_secret_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 10, count: 32))
        fields["app_attest_key_id_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 8, count: 32))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: JSONSerialization.data(withJSONObject: fields), now: 1_799_999_940, storage: store))
    }
}
