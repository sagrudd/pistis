import CryptoKit
import Foundation
import XCTest
@testable import Pistis

final class AttendedRecoveryQRV1Tests: XCTestCase {
    private let qr = #"{"app_attest_key_id_b64url":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A","intent_b64url":"bW5lbW9zeW5lLm1vbmFzLmF0dGVuZGVkLXJlY292ZXJ5LmludGVudC52MQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICAgICAgLQ3xIp0PVGoYEpxkKzy7itEqSZ-zV4kcfk6ofL6ZIPzAQEBAQEBAQEBAQEBAQEBASON7Sp8mXYFZjG4GNwNkyJ2khooa-j2j5at_u56W0JqwUFBQUFBQUFBQUFBQUFBQUGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgcHBwcHBwcHBwcHBwcHBwcICAgICAgICAgICAgICAgICQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQm5sH3U53GEVEdvBO3rk1Airk9NkJNKt86RP_IMi66zmfDji4MOvYpQZhXs0VQzDsB_9r9QMER7ROKX2x1LdRSsMIwc-JegXDWE1xhuMLuAumhs4XH1TLOAsg-rk3mfc0FJmMVlPwwRKyatP9ixcYV4F-KP1wfTiwjQl53VqSMHbO8DlHzQSrAEg7HoEtPmpEQTrqQKggbJGeByD_bG8-9HAAAAAGtJ0gAAAAAAa0nUWA","phone_relay_secret_b64url":"CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo","reference":"reg-001","schema":"mnemosyne.monas.attended-recovery.qr.v1","site":"site-12345678-1234-1234-1234-123456789abc","site_root_public_key_b64url":"Al7L5NGmMwpEyPfvlR1L8WXmxrch762phftBZhvG5_1s","successor_phone_secret_b64url":"DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"}"#
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
            "0d0eece47b95f67e3c64df326217f773054c34415fe591f0afacd87b053a94f5")
        XCTAssertEqual(try AttendedRecoveryComparison.format(value.transcript.comparison()), "98AF-404A-B199-3266")
        XCTAssertEqual(value.pending.correlation, Data(repeating: 3, count: 32))
        let signature = Data(base64Encoded: "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI/EdmmXg4guR/N58m+YVBBDEeeSSiGToGOXGMlvoWLWwLY1najw==")!
        let proof = try AttendedRecoveryProofWireV1.encode(transcript: value.transcript,
            signature: signature, assertion: Data([0xa1, 1, 2, 3]))
        XCTAssertEqual(String(decoding: proof, as: UTF8.self), #"{"assertion_b64url":"oQECAw","correlation_b64url":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","schema":"mnemosyne.monas.attended-recovery.proof.v1","signature_b64url":"fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg4guR_N58m-YVBBDEeeSSiGToGOXGMlvoWLWwLY1najw","transcript_b64url":"bW5lbW9zeW5lLm1vbmFzLmF0dGVuZGVkLXJlY292ZXJ5LnYxAAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJAgICAgICAgICAgICAgICAtDfEinQ9UahgSnGQrPLuK0SpJn7NXiRx-Tqh8vpkg_MdNgqLgnXgt8j4IHSMzxjGecIGuI64uMo67EKp26NVviON7Sp8mXYFZjG4GNwNkyJ2khooa-j2j5at_u56W0JqwQEBAQEBAQEBAQEBAQEBARhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gHAYh-3K30aS5MgE3GEc2zlBPdfzxDMKddSLQVtQPPT-BQUFBQUFBQUFBQUFBQUFBQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG7wOUfNBKsASDsegS0-akRBOupAqCBskZ4HIP9sbz70dnVnH7xmRqVklYPRZ2qBdouyyGPWjsluWG9e1hoIJiPAAAAABrSdIA"}"#)
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
        var intent = try XCTUnwrap(SiteRootBrokerPresentationV2.base64(encodedIntent, exact: 460))
        intent[intent.count - 48] ^= 1
        fields["intent_b64url"] = SiteRootBrokerPresentationV2.encode(intent)
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: JSONSerialization.data(withJSONObject: fields), now: 1_799_999_940, storage: store))
        fields["intent_b64url"] = encodedIntent
        fields["phone_relay_secret_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 9, count: 32))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: JSONSerialization.data(withJSONObject: fields), now: 1_799_999_940, storage: store))
        fields["phone_relay_secret_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 10, count: 32))
        fields["phone_relay_secret_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: JSONSerialization.data(withJSONObject: fields), now: 1_799_999_940, storage: store))
        fields["phone_relay_secret_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 10, count: 32))
        fields["successor_phone_secret_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: JSONSerialization.data(withJSONObject: fields), now: 1_799_999_940, storage: store))
        fields["successor_phone_secret_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 12, count: 32))
        fields["app_attest_key_id_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 8, count: 32))
        XCTAssertThrowsError(try AttendedRecoveryQRV1(data: JSONSerialization.data(withJSONObject: fields), now: 1_799_999_940, storage: store))
    }
    @MainActor
    func testCancellationWhileAssertionSuspendedPreventsProofUpload() async throws {
        let store = try storage(); defer { try? store.resetAll() }
        let harness = try AttendedRecoveryTestHarness(qr: Data(qr.utf8), storage: store, now: 1_799_999_940)
        try harness.confirm(comparison: Data([0x98,0xaf,0x40,0x4a,0xb1,0x99,0x32,0x66]), now: 1_799_999_941)
        let root = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([3]))
        var sent = false
        do {
            try await harness.submit(now: { 1_799_999_942 }, sign: { transcript in
                try P256Format.rawSignature(fromStrictDER: root.signature(for: transcript.signingMessage()).derRepresentation)
            }, assertB: { _, _ in
                await Task.yield()
                harness.cancel()
                return Data([1])
            }, send: { _ in
                sent = true
                throw PlatformFailure.invalidConfiguration
            })
            XCTFail("Cancellation must prevent upload")
        } catch { XCTAssertFalse(sent) }
    }
    @MainActor
    func testSyntheticScanCompareProofAndMailboxReceipt() async throws {
        let store = try storage(); defer { try? store.resetAll() }
        let aID = UUID()
        let aKey = Data(repeating: 0x22, count: 32).base64EncodedString()
        let a = ScopedAppAttestPending(attemptID: aID, correlation: Data(repeating: 0x23, count: 32),
            registrationReference: "site-a", siteClaim: "site-a",
            appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier, environmentClaim: "Production",
            keyID: aKey, preparedRegistration: Data([1]))
        let aBinding = ScopedAppAttestBinding(attemptID: aID, installationID: Data(repeating: 0x24, count: 16),
            site: "site-a", appIdentifier: a.appClaim, environment: "Production", keyID: aKey,
            policyGeneration: 1, revocationGeneration: 1)
        try store.stage(a); try store.markSubmitted(attemptID: aID); try store.commit(aBinding)
        let harness = try AttendedRecoveryTestHarness(qr: Data(qr.utf8), storage: store, now: 1_799_999_940)
        let comparison = Data([0x98,0xaf,0x40,0x4a,0xb1,0x99,0x32,0x66])
        try harness.confirm(comparison: comparison, now: 1_799_999_941)
        let root = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([3]))
        var sends = 0
        let apple = RecoveryRecordingAppleService()
        let legacy = RecoveryLegacyStore()
        let client = AppleAppAttestClient(service: apple, keyIDStore: legacy)
        let pendingID = try XCTUnwrap(UUID(uuidString: "02020202-0202-0202-0202-020202020202"))
        try await harness.submit(now: { 1_799_999_942 }, sign: { transcript in
            try P256Format.rawSignature(fromStrictDER: root.signature(for: transcript.signingMessage()).derRepresentation)
        }, assertB: { transcript, signature in
            try await client.preparePendingAttendedRecoveryAssertion(transcript: transcript, signature: signature,
                storage: store, attemptID: pendingID, issuedAt: 1_799_999_940, now: 1_799_999_942)
        }, send: { request in
            sends += 1
            XCTAssertEqual(request.url, AttendedRecoveryMailboxV1.endpoint)
            let response = try XCTUnwrap(HTTPURLResponse(url: AttendedRecoveryMailboxV1.endpoint, statusCode: 200,
                httpVersion: nil, headerFields: ["Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"]))
            return (Data(#"{"schema":"mnemosyne.monas.first-install-broker.response.v1","state":"accepted"}"#.utf8), response)
        })
        XCTAssertEqual(sends, 1)
        XCTAssertEqual(apple.assertedKeyID, Data(97...128).base64EncodedString())
        XCTAssertEqual(legacy.reads, 0); XCTAssertEqual(legacy.writes, 0)
        XCTAssertEqual(try store.binding(installationID: aBinding.installationID), aBinding)
        let id = try XCTUnwrap(UUID(uuidString: "02020202-0202-0202-0202-020202020202"))
        let staged = try XCTUnwrap(store.attendedRecoveryProof(attemptID: id))
        let context = try staged.testOnlySuccessorContext(now: 1_800_000_100)
        XCTAssertEqual(context.requestID, Data(repeating: 7, count: 16))
        XCTAssertEqual(context.capability, Data(repeating: 12, count: 32))
        XCTAssertEqual(context.expiry, 1_800_000_600)
        XCTAssertThrowsError(try staged.testOnlySuccessorContext(now: context.expiry))
        XCTAssertThrowsError(try AttendedRecoveryTestHarness(qr: Data(qr.utf8), storage: store, now: 1_799_999_940))
    }

}

private final class RecoveryRecordingAppleService: AppleAppAttestServicing, @unchecked Sendable {
    private(set) var assertedKeyID: String?
    var isSupported: Bool { true }
    func generateKey() async throws -> String { throw PlatformFailure.invalidConfiguration }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data { throw PlatformFailure.invalidConfiguration }
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        assertedKeyID = keyID
        return Data([0xa1, 1, 2, 3])
    }
}
private final class RecoveryLegacyStore: AppleAppAttestKeyIDStoring, @unchecked Sendable {
    private(set) var reads = 0
    private(set) var writes = 0
    func loadKeyID() -> String? { reads += 1; return nil }
    func saveKeyID(_ keyID: String) throws { writes += 1 }
}
