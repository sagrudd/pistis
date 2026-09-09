import CryptoKit
import Foundation
import XCTest
@testable import Pistis

final class StandaloneReceiptUnlockTests: XCTestCase {
    @MainActor
    func testMissingDirectBindingHasLocalFailureWithoutBrokerRequest() async throws {
        let coordinator = SiteRootConvergenceCoordinator(
            transport: try MonasSiteX509FirstProvisionBrokerTransport(),
            standaloneUnlockAvailable: false
        )
        await coordinator.acceptStandaloneUnlock(qrText: descriptor)
        XCTAssertEqual(coordinator.phase, .failed(.siteRootBindingUnavailable))
        XCTAssertNil(coordinator.presentedReview)
    }
    // Exact serialised four-field QrDescriptor from deployed Monas
    // 7f6952486c56595f7c6652f2447b2007316e9e69,
    // crates/monas-server/src/site_root_bundle_receipt_unlock_relay.rs:33–42.
    // Public conformance vector, not a physical-camera or live approval receipt.
    private let descriptor = #"{"schema":"monas.site-root-bundle-receipt-unlock-qr.v1","purpose":"thesaurophylax.site-root-bundle-receipt-rewrap.v1","role":"site-root-bundle-receipt","presentation_path":"/v1/pistis/site-root-bundle-receipt-unlock/presentation"}"#

    func testExactMonasDescriptorAndClosedDenials() throws {
        XCTAssertEqual(MonasJSONScanRoute.classify(descriptor), .siteRootConvergence)
        XCTAssertNoThrow(try SiteRootBundleReceiptUnlockDescriptorV1(qrText: descriptor))
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(descriptor.utf8)) as? [String: String])
        var invalid: [String] = []
        for key in original.keys {
            var changed = original
            changed[key] = "wrong"
            invalid.append(String(decoding: try JSONSerialization.data(withJSONObject: changed), as: UTF8.self))
            changed = original
            changed.removeValue(forKey: key)
            invalid.append(String(decoding: try JSONSerialization.data(withJSONObject: changed), as: UTF8.self))
            invalid.append(descriptor.dropLast() + ",\"\(key)\":\"\(original[key]!)\"}")
        }
        invalid += [descriptor.dropLast() + ",\"origin\":\"https://other.example\"}",
                    descriptor.replacingOccurrences(of: "\"site-root-bundle-receipt\"", with: "42"),
                    descriptor.replacingOccurrences(of: "/v1/pistis/", with: "https://other.example/v1/pistis/"),
                    "pistis://" + descriptor, descriptor + String(repeating: " ", count: 1_025)]
        for value in invalid { XCTAssertThrowsError(try SiteRootBundleReceiptUnlockDescriptorV1(qrText: value)) }
    }

    @MainActor
    func testDirectFetchedReviewAndResetSuppressesStaleCompletion() async throws {
        let value = try receiptPresentation(expiry: UInt64(Date().timeIntervalSince1970) + 120)
        let gate = UnlockFetchGate(value: value)
        let coordinator = SiteRootConvergenceCoordinator(transport: UnlockTransport(gate: gate))
        let text = descriptor
        await coordinator.acceptStandaloneUnlock(qrText: "{}")
        if case .failed = coordinator.phase {} else { XCTFail("malformed descriptor accepted") }
        coordinator.cancelStandaloneUnlock()
        XCTAssertEqual(coordinator.phase, .idle)
        let fetch = Task { await coordinator.acceptStandaloneUnlock(qrText: text) }
        await gate.waitUntilRequested()
        coordinator.cancelStandaloneUnlock()
        await gate.release()
        await fetch.value
        XCTAssertEqual(coordinator.phase, .idle)
        XCTAssertNil(coordinator.presentedReview)
        XCTAssertNil(coordinator.selectedTransportRoute)

        await coordinator.acceptStandaloneUnlock(qrText: text)
        XCTAssertEqual(coordinator.selectedTransportRoute, .direct)
        let review = try XCTUnwrap(coordinator.presentedReview)
        XCTAssertEqual(review.site, value.siteTrustDomain)
        XCTAssertEqual(review.kind, .bundleReceiptUnlock(generation: value.keyGeneration))
        coordinator.reset()
        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .idle)
        let submissions = await gate.submissions
        XCTAssertEqual(submissions, 0)
    }

    func testFetchedChallengePurposeSiteGenerationAndExpiry() throws {
        let now: UInt64 = 1_900_000_000
        let valid = try receiptPresentation(expiry: now + 120)
        XCTAssertNoThrow(try SiteRootConvergenceServiceV2.validateStandaloneUnlock(valid, nowUnixSeconds: now))
        XCTAssertThrowsError(try SiteRootConvergenceServiceV2.validateStandaloneUnlock(valid, nowUnixSeconds: now + 120))
        XCTAssertThrowsError(try SiteRootConvergenceServiceV2.validateStandaloneUnlock(valid, nowUnixSeconds: now - 301))
        for generation in ["other-1", "site-root-bundle-receipt-0", "site-root-bundle-receipt-01"] {
            XCTAssertThrowsError(try SiteRootConvergenceServiceV2.validateStandaloneUnlock(
                receiptPresentation(expiry: now + 120, generation: generation), nowUnixSeconds: now))
        }
        for site in ["site-demo", "02020202-0202-0202-0202-020202020202", "site-00000000-0000-0000-0000-000000000000"] {
            XCTAssertThrowsError(try SiteRootConvergenceServiceV2.validateStandaloneUnlock(
                receiptPresentation(expiry: now + 120, site: site), nowUnixSeconds: now))
        }
        XCTAssertThrowsError(try SiteRootConvergenceServiceV2.validateStandaloneUnlock(
            receiptPresentation(expiry: now + 120, schema: Data("wrong-purpose\0".utf8)), nowUnixSeconds: now))
    }

    private func receiptPresentation(
        expiry: UInt64, generation: String = "site-root-bundle-receipt-1",
        site: String = "site-02020202-0202-0202-0202-020202020202",
        schema: Data = SiteRootBundleReceiptRewrapV1.challengeSchema
    ) throws -> IphoneMediatedCustodyRewrapPresentationV1 {
        let record = Data(repeating: 0x44, count: 60)
        let digest = Data(SHA256.hash(data: record))
        let key = Data(repeating: 0x11, count: 32)
        let old = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
        let fresh = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
        let device = "site-root-fixture"
        var challenge = schema
        func field(_ tag: UInt8, _ bytes: Data) {
            challenge.append(tag)
            challenge.append(contentsOf: withUnsafeBytes(of: UInt16(bytes.count).bigEndian, Array.init))
            challenge.append(bytes)
        }
        field(1, Data(site.utf8)); field(2, Data(generation.utf8)); field(3, Data(device.utf8))
        field(4, key); field(5, digest)
        field(6, Data(withUnsafeBytes(of: UInt64(7).bigEndian, Array.init)))
        field(7, Data("serial-1".utf8))
        field(8, Data(withUnsafeBytes(of: expiry.bigEndian, Array.init)))
        field(9, fresh)
        return try IphoneMediatedCustodyRewrapPresentationV1(
            correlation: Data(repeating: 1, count: 16), canonicalChallenge: challenge,
            siteTrustDomain: site, keyGeneration: generation, deviceKeyID: device,
            expectedEd25519PublicKey: key, encryptedRecordDigest: digest,
            currentRevocationGeneration: 7, delegationSerial: "serial-1", expiresAtUnixSeconds: expiry,
            existingHostEphemeralPublicSEC1: old, existingEncryptedRecord: record,
            freshHostEphemeralPublicSEC1: fresh, expectedChallengeSchema: schema
        )
    }

    @MainActor
    func testFreshAuthenticationCancellationAndPreSubmitChecks() async throws {
        for cancelAt in [0, 1, 2, 3] {
            var checks = 0
            var events: [String] = []
            do {
                try await SiteRootConvergenceServiceV2.performStandaloneUnlock(
                    requireCurrent: {
                        checks += 1
                        if checks == cancelAt { throw PlatformFailure.custodyRewrapUnavailable }
                    },
                    authenticate: { events.append("fresh-authentication"); return 1 },
                    produce: { _ in events.append("produce"); return 2 },
                    submit: { _ in events.append("submit") }
                )
                XCTAssertEqual(cancelAt, 0)
            } catch { XCTAssertNotEqual(cancelAt, 0) }
            XCTAssertEqual(events, cancelAt == 0 ? ["fresh-authentication", "produce", "submit"]
                : cancelAt == 1 ? [] : cancelAt == 2 ? ["fresh-authentication"] : ["fresh-authentication", "produce"])
        }
    }

    @MainActor
    func testWrongDeviceBindingStopsBeforeProofAndSubmission() async throws {
        let key = P256.Signing.PrivateKey().publicKey.compressedRepresentation
        let correct = "site-root-" + Data(SHA256.hash(data: key)).map { String(format: "%02x", $0) }.joined()
        XCTAssertNoThrow(try SecureEnclaveSiteRootBundleReceiptRewrapProducerV1.requireDeviceBinding(key, deviceKeyID: correct))
        var events: [String] = []
        do {
            try await SiteRootConvergenceServiceV2.performStandaloneUnlock(
                requireCurrent: {}, authenticate: { events.append("authentication") },
                produce: { _ in
                    try SecureEnclaveSiteRootBundleReceiptRewrapProducerV1.requireDeviceBinding(key, deviceKeyID: "site-root-wrong")
                    events.append("proof")
                }, submit: { _ in events.append("submit") }
            )
            XCTFail("wrong device accepted")
        } catch {}
        XCTAssertEqual(events, ["authentication"])
    }
}

private actor UnlockFetchGate {
    let value: IphoneMediatedCustodyRewrapPresentationV1
    var requested = false
    var released = false
    var submissions = 0
    init(value: IphoneMediatedCustodyRewrapPresentationV1) { self.value = value }
    func fetch() async -> IphoneMediatedCustodyRewrapPresentationV1 {
        requested = true
        while !released { await Task.yield() }
        return value
    }
    func waitUntilRequested() async { while !requested { await Task.yield() } }
    func release() { released = true }
    func submit() { submissions += 1 }
}

private struct UnlockTransport: MonasSiteRootConvergenceSubmitting {
    let authorityOrigin = URL(string: "https://enrolled.example")!
    let gate: UnlockFetchGate
    func fetchBundleReceiptUnlock(nowUnixSeconds: UInt64) async throws -> IphoneMediatedCustodyRewrapPresentationV1 {
        await gate.fetch()
    }
    func submitBundleReceiptUnlock(_: IphoneMediatedCustodyRewrapSubmissionV1) async throws { await gate.submit() }
    func submitBundleReceiptProvision(_: SiteRootBundleReceiptProvisionPresentationV1, detachedCOSE: Data) async throws -> UInt64 { throw PlatformFailure.siteRootAuthorityUnavailable }
    func submitSiteX509FirstProvision(_: SiteX509FirstProvisionPresentationV1, detachedCOSE: Data) async throws { throw PlatformFailure.siteRootAuthorityUnavailable }
    func reserveSiteX509FirstProvisionBroker(_: SiteX509FirstProvisionBrokerPresentationV1) async throws { throw PlatformFailure.siteRootAuthorityUnavailable }
    func submitSiteX509FirstProvisionBroker(_: SiteX509FirstProvisionBrokerPresentationV1, detachedCOSE: Data) async throws { throw PlatformFailure.siteRootAuthorityUnavailable }
    func registerAckKey(_: SiteRootConvergenceAckRegistrationV2) async throws -> SiteRootConvergenceAckRegistrationResultV2 { throw PlatformFailure.siteRootAuthorityUnavailable }
    func submitAck(_: Data, endpoint: URL) async throws { throw PlatformFailure.siteRootAuthorityUnavailable }
}
