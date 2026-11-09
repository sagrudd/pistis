import CryptoKit
import Foundation
import XCTest
@testable import Pistis

final class SiteRootBrokerV2PreparerTests: XCTestCase {
    private func fixture() throws -> SiteRootBrokerPresentationV2 {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Fixtures/broker-v2-qr.json")
        return try SiteRootBrokerPresentationV2(qrText: String(contentsOf: url, encoding: .utf8),
                                                 nowMillis: 1_900_000_000_000)
    }
    private func root() -> SiteRootKeyRegistrationV1 {
        let publicKey = P256.Signing.PrivateKey().publicKey.compressedRepresentation
        return SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-" + SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined(),
            publicKeyCompressedSEC1: publicKey, secureEnclaveAttestation: "not-asserted")
    }
    func testExactRetryRetainsOneKeyAndDoesNotTouchLegacy() async throws {
        let service = PreparationTestAppleService()
        let legacy = PreparationTestLegacyStore()
        let persistence = ScopedMemoryPersistence()
        let storage = ScopedAppAttestStore(persistence: persistence)
        let preparer = SiteRootBrokerV2Preparer(
            storage: storage, appAttest: AppleAppAttestClient(service: service, keyIDStore: legacy))
        let presentation = try fixture(), key = root(), attempt = UUID()
        let first = try await preparer.prepare(
            presentation: presentation, attemptID: attempt, siteRootKey: key, nowMillis: { 1_900_000_000_000 })
        let second = try await preparer.prepare(
            presentation: presentation, attemptID: attempt, siteRootKey: key, nowMillis: { 1_900_000_000_000 })
        XCTAssertEqual(first, second)
        XCTAssertEqual(service.generated, 1); XCTAssertEqual(service.attested, 1)
        XCTAssertEqual(legacy.reads, 0); XCTAssertEqual(legacy.writes, 0)
        try storage.markSubmitted(attemptID: attempt)
        let afterSend = try await preparer.prepare(
            presentation: presentation, attemptID: attempt, siteRootKey: key, nowMillis: { 1_900_000_000_000 })
        XCTAssertEqual(afterSend, first)
        XCTAssertEqual(service.generated, 1)
        do {
            _ = try await preparer.prepare(presentation: presentation, attemptID: attempt,
                                            siteRootKey: root(), nowMillis: { 1_900_000_000_000 })
            XCTFail("substituted root key unexpectedly accepted")
        } catch { XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration) }
        XCTAssertEqual(service.generated, 1)
    }
    func testOrphanedPreparationNeverRegeneratesOnRestart() async throws {
        let service = PreparationTestAppleService()
        let persistence = ScopedMemoryPersistence(); persistence.failNextPending = true
        let storage = ScopedAppAttestStore(persistence: persistence)
        let preparer = SiteRootBrokerV2Preparer(
            storage: storage, appAttest: AppleAppAttestClient(service: service, keyIDStore: PreparationTestLegacyStore()))
        let presentation = try fixture(), key = root(), attempt = UUID()
        do {
            _ = try await preparer.prepare(presentation: presentation, attemptID: attempt,
                                            siteRootKey: key, nowMillis: { 1_900_000_000_000 })
            XCTFail("injected pending write failure unexpectedly succeeded")
        } catch { }
        XCTAssertEqual(service.generated, 1)
        let restarted = SiteRootBrokerV2Preparer(
            storage: ScopedAppAttestStore(persistence: persistence),
            appAttest: AppleAppAttestClient(service: service, keyIDStore: PreparationTestLegacyStore()))
        do {
            _ = try await restarted.prepare(presentation: presentation, attemptID: attempt,
                                             siteRootKey: key, nowMillis: { 1_900_000_000_000 })
            XCTFail("orphaned attempt regenerated a key")
        } catch { XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration) }
        XCTAssertEqual(service.generated, 1)
        try storage.abandonPreparing(attempt)
        do {
            _ = try await restarted.prepare(presentation: presentation, attemptID: attempt,
                                             siteRootKey: key, nowMillis: { 1_900_000_000_000 })
            XCTFail("abandoned attempt restarted")
        } catch { XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration) }
        XCTAssertEqual(service.generated, 1)
    }

    func testResetInvalidatesInFlightPreparationMarker() async throws {
        let storage = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let preparer = SiteRootBrokerV2Preparer(
            storage: storage, appAttest: AppleAppAttestClient(service: PreparationTestAppleService(), keyIDStore: PreparationTestLegacyStore()))
        let attempt = UUID()
        let pending = try await preparer.prepare(presentation: fixture(), attemptID: attempt,
                                                  siteRootKey: root(), nowMillis: { 1_900_000_000_000 })
        try storage.resetAll()
        try storage.markPreparing(attempt)
        try storage.resetAll()
        XCTAssertThrowsError(try storage.stagePrepared(pending))
        XCTAssertThrowsError(try storage.markSubmitted(attemptID: attempt))
    }
}

private final class PreparationTestLegacyStore: AppleAppAttestKeyIDStoring, @unchecked Sendable {
    private(set) var reads = 0; private(set) var writes = 0
    func loadKeyID() -> String? { reads += 1; return Data(repeating: 0x11, count: 32).base64EncodedString() }
    func saveKeyID(_: String) throws { writes += 1 }
}
private final class PreparationTestAppleService: AppleAppAttestServicing, @unchecked Sendable {
    private(set) var generated = 0; private(set) var attested = 0
    var isSupported: Bool { true }
    func generateKey() async throws -> String { generated += 1; return Data(repeating: 0x22, count: 32).base64EncodedString() }
    func attestKey(_: String, clientDataHash _: Data) async throws -> Data { attested += 1; return Data([1, 2, 3]) }
    func generateAssertion(_: String, clientDataHash _: Data) async throws -> Data { throw PlatformFailure.appAttestUnavailable }
}
