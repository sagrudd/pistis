import CryptoKit
import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class SiteRootBrokerV2PreparerTests: XCTestCase {
    @MainActor
    func testNormalCoordinatorRunsBrokerV2WithControlledPeers() async throws {
        GenesisBrokerURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [GenesisBrokerURLProtocol.self]
        let broker = try MonasSiteRootGenesisBrokerTransport(session: URLSession(configuration: configuration),
            maximumPollAttempts: 1, pollDelayNanoseconds: 0)
        let presentation = try fixture(), registration = root()
        let canonical = "{\"device_key_id\":\"\(registration.deviceKeyID)\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\",\"site_trust_domain\":\"\(presentation.site)\"}"
        GenesisBrokerURLProtocol.delegationOverride = "{\"schema\":\"monas.site-root-genesis-registration-result.v1\",\"canonical_delegation_base64url\":\"\(SiteRootBrokerPresentationV2.encode(Data(canonical.utf8)))\",\"device_key_id\":\"\(registration.deviceKeyID)\",\"site_trust_domain\":\"\(presentation.site)\",\"submit_url\":\"https://customer.example.test/auth/pistis/site-root-delegations/v1/submit\",\"reference\":\"\(presentation.reference)\"}"
        let storage = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let legacy = PreparationTestLegacyStore(), service = PreparationTestAppleService()
        let coordinator = SiteRootDelegationCoordinator(testBroker: broker,
            appAttestClient: AppleAppAttestClient(service: service, keyIDStore: legacy),
            producer: ControlledBrokerRoot(registration: registration), storage: storage,
            eventRecorder: ControlledBrokerEventSink(), nowMillis: { 1_900_000_000_000 })
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Fixtures/broker-v2-qr.json")
        coordinator.accept(qrText: try String(contentsOf: url, encoding: .utf8))
        guard case .review = coordinator.phase else { return XCTFail("normal scan did not reach review") }
        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .submitted(.proofQueued))
        XCTAssertEqual(GenesisBrokerURLProtocol.requests().map { $0.url?.path }, [
            MonasSiteRootGenesisBrokerEndpointV1.registrationPath,
            MonasSiteRootGenesisBrokerEndpointV1.delegationPollPath,
            MonasSiteRootGenesisBrokerEndpointV1.proofPath])
        XCTAssertEqual(service.generated, 1); XCTAssertEqual(legacy.reads, 0); XCTAssertEqual(legacy.writes, 0)
        await coordinator.approve()
        guard case .failed = coordinator.phase else { return XCTFail("completed proof was replayed") }
        XCTAssertEqual(GenesisBrokerURLProtocol.requests().filter { $0.url?.path == MonasSiteRootGenesisBrokerEndpointV1.proofPath }.count, 1)
        XCTAssertEqual(service.generated, 1)
    }
    func testRecoverExternallyIssuedSyntheticV4Profile() throws {
        let url = URL(fileURLWithPath: "/tmp/pistis-swift-bridge-20261109/enrollment-b.json")
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("synthetic authority fixture unavailable") }
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let frameText = try XCTUnwrap(object["frame"] as? String)
        var frame = Data(); var cursor = frameText.startIndex
        while cursor < frameText.endIndex {
            let end = frameText.index(cursor, offsetBy: 2, limitedBy: frameText.endIndex) ?? frameText.endIndex
            frame.append(try XCTUnwrap(UInt8(frameText[cursor..<end], radix: 16)))
            cursor = end
        }
        let body = SiteRootBrokerPresentationV2.encode(frame)
        let checksum = SHA256.hash(data: Data("PISTIS1:\(body)".utf8)).prefix(8)
            .map { String(format: "%02x", $0) }.joined()
        let qr = "PISTIS1:\(body).\(checksum)"
        let millis = try XCTUnwrap(object["now_ms"] as? UInt64)
        let verified = try FirstDevicePresentationV4.verify(qrText: qr,
            expectedAppConfigurationDigest: Data(repeating: 7, count: 32),
            now: Date(timeIntervalSince1970: Double(millis) / 1_000))
        let record = ProvisionalBrokerPresentation(attemptID: UUID(), installationID: verified.installationID,
            presentationDigest: verified.presentationDigest, qrText: qr, verifiedAtMillis: millis)
        XCTAssertEqual(try ProvisionalPresentationRecovery.verify(record,
            expectedAppConfigurationDigest: Data(repeating: 7, count: 32)), verified)
        let wrong = ProvisionalBrokerPresentation(attemptID: record.attemptID, installationID: Data(repeating: 9, count: 16),
            presentationDigest: record.presentationDigest, qrText: qr, verifiedAtMillis: millis)
        XCTAssertThrowsError(try ProvisionalPresentationRecovery.verify(wrong,
            expectedAppConfigurationDigest: Data(repeating: 7, count: 32)))
    }
    func testBrokerEnvelopeUsesDistinctDecodedAndOuterLimits() throws {
        let registration = Data(repeating: 0x41, count: 12 * 1024)
        let body = try BrokerV2RelayEnvelope.encode(reference: "test", correlation: Data(repeating: 1, count: 32), registration: registration)
        XCTAssertGreaterThan(body.count, 12 * 1024)
        XCTAssertLessThanOrEqual(body.count, 32 * 1024)
        XCTAssertThrowsError(try BrokerV2RelayEnvelope.encode(reference: "test", correlation: Data(repeating: 1, count: 32), registration: registration + Data([1])))
    }
    func testProvisionalPresentationIsCreateOnceAndAmbiguityFailsClosed() async throws {
        let storage = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let preparer = SiteRootBrokerV2Preparer(
            storage: storage, appAttest: AppleAppAttestClient(service: PreparationTestAppleService(), keyIDStore: PreparationTestLegacyStore()))
        let presentation = try fixture(), first = UUID(), key = root()
        _ = try await preparer.prepare(presentation: presentation, attemptID: first,
                                       siteRootKey: key, nowMillis: { 1_900_000_000_000 })
        try storage.markSubmitted(attemptID: first)
        let installation = Data(repeating: 3, count: 16), digest = Data(repeating: 4, count: 32)
        XCTAssertEqual(try storage.stageProvisionalPresentation(installationID: installation, digest: digest, qrText: "PISTIS1:test", verifiedAtMillis: 1), first)
        XCTAssertEqual(try storage.provisionalPresentation(attemptID: first)?.qrText, "PISTIS1:test")
        XCTAssertEqual(try storage.stageProvisionalPresentation(installationID: installation, digest: digest, qrText: "PISTIS1:test", verifiedAtMillis: 1), first)
        XCTAssertThrowsError(try storage.stageProvisionalPresentation(installationID: installation, digest: Data(repeating: 5, count: 32), qrText: "PISTIS1:test", verifiedAtMillis: 1))
        let second = UUID()
        _ = try await preparer.prepare(presentation: presentation, attemptID: second,
                                       siteRootKey: key, nowMillis: { 1_900_000_000_000 })
        try storage.markSubmitted(attemptID: second)
        XCTAssertThrowsError(try storage.stageProvisionalPresentation(installationID: installation, digest: digest, qrText: "PISTIS1:test", verifiedAtMillis: 1))
    }
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

    func testRescanRecoversReservedAttemptAndRejectsChangedInvitation() throws {
        let persistence = ScopedMemoryPersistence()
        let presentation = try fixture()
        let original = try ScopedAppAttestStore(persistence: persistence).reserveBrokerAttempt(presentation)
        let reopened = ScopedAppAttestStore(persistence: persistence)
        XCTAssertEqual(try reopened.reserveBrokerAttempt(presentation), original)
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Fixtures/broker-v2-qr.json")
        let text = try String(contentsOf: url, encoding: .utf8)
        let changed = text.replacingOccurrences(of: presentation.site, with: presentation.site + "-changed")
        let other = try SiteRootBrokerPresentationV2(qrText: changed, nowMillis: 1_900_000_000_000)
        XCTAssertThrowsError(try reopened.reserveBrokerAttempt(other))
    }

    func testDispatchLifetimeExcludesResetAndResetPreventsDispatch() async throws {
        let storage = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let preparer = SiteRootBrokerV2Preparer(
            storage: storage, appAttest: AppleAppAttestClient(service: PreparationTestAppleService(), keyIDStore: PreparationTestLegacyStore()))
        let attempt = UUID()
        let pending = try await preparer.prepare(presentation: fixture(), attemptID: attempt,
                                                  siteRootKey: root(), nowMillis: { 1_900_000_000_000 })
        XCTAssertEqual(try storage.beginDispatch(attemptID: attempt, expected: pending), pending)
        try storage.markInitialProofSubmitted(attemptID: attempt, expected: pending)
        XCTAssertThrowsError(try storage.markInitialProofSubmitted(attemptID: attempt, expected: pending))
        XCTAssertThrowsError(try storage.resetAll())
        XCTAssertThrowsError(try ScopedAppAttestStore.beginLocalReset())
        storage.endDispatch()
        try ScopedAppAttestStore.beginLocalReset()
        XCTAssertThrowsError(try storage.reserveBrokerAttempt(fixture()))
        ScopedAppAttestStore.endLocalReset()
        try storage.resetAll()
        XCTAssertThrowsError(try storage.beginDispatch(attemptID: attempt, expected: pending))
    }

    func testV2DispatchSendsExactBytesOnceToFixedBroker() async throws {
        GenesisBrokerURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [GenesisBrokerURLProtocol.self]
        let transport = try MonasSiteRootGenesisBrokerTransport(session: URLSession(configuration: configuration))
        let storage = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let preparer = SiteRootBrokerV2Preparer(
            storage: storage, appAttest: AppleAppAttestClient(service: PreparationTestAppleService(), keyIDStore: PreparationTestLegacyStore()))
        let presentation = try fixture(), attempt = try storage.reserveBrokerAttempt(presentation), key = root()
        let pending = try await preparer.prepare(presentation: presentation, attemptID: attempt,
                                                  siteRootKey: key, nowMillis: { 1_900_000_000_000 })
        let fixtureURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Fixtures/broker-v2-qr.json")
        let text = try String(contentsOf: fixtureURL, encoding: .utf8)
        let wrong = try SiteRootBrokerPresentationV2(
            qrText: text.replacingOccurrences(of: presentation.site, with: presentation.site + "-changed"),
            nowMillis: 1_900_000_000_000)
        do {
            try await transport.submitV2(presentation: wrong, attemptID: attempt, storage: storage,
                                         nowMillis: { 1_900_000_000_000 })
            XCTFail("mismatched presentation was sent")
        } catch { XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration) }
        XCTAssertEqual(GenesisBrokerURLProtocol.requests().count, 0)
        try await transport.submitV2(presentation: presentation, attemptID: attempt, storage: storage,
                                     nowMillis: { 1_900_000_000_000 })
        let request = try XCTUnwrap(GenesisBrokerURLProtocol.requests().last)
        XCTAssertEqual(request.url?.absoluteString, MonasSiteRootGenesisBrokerEndpointV1.origin + MonasSiteRootGenesisBrokerEndpointV1.registrationPath)
        let body = try XCTUnwrap(request.httpBody)
        let object = try StrictJSONObject(data: body, maximumBytes: 300_000).values
        XCTAssertEqual(object["registration_request_b64url"], .string(SiteRootBrokerPresentationV2.encode(pending.preparedRegistration)))
        do {
            try await transport.submitV2(presentation: presentation, attemptID: attempt, storage: storage,
                                         nowMillis: { 1_900_000_000_000 })
            XCTFail("submitted attempt was sent twice")
        } catch { XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration) }
        XCTAssertEqual(GenesisBrokerURLProtocol.requests().count, 1)
        do {
            _ = try await transport.pollV2(presentation: presentation, attemptID: attempt, storage: storage)
            XCTFail("foreign delegation unexpectedly accepted")
        } catch { XCTAssertEqual(error as? PlatformFailure, .siteRootAuthorityUnavailable) }
        XCTAssertEqual(try storage.pending(attemptID: attempt), pending)
        let canonical = "{\"device_key_id\":\"\(key.deviceKeyID)\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\",\"site_trust_domain\":\"\(presentation.site)\"}"
        GenesisBrokerURLProtocol.delegationOverride = "{\"schema\":\"monas.site-root-genesis-registration-result.v1\",\"canonical_delegation_base64url\":\"\(SiteRootBrokerPresentationV2.encode(Data(canonical.utf8)))\",\"device_key_id\":\"\(key.deviceKeyID)\",\"site_trust_domain\":\"\(presentation.site)\",\"submit_url\":\"https://customer.example.test/auth/pistis/site-root-delegations/v1/submit\",\"reference\":\"\(presentation.reference)\"}"
        let delegation = try await transport.pollV2(presentation: presentation, attemptID: attempt, storage: storage)
        XCTAssertEqual(delegation.deviceKeyID, key.deviceKeyID)
        XCTAssertEqual(delegation.siteTrustDomain, presentation.site)
        XCTAssertEqual(try storage.pending(attemptID: attempt), pending)
    }
}

private struct ControlledBrokerRoot: BrokerV2SiteRootProducing {
    let registration: SiteRootKeyRegistrationV1
    func register() throws -> SiteRootKeyRegistrationV1 { registration }
    func prove(_ presentation: SiteRootDelegationPresentationV1) throws -> SiteRootDelegationSubmissionV1 {
        SiteRootDelegationSubmissionV1(schema: SiteRootDelegationSubmissionV1.schema,
            reference: presentation.reference, canonicalDelegationJSON: presentation.canonicalDelegationJSON,
            coseSign1: Data([1, 2, 3]), correlation: presentation.correlation)
    }
}

@MainActor private final class ControlledBrokerEventSink: OnboardingEventRecording {
    func append(_: OnboardingEvent) throws {}
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
