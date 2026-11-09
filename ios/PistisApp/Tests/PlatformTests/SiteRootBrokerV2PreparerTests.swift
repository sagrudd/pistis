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

        // Join the same operation to a production PXLA continuation and a
        // fixed native challenge, using explicitly controlled peers/signers.
        let attempt = try storage.reserveBrokerAttempt(presentation)
        let pending = try XCTUnwrap(storage.pending(attemptID: attempt))
        let siteUUID = String(presentation.site.dropFirst(5))
        let siteBytes = try XCTUnwrap(SiteRootConvergenceEncoding.uuidBytes(siteUUID))
        let leafURL = url.deletingLastPathComponent().appendingPathComponent("leaf-v2-ipv4.json")
        var wrapper = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: leafURL)) as? [String: Any])
        var nested = try XCTUnwrap(wrapper["presentation"] as? [String: Any])
        var canonicalLeaf = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(nested["canonical_payload_b64"] as? String)))
        canonicalLeaf.replaceSubrange(11..<27, with: siteBytes)
        nested["canonical_payload_b64"] = canonicalLeaf.base64EncodedString()
        wrapper["presentation"] = nested
        var uuid = attempt.uuid
        let operation = withUnsafeBytes(of: &uuid) { Data($0) }
        let digest = Data(SHA256.hash(data: Data("mnemosyne.monas.first-device.correlation.v2\0".utf8) + pending.correlation))
        wrapper["operation_id_b64url"] = SiteRootBrokerPresentationV2.encode(operation)
        wrapper["correlation_digest_b64url"] = SiteRootBrokerPresentationV2.encode(digest)
        let leafData = try JSONSerialization.data(withJSONObject: wrapper)
        let continuation = ControlledV2Continuation(leaf: leafData)
        let authorizer = ControlledV2Authorizer(pending: pending, storage: storage, expectedSite: siteBytes)
        let convergence = SiteRootConvergenceServiceV2(transport: RecordingBrokerTransport(recorder: BrokerAttemptRecorder()))
        try await convergence.continueBrokerSiteX509(correlation: pending.correlation, expectedSiteUUID: siteUUID,
                                                     transport: continuation, authorizer: authorizer)
        XCTAssertNotNil(try storage.provisionalLeaf(attemptID: attempt))
        AssertionURLProtocol.reset()
        AssertionURLProtocol.challengeSite = pending.siteClaim
        AssertionURLProtocol.challengeKeyByte = 0x22
        defer { AssertionURLProtocol.reset() }
        let nativeConfiguration = URLSessionConfiguration.ephemeral
        nativeConfiguration.protocolClasses = [AssertionURLProtocol.self]
        let native = try MonasAppAttestTransport(authorityOrigin: XCTUnwrap(URL(string: "https://10.0.2.15:8443")),
            expectedSPKISHA256: Data(repeating: 10, count: 32), configuration: nativeConfiguration)
        let device = try ControlledCustodySigner()
        let recovery = ControlledRecoveryStore()
        let custody = SecureEnclaveFirstAuthorityCustodyProducerV2(testSigner: device, store: recovery)
        let commitment = try custody.prepareInitialRotation()
        let hostKey = P256.KeyAgreement.PrivateKey()
        let identity = try FirstAuthorityCustodyIdentityV2(siteTrustDomain: pending.siteClaim,
            custodyGeneration: "generation-v2", deviceKeyID: commitment.deviceKeyID,
            enrolledDevicePublicSEC1: commitment.enrolledDevicePublicSEC1,
            recoverySeedEd25519PublicKey: commitment.recoverySeedEd25519PublicKey, revocationGeneration: 1)
        let rotation = FirstAuthorityRotationPresentationV2(correlation: Data(repeating: 1, count: 16), identity: identity,
            hostEphemeralPublicSEC1: hostKey.publicKey.compressedRepresentation,
            legacyRecordSHA256: Data(repeating: 4, count: 32), installationBindingSHA256: Data(repeating: 5, count: 32),
            appAttestAcceptanceSHA256: Data(repeating: 6, count: 32), siteRootProofSHA256: Data(repeating: 7, count: 32),
            delegationSerial: "delegation-v2", expiresAtUnixSeconds: 200)
        let encode = SiteRootBrokerPresentationV2.encode
        let begin: [String: Any] = ["schema": FirstAuthorityCustodyRotationV2Wire.presentationSchema,
            "purpose": FirstAuthorityCustodyPurposeV2.rotation, "correlation_b64url": encode(rotation.correlation),
            "canonical_transcript_b64url": encode(try rotation.canonicalTranscript()), "site_trust_domain_id": identity.siteTrustDomain,
            "custody_generation": identity.custodyGeneration, "device_key_id": identity.deviceKeyID,
            "enrolled_device_public_sec1_b64url": encode(identity.enrolledDevicePublicSEC1),
            "recovery_seed_ed25519_public_key_b64url": encode(identity.recoverySeedEd25519PublicKey), "revocation_generation": 1,
            "host_ephemeral_public_sec1_b64url": encode(rotation.hostEphemeralPublicSEC1),
            "legacy_record_sha256_b64url": encode(rotation.legacyRecordSHA256),
            "installation_binding_sha256_b64url": encode(rotation.installationBindingSHA256),
            "app_attest_acceptance_sha256_b64url": encode(rotation.appAttestAcceptanceSHA256),
            "site_root_proof_sha256_b64url": encode(rotation.siteRootProofSHA256),
            "delegation_serial": rotation.delegationSerial, "expires_at_unix_seconds": 200]
        AssertionURLProtocol.rotationBeginResponse = try JSONSerialization.data(withJSONObject: begin)
        AssertionURLProtocol.rotationCompleteResponse = try JSONSerialization.data(withJSONObject: [
            "schema": FirstAuthorityCustodyRotationV2Wire.acceptedSchema, "correlation_b64url": encode(rotation.correlation),
            "authority_descriptor_b64url": encode(Data(repeating: 9, count: 64))])
        try await convergence.testOnlyDriveProvisionalCustody(pending, storage: storage, native: native,
            appAttest: AppleAppAttestClient(service: service, keyIDStore: legacy), producer: custody, now: { 150 })
        let sent = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(AssertionURLProtocol.lastBody())) as? [String: Any])
        let cipherText = try XCTUnwrap(sent["rewrapped_seed_ciphertext_b64url"] as? String)
        let cipher = try XCTUnwrap(SiteRootBrokerPresentationV2.base64(cipherText, exact: 60))
        let shared = try hostKey.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(compressedRepresentation: commitment.enrolledDevicePublicSEC1))
        let aad = Data(SHA256.hash(data: try rotation.canonicalTranscript()))
        let wrapKey = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: aad,
            sharedInfo: SecureEnclaveFirstAuthorityCustodyProducerV2.hostEnvelopeInfo, outputByteCount: 32)
        let recoveredSeed = try SecureEnclaveFirstAuthorityCustodyProducerV2.open(cipher, key: wrapKey, aad: aad)
        XCTAssertEqual(try Curve25519.Signing.PrivateKey(rawRepresentation: recoveredSeed).publicKey.rawRepresentation,
                       commitment.recoverySeedEd25519PublicKey)
        XCTAssertThrowsError(try storage.requireFreshCustodyStep("assertion", pending: pending))
        XCTAssertThrowsError(try storage.requireFreshCustodyStep("begin", pending: pending))
        XCTAssertThrowsError(try storage.requireFreshCustodyStep("complete", pending: pending))
        XCTAssertEqual(legacy.reads, 0); XCTAssertEqual(legacy.writes, 0)
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
    func testLegacyGlobalWriteExcludesV2ReservationAndReset() throws {
        let storage = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        try storage.beginLegacyGlobalWrite()
        XCTAssertThrowsError(try storage.reserveBrokerAttempt(fixture()))
        XCTAssertThrowsError(try ScopedAppAttestStore.beginLocalReset())
        storage.endLegacyGlobalWrite()
        _ = try storage.reserveBrokerAttempt(fixture())
        XCTAssertThrowsError(try storage.beginLegacyGlobalWrite())
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

private struct ControlledV2Continuation: MonasSiteX509BrokerContinuing {
    let leaf: Data
    func awaitSiteX509Continuation(correlation _: Data, phase: SiteX509BrokerContinuationPhaseV1) async throws -> SiteX509BrokerContinuationPresentationV1? {
        let data = phase == .leafApproval ? leaf : Data([1])
        return SiteX509BrokerContinuationPresentationV1(payload: data, sha256: Data(SHA256.hash(data: data)))
    }
    func submitSiteX509Continuation(correlation _: Data, phase _: SiteX509BrokerContinuationPhaseV1,
                                    presentationSHA256 _: Data, submission _: Data) async throws {}
}

private final class ControlledV2Authorizer: SiteX509BrokerContinuationAuthorizingV2, @unchecked Sendable {
    let pending: ScopedAppAttestPending
    let storage: ScopedAppAttestStore
    let expectedSite: Data
    init(pending: ScopedAppAttestPending, storage: ScopedAppAttestStore, expectedSite: Data) {
        self.pending = pending; self.storage = storage; self.expectedSite = expectedSite
    }
    func attendedUnlock(_: Data, role _: SiteX509AttendedUnlockRoleV2) throws -> Data { Data([1]) }
    func prepareAckRegistration(expectedSiteUUID _: String) throws {}
    func ackRegistration(_: Data) throws -> Data { Data([1]) }
    func leafApproval(_ data: Data) throws -> Data {
        var uuid = pending.attemptID.uuid
        let operation = withUnsafeBytes(of: &uuid) { Data($0) }
        let digest = Data(SHA256.hash(data: Data("mnemosyne.monas.first-device.correlation.v2\0".utf8) + pending.correlation))
        _ = try SiteX509LeafHandoffV2(data: data, operationID: operation, correlationDigest: digest,
            expectedSiteUUID: expectedSite, nowUnixSeconds: 1_900_000_000)
        try storage.stageProvisionalLeaf(ProvisionalLeafHandoff(attemptID: pending.attemptID,
            wrapper: data, verifiedAtSeconds: 1_900_000_000), pending: pending)
        return Data([1])
    }
}

private final class ControlledRecoveryStore: FirstAuthorityRecoveryEnvelopeStoring, @unchecked Sendable {
    private var value: Data?
    func load() throws -> Data? { value }
    func insert(_ envelope: Data) throws {
        guard value == nil else { throw PlatformFailure.invalidConfiguration }; value = envelope
    }
}

private struct ControlledCustodySigner: FirstAuthorityCustodyKeyOperations {
    let signing: P256.Signing.PrivateKey
    let agreement: P256.KeyAgreement.PrivateKey
    init() throws {
        signing = P256.Signing.PrivateKey()
        agreement = try P256.KeyAgreement.PrivateKey(rawRepresentation: signing.rawRepresentation)
    }
    func create() throws -> DevicePublicKey { try publicKey() }
    func publicKey() throws -> DevicePublicKey {
        DevicePublicKey(compressedSEC1: signing.publicKey.compressedRepresentation, assurance: .secureEnclaveFaceIDCurrentSet)
    }
    func sign(message: Data) throws -> Data {
        try P256Format.rawSignature(fromStrictDER: signing.signature(for: message).derRepresentation)
    }
    func deriveECDHSharedSecret(peerPublicCompressedSEC1: Data) throws -> Data {
        let shared = try agreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(compressedRepresentation: peerPublicCompressedSEC1))
        return shared.withUnsafeBytes { Data($0) }
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
    func generateAssertion(_: String, clientDataHash _: Data) async throws -> Data { Data(repeating: 0x44, count: 64) }
}
