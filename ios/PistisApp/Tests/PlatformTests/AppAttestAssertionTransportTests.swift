import CryptoKit
import Foundation
import XCTest

@testable import Pistis

final class AppAttestAssertionTransportTests: XCTestCase {
    func testClientHashesExactPurposeSeparatedAssertionBytes() async throws {
        let keyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let service = RecordingAppAttestService(keyID: keyID)
        let client = AppleAppAttestClient(
            service: service,
            keyIDStore: FixedKeyIDStore(keyID: keyID)
        )
        let vector = try assertionVector()
        let bootstrap = try MonasAppAttestCeremonyBootstrap(
            httpsOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            tlsSPKISHA256: Data(repeating: 0x12, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challengeDigest: vector.challengeDigest
        )
        let envelope = try await client.prepareAssertion(bootstrap: bootstrap)

        XCTAssertEqual(
            AppleAppAttestClient.assertionClientDataPrefix + vector.challengeDigest,
            vector.clientData
        )
        XCTAssertEqual(service.assertionHash, vector.clientDataHash)
        XCTAssertEqual(
            envelope.ceremonyIDB64URL,
            Data(repeating: 0x22, count: 16).base64EncodedString()
                .replacingOccurrences(of: "=", with: "")
        )
        XCTAssertEqual(envelope.profile,
                       "mnemosyne.pistis.site-trust-app-attest-assertion-ingress.v1")
        XCTAssertFalse(envelope.assertionB64URL.contains("="))
    }

    func testRegistrationCanUseOnlyTheSealedServerClientDataHash() async throws {
        let keyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let service = RecordingAppAttestService(keyID: keyID)
        let client = AppleAppAttestClient(
            service: service,
            keyIDStore: FixedKeyIDStore(keyID: keyID)
        )
        let hash = Data(repeating: 0x5a, count: 32)

        let prepared = try await client.prepareRegistration(
            ceremonyID: "server-owned-registration-ceremony",
            siteTrustDomain: "site-demo-1",
            clientDataHash: hash
        )

        XCTAssertEqual(service.attestationHash, hash)
        XCTAssertEqual(prepared.envelope.clientDataHashB64URL, Self.base64URL(hash))
        do {
            _ = try await client.prepareRegistration(
                ceremonyID: "server-owned-registration-ceremony",
                siteTrustDomain: "site-demo-1",
                clientDataHash: Data(repeating: 0, count: 32)
            )
            XCTFail("zero client-data hash unexpectedly accepted")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput)
        }
    }

    func testPreparedRegistrationCannotReplaceTheAcceptedKeyBeforeAuthorityCommit() async throws {
        let staleKeyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let freshKeyID = Data(repeating: 0x22, count: 32).base64EncodedString()
        let service = RecordingAppAttestService(keyID: freshKeyID)
        let store = MutableKeyIDStore(keyID: staleKeyID)
        let client = AppleAppAttestClient(service: service, keyIDStore: store)

        let prepared = try await client.prepareRegistration(
            ceremonyID: "server-owned-registration-ceremony",
            siteTrustDomain: "site-demo-1",
            clientDataHash: Data(repeating: 0x5a, count: 32)
        )

        XCTAssertEqual(service.generatedKeyCount, 1)
        XCTAssertEqual(service.attestedKeyID, freshKeyID)
        XCTAssertEqual(store.keyID, staleKeyID)
        try client.commitAcceptedRegistration(prepared)
        XCTAssertEqual(store.keyID, freshKeyID)
    }

    func testFailedRegistrationDoesNotReplaceTheRetainedKey() async throws {
        let staleKeyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let replacementKeyID = Data(repeating: 0x22, count: 32).base64EncodedString()
        let service = FailingAttestationService(keyID: replacementKeyID)
        let store = MutableKeyIDStore(keyID: staleKeyID)
        let client = AppleAppAttestClient(service: service, keyIDStore: store)

        do {
            _ = try await client.prepareRegistration(
                ceremonyID: "server-owned-registration-ceremony",
                siteTrustDomain: "site-demo-1",
                clientDataHash: Data(repeating: 0x5a, count: 32)
            )
            XCTFail("failed Apple attestation unexpectedly produced a registration")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .appAttestAttestationFailed)
        }

        XCTAssertEqual(service.generatedKeyCount, 1)
        XCTAssertEqual(store.keyID, staleKeyID)
    }

    func testRawAppAttestAssertionErrorMapsToTheAssertionStage() async throws {
        let keyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let client = AppleAppAttestClient(
            service: FailingAttestationService(keyID: keyID),
            keyIDStore: FixedKeyIDStore(keyID: keyID)
        )

        do {
            _ = try await client.prepareAssertion(bootstrap: try bootstrap())
            XCTFail("raw App Attest assertion error unexpectedly succeeded")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .appAttestAssertionFailed)
        }
    }

    func testRelocationAssertionUsesExactRegisteredKeyAndServerCompatibleHash() async throws {
        let key = Data(repeating: 0x11, count: 32)
        let keyID = key.base64EncodedString()
        let service = RecordingAppAttestService(keyID: keyID)
        let client = AppleAppAttestClient(
            service: service, keyIDStore: FixedKeyIDStore(keyID: keyID)
        )
        let hash = Data(repeating: 0x44, count: 32)
        _ = try await client.prepareSiteOriginRelocationAssertion(
            ceremonyID: Data(repeating: 0x22, count: 16),
            expectedKeyID: key, clientDataHash: hash
        )
        XCTAssertEqual(service.assertionHash, hash)
        do {
            _ = try await client.prepareSiteOriginRelocationAssertion(
                ceremonyID: Data(repeating: 0x22, count: 16),
                expectedKeyID: Data(repeating: 0x12, count: 32), clientDataHash: hash
            )
            XCTFail("substituted App Attest key unexpectedly accepted")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .appAttestUnavailable)
        }
    }

    func testAssertionEnvelopeRejectsZeroOrOversizedInputs() {
        XCTAssertThrowsError(try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 0, count: 16), assertion: Data([1])
        ))
        XCTAssertThrowsError(try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 1, count: 15), assertion: Data([1])
        ))
        XCTAssertThrowsError(try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 1, count: 16),
            assertion: Data(repeating: 2, count: 16_385)
        ))
    }

    func testTransportPostsOnlyExactCanonicalAssertionEnvelope() async throws {
        AssertionURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        let envelope = try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 0x22, count: 16),
            assertion: Data(repeating: 0x44, count: 64)
        )
        try await transport.submitAssertion(envelope)

        let request = try XCTUnwrap(AssertionURLProtocol.lastRequest())
        XCTAssertEqual(request.url?.absoluteString,
                       "https://monas.example.test/v1/pistis/site-trust/app-attest/assertion")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"),
                       "application/json; charset=utf-8")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"), nil)
        let body = try XCTUnwrap(AssertionURLProtocol.lastBody())
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        XCTAssertEqual(Set(object.keys), ["profile", "ceremony_id_b64url", "assertion_b64url"])
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
    }

    func testRotationFetchUsesFreshServerHashThenArmsOnlyThroughExactAssertionIngress() async throws {
        AssertionURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        let challenge = try await transport.fetchCustodyRotationAssertionChallengeV2(
            nowUnixSeconds: 150
        )
        let fetch = try XCTUnwrap(AssertionURLProtocol.lastRequest())
        XCTAssertEqual(fetch.httpMethod, "GET")
        XCTAssertEqual(fetch.url?.path,
                       "/v1/pistis/site-trust/authority-custody-rotation/v2/assertion-challenge")
        XCTAssertNil(fetch.value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(fetch.value(forHTTPHeaderField: "Authorization"))

        let keyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let service = RecordingAppAttestService(keyID: keyID)
        let client = AppleAppAttestClient(
            service: service, keyIDStore: FixedKeyIDStore(keyID: keyID)
        )
        let prepared = try await client.prepareCustodyRotationAssertion(challenge: challenge)
        XCTAssertEqual(service.assertionHash, Data(repeating: 0x33, count: 32))
        XCTAssertFalse(prepared.restoredRegisteredKeyReference)
        try await transport.submitAssertion(prepared.envelope)
        let post = try XCTUnwrap(AssertionURLProtocol.lastRequest())
        XCTAssertEqual(post.httpMethod, "POST")
        XCTAssertEqual(post.url?.path, "/v1/pistis/site-trust/app-attest/assertion")
        XCTAssertNil(post.value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(post.value(forHTTPHeaderField: "Authorization"))
    }

    func testPendingCustodyAssertionUsesOnlyBoundBKeyAndPreservesLegacyA() async throws {
        let bKey = Data(repeating: 0x11, count: 32).base64EncodedString()
        let aKey = Data(repeating: 0x22, count: 32).base64EncodedString()
        let legacy = MutableKeyIDStore(keyID: aKey)
        let service = RecordingAppAttestService(keyID: bKey)
        let client = AppleAppAttestClient(service: service, keyIDStore: legacy)
        let storage = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let attemptID = UUID()
        let pending = ScopedAppAttestPending(
            attemptID: attemptID, correlation: Data(repeating: 0x44, count: 32),
            registrationReference: "reference-b", siteClaim: "site-demo",
            appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environmentClaim: "Production", keyID: bKey, preparedRegistration: Data([1])
        )
        try storage.stage(pending)
        XCTAssertNil(try storage.submittedAttempt(attemptID: attemptID))
        try storage.markSubmitted(attemptID: attemptID)
        XCTAssertNotNil(try storage.submittedAttempt(attemptID: attemptID))
        let challenge = try CustodyRotationAppAttestChallengeV2(
            data: AssertionURLProtocol.challengeData(expires: 200), nowUnixSeconds: 150
        )
        do {
            _ = try await client.preparePendingCustodyRotationAssertion(
                challenge: challenge, storage: storage, attemptID: attemptID,
                verifiedInstallationID: Data(repeating: 2, count: 16)
            )
            XCTFail("cross-installation challenge was accepted")
        } catch { XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput) }
        XCTAssertNil(service.assertedKeyID)
        for (field, value) in [
            ("site_trust_domain", "other-site"),
            ("key_id_b64url", Data(repeating: 0x33, count: 32).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")),
        ] {
            var object = try XCTUnwrap(JSONSerialization.jsonObject(
                with: AssertionURLProtocol.challengeData(expires: 200)
            ) as? [String: Any])
            object[field] = value
            let swapped = try CustodyRotationAppAttestChallengeV2(
                data: JSONSerialization.data(withJSONObject: object), nowUnixSeconds: 150
            )
            do {
                _ = try await client.preparePendingCustodyRotationAssertion(
                    challenge: swapped, storage: storage, attemptID: attemptID,
                    verifiedInstallationID: Data(repeating: 1, count: 16)
                )
                XCTFail("cross-site or cross-key challenge was accepted")
            } catch { XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput) }
            XCTAssertNil(service.assertedKeyID)
        }
        _ = try await client.preparePendingCustodyRotationAssertion(
            challenge: challenge, storage: storage, attemptID: attemptID,
            verifiedInstallationID: Data(repeating: 1, count: 16)
        )
        XCTAssertEqual(service.assertedKeyID, bKey)
        XCTAssertEqual(legacy.keyID, aKey)
        XCTAssertNil(try storage.binding(installationID: Data(repeating: 1, count: 16)))
        try storage.resetAll()
        do {
            _ = try await client.preparePendingCustodyRotationAssertion(
                challenge: challenge, storage: storage, attemptID: attemptID,
                verifiedInstallationID: Data(repeating: 1, count: 16)
            )
            XCTFail("reset attempt unexpectedly remained usable")
        } catch { XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput) }
        XCTAssertEqual(legacy.keyID, aKey)
        XCTAssertEqual(legacy.readCount, 0)
        XCTAssertEqual(legacy.writeCount, 0)
    }

    func testPendingStatusAssertionIsPurposeBoundAndNeverTouchesLegacy() async throws {
        let bKey = Data(repeating: 0x11, count: 32).base64EncodedString()
        let legacy = MutableKeyIDStore(keyID: Data(repeating: 0x22, count: 32).base64EncodedString())
        let service = RecordingAppAttestService(keyID: bKey)
        let client = AppleAppAttestClient(service: service, keyIDStore: legacy)
        let storage = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let id = try XCTUnwrap(UUID(uuidString: "01020304-0506-0708-090A-0B0C0D0E0F10"))
        let pending = ScopedAppAttestPending(attemptID: id, correlation: Data(32...63),
            registrationReference: "genesis-reference-1", siteClaim: "site-6073349b-e7f6-420f-ba7c-586b6d9ad78e",
            appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environmentClaim: "Production", keyID: bKey, preparedRegistration: Data([1]))
        try storage.stage(pending); try storage.markSubmitted(attemptID: id)
        let status = FirstDeviceStatusTranscriptV2(
            nonce: Data(96...127), operationID: Data(1...16),
            correlationDigest: Data([0xf8,0x46,0xc9,0x78,0xde,0xdf,0x75,0xc3,0x07,0x9b,0x33,0x6f,0x7b,0xae,0xc0,0xce,0x62,0xed,0xb2,0x94,0x00,0x27,0xcc,0x25,0x1c,0xd0,0x63,0x28,0x50,0xee,0x23,0xcd]),
            reference: pending.registrationReference, installationID: Data(160...175), site: pending.siteClaim,
            presentationDigest: Data(176...207), receiptDigest: Data(208...239),
            tlsSPKIDigest: Data(repeating: 0x10, count: 32), appAttestKeyID: Data(repeating: 0x11, count: 32),
            siteRootKeyDigest: Data(repeating: 0x12, count: 32), deviceKeyDigest: Data(repeating: 0x13, count: 32),
            expiry: 1_900_000_060)
        do {
            _ = try await client.preparePendingFirstDeviceStatusAssertion(
                transcript: status, storage: storage, attemptID: id,
                verifiedInstallationID: Data(repeating: 9, count: 16), issuedAt: 1_900_000_000, now: 1_900_000_001)
            XCTFail("cross-installation status unexpectedly signed")
        } catch { XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput) }
        do {
            _ = try await client.preparePendingFirstDeviceStatusAssertion(
                transcript: status, storage: storage, attemptID: id,
                verifiedInstallationID: status.installationID, issuedAt: 1_900_000_000, now: status.expiry)
            XCTFail("expired status unexpectedly signed")
        } catch { XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput) }
        XCTAssertNil(service.assertedKeyID)
        let swappedCorrelation = FirstDeviceStatusTranscriptV2(
            nonce: status.nonce, operationID: status.operationID,
            correlationDigest: Data(repeating: 0x55, count: 32), reference: status.reference,
            installationID: status.installationID, site: status.site,
            presentationDigest: status.presentationDigest, receiptDigest: status.receiptDigest,
            tlsSPKIDigest: status.tlsSPKIDigest, appAttestKeyID: status.appAttestKeyID,
            siteRootKeyDigest: status.siteRootKeyDigest, deviceKeyDigest: status.deviceKeyDigest, expiry: status.expiry)
        do {
            _ = try await client.preparePendingFirstDeviceStatusAssertion(
                transcript: swappedCorrelation, storage: storage, attemptID: id,
                verifiedInstallationID: status.installationID, issuedAt: 1_900_000_000, now: 1_900_000_001)
            XCTFail("cross-operation correlation unexpectedly signed")
        } catch { XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput) }
        XCTAssertNil(service.assertedKeyID)
        let developmentStore = ScopedAppAttestStore(persistence: ScopedMemoryPersistence())
        let development = ScopedAppAttestPending(attemptID: id, correlation: pending.correlation,
            registrationReference: pending.registrationReference, siteClaim: pending.siteClaim,
            appClaim: pending.appClaim, environmentClaim: "Development", keyID: bKey,
            preparedRegistration: Data([1]))
        try developmentStore.stage(development); try developmentStore.markSubmitted(attemptID: id)
        do {
            _ = try await client.preparePendingFirstDeviceStatusAssertion(
                transcript: status, storage: developmentStore, attemptID: id,
                verifiedInstallationID: status.installationID, issuedAt: 1_900_000_000, now: 1_900_000_001)
            XCTFail("development App Attest key unexpectedly used for production status")
        } catch { XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput) }
        XCTAssertNil(service.assertedKeyID)
        _ = try await client.preparePendingFirstDeviceStatusAssertion(
            transcript: status, storage: storage, attemptID: id,
            verifiedInstallationID: status.installationID, issuedAt: 1_900_000_000, now: 1_900_000_001)
        XCTAssertEqual(service.assertedKeyID, bKey)
        XCTAssertEqual(service.assertionHash, try status.clientDataHash())
        XCTAssertEqual(legacy.readCount, 0); XCTAssertEqual(legacy.writeCount, 0)
    }

    func testCustodyAssertionRestoresOnlyTheAppleProvenServerKeyReference() async throws {
        AssertionURLProtocol.reset()
        let serverKeyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let unacceptedRetryKeyID = Data(repeating: 0x22, count: 32).base64EncodedString()
        let store = MutableKeyIDStore(keyID: unacceptedRetryKeyID)
        let service = RecordingAppAttestService(keyID: serverKeyID)
        let client = AppleAppAttestClient(service: service, keyIDStore: store)
        let challenge = try CustodyRotationAppAttestChallengeV2(
            data: AssertionURLProtocol.challengeData(expires: 200),
            nowUnixSeconds: 150
        )

        let prepared = try await client.prepareCustodyRotationAssertion(challenge: challenge)

        XCTAssertEqual(service.assertedKeyID, serverKeyID)
        XCTAssertEqual(store.keyID, serverKeyID)
        XCTAssertTrue(prepared.restoredRegisteredKeyReference)
    }

    func testBoundCustodyAssertionUsesOnlyMatchingInstallationKey() async throws {
        let bKey = Data(repeating: 0x11, count: 32).base64EncodedString()
        let legacy = MutableKeyIDStore(keyID: Data(repeating: 0x22, count: 32).base64EncodedString())
        let service = RecordingAppAttestService(keyID: bKey)
        let client = AppleAppAttestClient(service: service, keyIDStore: legacy)
        let challenge = try CustodyRotationAppAttestChallengeV2(data: AssertionURLProtocol.challengeData(expires: 200), nowUnixSeconds: 150)
        let binding = ScopedAppAttestBinding(attemptID: UUID(), installationID: Data(repeating: 1, count: 16),
            site: "site-demo", appIdentifier: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environment: "Production", keyID: bKey, policyGeneration: 1, revocationGeneration: 1)
        let wrong = ScopedAppAttestBinding(attemptID: binding.attemptID, installationID: Data(repeating: 2, count: 16),
            site: binding.site, appIdentifier: binding.appIdentifier, environment: binding.environment,
            keyID: binding.keyID, policyGeneration: 1, revocationGeneration: 1)
        do {
            _ = try await client.prepareBoundCustodyRotationAssertion(challenge: challenge, binding: wrong)
            XCTFail("cross-installation assertion unexpectedly accepted")
        } catch { XCTAssertEqual(error as? PlatformFailure, .appAttestInvalidInput) }
        XCTAssertNil(service.assertedKeyID)
        _ = try await client.prepareBoundCustodyRotationAssertion(challenge: challenge, binding: binding)
        XCTAssertEqual(service.assertedKeyID, bKey)
        XCTAssertEqual(legacy.readCount, 0); XCTAssertEqual(legacy.writeCount, 0)
    }

    func testUnavailableServerRegisteredKeyDoesNotChangeTheLocalReference() async throws {
        let unacceptedRetryKeyID = Data(repeating: 0x22, count: 32).base64EncodedString()
        let store = MutableKeyIDStore(keyID: unacceptedRetryKeyID)
        let client = AppleAppAttestClient(
            service: FailingAttestationService(keyID: unacceptedRetryKeyID),
            keyIDStore: store
        )
        let challenge = try CustodyRotationAppAttestChallengeV2(
            data: AssertionURLProtocol.challengeData(expires: 200),
            nowUnixSeconds: 150
        )

        do {
            _ = try await client.prepareCustodyRotationAssertion(challenge: challenge)
            XCTFail("an unavailable server-registered Apple key unexpectedly recovered")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .appAttestAssertionFailed)
        }
        XCTAssertEqual(store.keyID, unacceptedRetryKeyID)
    }

    func testRotationChallengeRetainsAuthorityBindingFields() throws {
        let challenge = try CustodyRotationAppAttestChallengeV2(
            data: AssertionURLProtocol.challengeData(expires: 200), nowUnixSeconds: 150
        )
        XCTAssertEqual(challenge.installationID, Data(repeating: 1, count: 16))
        XCTAssertEqual(challenge.siteTrustDomain, "site-demo")
        let app = AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier
        let installation = Data(repeating: 1, count: 16)
        let key = Data(repeating: 0x11, count: 32)
        XCTAssertEqual(challenge.appIdentifier, app)
        XCTAssertTrue(challenge.matchesBinding(
            installationID: installation, siteTrustDomain: "site-demo", appIdentifier: app, keyID: key
        ))
        XCTAssertFalse(challenge.matchesBinding(
            installationID: Data(repeating: 2, count: 16), siteTrustDomain: "site-demo", appIdentifier: app, keyID: key
        ))
        XCTAssertFalse(challenge.matchesBinding(
            installationID: installation, siteTrustDomain: "other-site", appIdentifier: app, keyID: key
        ))
        XCTAssertFalse(challenge.matchesBinding(
            installationID: installation, siteTrustDomain: "site-demo", appIdentifier: "other.app", keyID: key
        ))
        XCTAssertFalse(challenge.matchesBinding(
            installationID: installation, siteTrustDomain: "site-demo", appIdentifier: app,
            keyID: Data(repeating: 0x12, count: 32)
        ))
    }

    func testRotationChallengeRejectsReplayWindowMismatchAndUnknownFields() throws {
        XCTAssertThrowsError(try CustodyRotationAppAttestChallengeV2(
            data: AssertionURLProtocol.challengeData(expires: 150), nowUnixSeconds: 150
        ))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(
            with: AssertionURLProtocol.challengeData(expires: 200)
        ) as? [String: Any])
        object["device_id"] = "invented"
        XCTAssertThrowsError(try CustodyRotationAppAttestChallengeV2(
            data: JSONSerialization.data(withJSONObject: object), nowUnixSeconds: 150
        ))
    }

    func testRegistrationUsesItsDistinctPinnedJSONEndpoint() async throws {
        AssertionURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        let envelope = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: "server-owned-registration-ceremony",
            siteTrustDomain: "site-trust.example",
            appleKeyID: Data(repeating: 0x11, count: 32).base64EncodedString(),
            clientDataHash: Data(repeating: 0x22, count: 32),
            attestationObject: Data(repeating: 0x33, count: 64)
        )
        try await transport.submitRegistration(envelope)
        let request = try XCTUnwrap(AssertionURLProtocol.lastRequest())
        XCTAssertEqual(request.url?.absoluteString,
                       "https://monas.example.test/v1/pistis/site-trust/app-attest/registration")
        let body = try XCTUnwrap(AssertionURLProtocol.lastBody())
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        XCTAssertEqual(Set(object.keys), [
            "protocol", "ceremony_id", "site_trust_domain", "app_identifier",
            "key_id_b64url", "client_data_hash_b64url", "attestation_object_b64url",
        ])
    }

    func testCustodyRewrapUsesOnlyItsFixedPinnedSubmissionEndpoint() async throws {
        AssertionURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        try await transport.submitCustodyRewrap(IphoneMediatedCustodyRewrapSubmissionV1(
            correlation: Data(repeating: 0x01, count: 16),
            canonicalPayload: Data(repeating: 0x02, count: 64),
            deviceKeyID: "site-root-1",
            delegationSerial: "serial-1",
            siteTrustDomain: "site-1",
            purpose: IphoneMediatedCustodyRewrapPurposeV1.value,
            coseSign1: Data(repeating: 0x03, count: 64),
            rewrappedCiphertext: Data(repeating: 0x04, count: 60)
        ))

        let request = try XCTUnwrap(AssertionURLProtocol.lastRequest())
        XCTAssertEqual(request.url?.absoluteString,
                       "https://monas.example.test/v1/pistis/site-trust/custody-rewrap/submit")
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        let body = try XCTUnwrap(AssertionURLProtocol.lastBody())
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(Set(object.keys), [
            "schema", "correlation_b64url", "canonical_challenge_b64url", "device_key_id",
            "delegation_serial", "site_trust_domain", "purpose", "detached_cose_sign1_b64url",
            "rewrapped_ciphertext_b64url",
        ])
    }

    func testTransportRejectsRedirectOrNonAcceptedResponse() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RejectingAssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        let envelope = try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 0x22, count: 16), assertion: Data([1])
        )
        do {
            try await transport.submitAssertion(envelope)
            XCTFail("non-202 response must not be accepted")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .productionEnvelopeUnavailable)
        }
    }

    private func bootstrap() throws -> MonasAppAttestCeremonyBootstrap {
        try MonasAppAttestCeremonyBootstrap(
            httpsOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            tlsSPKISHA256: Data(repeating: 0x12, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challengeDigest: Data(repeating: 0x33, count: 32)
        )
    }

    private func assertionVector() throws -> (
        challengeDigest: Data, clientData: Data, clientDataHash: Data
    ) {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../../../../fixtures/app-attest/site-trust-assertion-client-data-v1.json")
            .standardizedFileURL
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: root)) as? [String: String]
        )
        return (
            try decodeCanonicalB64URL(object["challenge_digest_b64url"]),
            try decodeCanonicalB64URL(object["client_data_b64url"]),
            try decodeCanonicalB64URL(object["client_data_sha256_b64url"])
        )
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private func decodeCanonicalB64URL(_ value: String?) throws -> Data {
    let value = try XCTUnwrap(value)
    XCTAssertFalse(value.contains("="))
    XCTAssertTrue(value.unicodeScalars.allSatisfy {
        $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_")
    })
    let padded = value.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
        + String(repeating: "=", count: (4 - value.count % 4) % 4)
    return try XCTUnwrap(Data(base64Encoded: padded))
}

private final class FixedKeyIDStore: AppleAppAttestKeyIDStoring, @unchecked Sendable {
    let keyID: String
    init(keyID: String) { self.keyID = keyID }
    func loadKeyID() -> String? { keyID }
    func saveKeyID(_: String) throws {}
}

private final class MutableKeyIDStore: AppleAppAttestKeyIDStoring, @unchecked Sendable {
    var keyID: String?
    private(set) var readCount = 0
    private(set) var writeCount = 0

    init(keyID: String?) { self.keyID = keyID }

    func loadKeyID() -> String? { readCount += 1; return keyID }
    func saveKeyID(_ keyID: String) throws { writeCount += 1; self.keyID = keyID }
}

private final class RecordingAppAttestService: AppleAppAttestServicing, @unchecked Sendable {
    let keyID: String
    private(set) var generatedKeyCount = 0
    private(set) var attestedKeyID: String?
    private(set) var assertedKeyID: String?
    private(set) var attestationHash: Data?
    private(set) var assertionHash: Data?
    init(keyID: String) { self.keyID = keyID }
    var isSupported: Bool { true }
    func generateKey() async throws -> String {
        generatedKeyCount += 1
        return keyID
    }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        attestedKeyID = keyID
        attestationHash = clientDataHash
        return Data([1])
    }
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        assertedKeyID = keyID
        assertionHash = clientDataHash
        return Data(repeating: 0x44, count: 64)
    }
}

private final class FailingAttestationService: AppleAppAttestServicing, @unchecked Sendable {
    let keyID: String
    private(set) var generatedKeyCount = 0

    init(keyID: String) { self.keyID = keyID }
    var isSupported: Bool { true }

    func generateKey() async throws -> String {
        generatedKeyCount += 1
        return keyID
    }

    func attestKey(_: String, clientDataHash _: Data) async throws -> Data {
        throw NSError(domain: "DCError", code: 2)
    }

    func generateAssertion(_: String, clientDataHash _: Data) async throws -> Data {
        throw NSError(domain: "DCError", code: 3)
    }
}

private final class AssertionURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var requestValue: URLRequest?
    private nonisolated(unsafe) static var bodyValue: Data?

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.requestValue = request
        Self.bodyValue = request.httpBody ?? readBodyStream(request.httpBodyStream)
        Self.lock.unlock()
        let isChallenge = request.url?.path.hasSuffix("/assertion-challenge") == true
        let response = HTTPURLResponse(
            url: request.url!, statusCode: isChallenge ? 200 : 202, httpVersion: "HTTP/1.1",
            headerFields: ["Cache-Control": "no-store"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if isChallenge {
            client?.urlProtocol(self, didLoad: Self.challengeData(expires: 200))
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func lastRequest() -> URLRequest? {
        lock.lock(); defer { lock.unlock() }
        return requestValue
    }

    static func lastBody() -> Data? {
        lock.lock(); defer { lock.unlock() }
        return bodyValue
    }

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        requestValue = nil
        bodyValue = nil
    }

    static func challengeData(expires: UInt64) -> Data {
        func b64(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return try! JSONSerialization.data(withJSONObject: [
            "schema": "monas.first-authority-custody-app-attest-challenge.v2",
            "installation_id_b64url": b64(Data(repeating: 1, count: 16)),
            "site_trust_domain": "site-demo",
            "ceremony_id_b64url": b64(Data(repeating: 2, count: 16)),
            "client_data_hash_b64url": b64(Data(repeating: 0x33, count: 32)),
            "app_identifier": "C7A6NQTSY4.org.mnemosynebiosciences.pistis",
            "key_id_b64url": b64(Data(repeating: 0x11, count: 32)),
            "issued_at_unix_seconds": 100,
            "expires_at_unix_seconds": expires,
        ])
    }
}

private final class RejectingAssertionURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!, statusCode: 302, httpVersion: "HTTP/1.1",
            headerFields: ["Location": "https://redirect.invalid/"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private func readBodyStream(_ stream: InputStream?) -> Data {
    guard let stream else { return Data() }
    stream.open()
    defer { stream.close() }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while stream.hasBytesAvailable {
        let count = stream.read(&buffer, maxLength: buffer.count)
        guard count > 0 else { break }
        data.append(buffer, count: count)
    }
    return data
}
