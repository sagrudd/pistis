import CryptoKit
import PistisCore
import XCTest

@testable import Pistis

final class BaseCampVaultSuccessorRotationV1Tests: XCTestCase {
    func testCheckedInSuccessorVectorIsExecutableByteForByte() throws {
        let fixture = try SuccessorFixture()
        let presentation = try fixture.presentation()
        let checkedIn = try baseCampVaultVector(named: "successor-vector.json")
        let expected = try XCTUnwrap(
            JSONSerialization.jsonObject(with: checkedIn) as? [String: Any]
        )
        XCTAssertEqual(expected["test_only"] as? Bool, true)
        let protected = try DetachedES256Cose.protectedHeaders(kid: fixture.deviceID)
        let signingInput = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: fixture.canonicalChallenge
        )
        let signature = try XCTUnwrap(
            Data(successorFixtureHex: try XCTUnwrap(expected["signature_raw_hex"] as? String))
        )
        let signingPublic = try P256.Signing.PublicKey(
            compressedRepresentation: fixture.deviceSigning.publicKey.compressedRepresentation
        )
        XCTAssertTrue(signingPublic.isValidSignature(
            try P256.Signing.ECDSASignature(rawRepresentation: signature),
            for: signingInput
        ))
        let submission = try fixture.produce(
            presentation, fixedSignature: signature, freshNonceByte: 0xb2
        )
        let presentationObject = try JSONSerialization.jsonObject(
            with: fixture.presentationJSON()
        )
        let submissionObject = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(try BaseCampVaultSuccessorSubmissionWireV1(submission))
        )
        let qrJSON = #"{"presentation_path":"/v1/pistis/basecamp-vault-unlock/presentation","purpose":"basecamp-vault-passphrase-delivery-v1","recipient":"mnemosyne-expedition-basecamp.service","schema":"monas.basecamp-vault-successor-rotation-qr.v1"}"#
        let presentationJSON = String(
            data: try JSONSerialization.data(withJSONObject: presentationObject, options: [.sortedKeys]),
            encoding: .utf8
        )!
        let submissionJSON = String(
            data: try JSONSerialization.data(withJSONObject: submissionObject, options: [.sortedKeys]),
            encoding: .utf8
        )!
        let object: [String: Any] = [
            "schema": "pistis.basecamp-vault-successor-test-vector.v1",
            "test_only": true,
            "device_private_scalar_hex": Data(repeating: 0x09, count: 32).successorHex,
            "device_public_sec1_hex": fixture.devicePublic.successorHex,
            "old_host_private_scalar_hex": Data(repeating: 0x02, count: 32).successorHex,
            "old_host_public_sec1_hex": fixture.oldHostPublic.successorHex,
            "fresh_host_private_scalar_hex": Data(repeating: 0x03, count: 32).successorHex,
            "fresh_host_public_sec1_hex": fixture.freshHostPublic.successorHex,
            "secret_hex": fixture.secret.successorHex,
            "old_nonce_hex": Data(repeating: 0xa2, count: 12).successorHex,
            "fresh_nonce_hex": Data(repeating: 0xb2, count: 12).successorHex,
            "canonical_challenge_hex": fixture.canonicalChallenge.successorHex,
            "signature_structure_hex": signingInput.successorHex,
            "signature_raw_hex": signature.successorHex,
            "old_ciphertext_hex": fixture.encryptedRecord.successorHex,
            "old_ciphertext_sha256_hex": fixture.recordDigest.successorHex,
            "current_binding_bytes_hex": fixture.bindingBytes.successorHex,
            "current_binding_sha256_hex": fixture.bindingDigest.successorHex,
            "detached_cose_sign1_hex": submission.coseSign1.successorHex,
            "rewrapped_ciphertext_hex": submission.rewrappedCiphertext.successorHex,
            "presentation": presentationObject,
            "submission": submissionObject,
            "qr_json": qrJSON,
            "presentation_json": presentationJSON,
            "submission_json": submissionJSON,
            "expected_submit_http_status": 204,
        ]
        let actual = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let normalizedExpected = try JSONSerialization.data(
            withJSONObject: expected, options: [.sortedKeys]
        )
        XCTAssertEqual(actual, normalizedExpected)
    }

    func testAcceptedAuthoritativeEighteenFieldVector() throws {
        let fixture = try SuccessorFixture()
        let value = try fixture.presentation()
        XCTAssertEqual(fixture.bindingBytes.count, 621)
        XCTAssertEqual(
            fixture.bindingDigest.successorHex,
            "5e394062c627247a1a843ff03004c17c0226dfc08901de8c371c64a3ecf39d30"
        )
        XCTAssertEqual(value.currentGeneration, "basecamp-vault-7")
        XCTAssertEqual(value.successorGeneration, "basecamp-vault-8")
        XCTAssertEqual(value.currentBindingDigest, fixture.bindingDigest)
        XCTAssertEqual(value.enrolledDevicePublicSEC1, fixture.devicePublic)
        XCTAssertEqual(value.review.currentGeneration, "basecamp-vault-7")
        XCTAssertEqual(value.review.successorGeneration, "basecamp-vault-8")
    }

    func testEveryTagPositionAndLengthIsClosed() throws {
        let fixture = try SuccessorFixture()
        XCTAssertEqual(fixture.fields.count, 18)
        for index in fixture.fields.indices {
            var tag = fixture.fields
            tag[index].tag += 1
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(tag)),
                "accepted changed tag \(index + 1)"
            )
            var empty = fixture.fields
            empty[index].value = Data()
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(empty)),
                "accepted empty field \(index + 1)"
            )
        }
    }

    func testEveryDuplicatedFixedOrTrustedFieldIsCrossBound() throws {
        let fixture = try SuccessorFixture()
        for index in fixture.fields.indices where index != 4 {
            var fields = fixture.fields
            fields[index].value[fields[index].value.startIndex] ^= 1
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(fields)),
                "accepted changed field \(index + 1)"
            )
        }
        var binding = fixture.fields
        binding[4].value[0] ^= 1
        let changed = try fixture.presentation(challenge: fixture.challenge(binding))
        XCTAssertNotEqual(changed.currentBindingDigest, fixture.bindingDigest)
    }

    func testGenerationRepeatGapLeadingZeroAndOverflowDeny() throws {
        let fixture = try SuccessorFixture()
        XCTAssertThrowsError(try fixture.withGenerations(current: 7, successor: "basecamp-vault-7"))
        XCTAssertThrowsError(try fixture.withGenerations(current: 7, successor: "basecamp-vault-9"))
        XCTAssertThrowsError(try fixture.withGenerationText(
            current: "basecamp-vault-07", successor: "basecamp-vault-8"
        ))
        XCTAssertThrowsError(try fixture.withGenerationText(
            current: "basecamp-vault-18446744073709551615",
            successor: "basecamp-vault-1"
        ))
        XCTAssertThrowsError(try fixture.withGenerationText(
            current: "basecamp-vault-0", successor: "basecamp-vault-1"
        ))
    }

    func testWrongLocalKeyRevocationCrossSiteAndFreshnessDeny() throws {
        let fixture = try SuccessorFixture()
        XCTAssertThrowsError(try fixture.presentation(expectedDevice: "site-root-foreign"))
        XCTAssertThrowsError(try fixture.presentation(expectedRevocation: 8))
        XCTAssertThrowsError(try fixture.presentation(expectedSite: "foreign-site"))
        XCTAssertThrowsError(try fixture.presentation(now: fixture.issuedAt - 1))
        XCTAssertThrowsError(try fixture.presentation(now: fixture.expiresAt))

        var site = fixture.fields
        site[0].value = Data("foreign-site".utf8)
        XCTAssertThrowsError(try fixture.presentation(challenge: fixture.challenge(site)))
    }

    func testGenericAndMigrationProfilesCannotDispatchAsSuccessor() throws {
        let fixture = try SuccessorFixture()
        for schema in [
            SecureEnclaveIphoneMediatedCustodyRewrapProducer.challengeSchema,
            BaseCampVaultMigrationProfileV1.challengeSchema,
        ] {
            var challenge = schema
            challenge.append(fixture.canonicalChallenge.dropFirst(
                BaseCampVaultSuccessorRotationProfileV1.challengeSchema.count
            ))
            XCTAssertThrowsError(try fixture.presentation(challenge: challenge))
        }
    }

    func testProducerOpensUnderNAndRewrapsUnderExactlyNPlusOne() throws {
        let fixture = try SuccessorFixture()
        let value = try fixture.presentation()
        let submission = try fixture.produce(value)
        XCTAssertEqual(submission.canonicalPayload, fixture.canonicalChallenge)
        XCTAssertEqual(submission.purpose, BaseCampVaultSuccessorRotationProfileV1.purpose)
        XCTAssertEqual(submission.rewrappedCiphertext.count, 60)

        let freshShared = try fixture.shared(
            privateKey: fixture.freshHostPrivate, peer: fixture.devicePublic
        )
        let freshAAD = fixture.aad(generation: "basecamp-vault-8", host: fixture.freshHostPublic)
        let freshKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: freshShared, aadDigest: freshAAD
        )
        XCTAssertEqual(
            try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
                submission.rewrappedCiphertext, key: freshKey, aadDigest: freshAAD
            ), fixture.secret
        )

        let oldAAD = fixture.aad(generation: "basecamp-vault-7", host: fixture.freshHostPublic)
        let oldKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: freshShared, aadDigest: oldAAD
        )
        XCTAssertThrowsError(try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
            submission.rewrappedCiphertext, key: oldKey, aadDigest: oldAAD
        ))
    }

    func testQRIsExactNonBearerFourFieldDescriptor() throws {
        let accepted = """
        {"presentation_path":"/v1/pistis/basecamp-vault-unlock/presentation","purpose":"basecamp-vault-passphrase-delivery-v1","recipient":"mnemosyne-expedition-basecamp.service","schema":"monas.basecamp-vault-successor-rotation-qr.v1"}
        """
        XCTAssertNoThrow(try BaseCampVaultSuccessorRotationQRV1(qrText: accepted))
        XCTAssertEqual(MonasJSONScanRoute.classify(accepted), .baseCampVaultSuccessorRotation)
        for changed in [
            accepted.replacingOccurrences(of: "basecamp-vault-unlock", with: "other"),
            String(accepted.dropLast()) + ",\"reference\":\"bearer\"}",
            accepted.replacingOccurrences(of: "successor-rotation", with: "migration"),
        ] {
            XCTAssertThrowsError(try BaseCampVaultSuccessorRotationQRV1(qrText: changed))
        }
    }

    func testStrictOuterPresentationAndSubmissionHaveExactThirteenAndEightFields() throws {
        let fixture = try SuccessorFixture()
        let json = try fixture.presentationJSON()
        let decoded = try BaseCampVaultSuccessorPresentationWireV1(
            data: json,
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        ).presentation
        XCTAssertEqual(decoded.canonicalChallenge, fixture.canonicalChallenge)

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: json) as? [String: Any]
        )
        object["extra"] = true
        XCTAssertThrowsError(try BaseCampVaultSuccessorPresentationWireV1(
            data: JSONSerialization.data(withJSONObject: object),
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        ))

        let wire = try BaseCampVaultSuccessorSubmissionWireV1(
            fixture.produce(try fixture.presentation())
        )
        let submission = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(wire)
        ) as? [String: Any]
        XCTAssertEqual(submission?.count, 9)
        XCTAssertEqual(
            Set(submission.map { Array($0.keys) } ?? []),
            [
                "schema", "correlation_b64url", "canonical_challenge_b64url",
                "device_key_id", "delegation_serial", "site_trust_domain", "purpose",
                "detached_cose_sign1_b64url", "rewrapped_ciphertext_b64url",
            ]
        )
    }

    func testSimulatorFullSuccessorQRGetValidateProduceAndPostFlow() async throws {
        let fixture = try SuccessorFixture()
        let vector = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: baseCampVaultVector(named: "successor-vector.json")
            ) as? [String: Any]
        )
        let qr = try XCTUnwrap(vector["qr_json"] as? String)
        let presentationJSON = Data(
            try XCTUnwrap(vector["presentation_json"] as? String).utf8
        )
        let expectedSubmissionJSON = Data(
            try XCTUnwrap(vector["submission_json"] as? String).utf8
        )
        let signature = try XCTUnwrap(Data(
            successorFixtureHex: try XCTUnwrap(vector["signature_raw_hex"] as? String)
        ))
        XCTAssertNoThrow(try BaseCampVaultSuccessorRotationQRV1(qrText: qr))

        BaseCampSimulatorURLProtocol.configure(
            presentationPath: BaseCampVaultSuccessorRotationRouteV1.presentationPath,
            presentation: presentationJSON
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BaseCampSimulatorURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test:8443")),
            expectedSPKISHA256: Data(repeating: 0x72, count: 32),
            configuration: configuration
        )
        let presentation = try await transport.fetchBaseCampVaultSuccessorRotationV1(
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        )
        let submission = try fixture.produce(
            presentation, fixedSignature: signature, freshNonceByte: 0xb2
        )
        try await transport.submitBaseCampVaultSuccessorRotationV1(submission)

        let requests = BaseCampSimulatorURLProtocol.requests()
        XCTAssertEqual(requests.map(\.httpMethod), ["GET", "POST"])
        XCTAssertEqual(
            requests.compactMap { $0.url?.path },
            [BaseCampVaultSuccessorRotationRouteV1.presentationPath,
             BaseCampVaultSuccessorRotationRouteV1.submissionPath]
        )
        let body = try XCTUnwrap(BaseCampSimulatorURLProtocol.bodies().last ?? nil)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        XCTAssertEqual(object.count, 9)
        XCTAssertEqual(
            object["schema"] as? String,
            BaseCampVaultSuccessorRotationRouteV1.submissionSchema
        )
        XCTAssertEqual(body, expectedSubmissionJSON)
    }

    func testSuccessorPresentationRequiresJSONContentType() async throws {
        let fixture = try SuccessorFixture()
        let presentationJSON = try fixture.presentationJSON()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BaseCampSimulatorURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test:8443")),
            expectedSPKISHA256: Data(repeating: 0x72, count: 32),
            configuration: configuration
        )

        BaseCampSimulatorURLProtocol.configure(
            presentationPath: BaseCampVaultSuccessorRotationRouteV1.presentationPath,
            presentation: presentationJSON,
            contentType: "text/plain"
        )
        do {
            _ = try await transport.fetchBaseCampVaultSuccessorRotationV1(
                expectedDeviceKeyID: fixture.deviceID,
                expectedRevocationGeneration: fixture.revocation,
                nowUnixSeconds: fixture.issuedAt + 1
            )
            XCTFail("accepted a non-JSON successor presentation")
        } catch {}

        BaseCampSimulatorURLProtocol.configure(
            presentationPath: BaseCampVaultSuccessorRotationRouteV1.presentationPath,
            presentation: presentationJSON,
            contentType: "application/json; charset=utf-8"
        )
        _ = try await transport.fetchBaseCampVaultSuccessorRotationV1(
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        )
    }

    @MainActor
    func testSuccessorLost204RetriesIdenticalBodyWithoutSecondApproval() async throws {
        let fixture = try SuccessorFixture()
        let vector = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: baseCampVaultVector(named: "successor-vector.json")
            ) as? [String: Any]
        )
        let qr = try XCTUnwrap(vector["qr_json"] as? String)
        let presentationJSON = Data(
            try XCTUnwrap(vector["presentation_json"] as? String).utf8
        )
        let expectedSubmissionJSON = Data(
            try XCTUnwrap(vector["submission_json"] as? String).utf8
        )
        let signature = try XCTUnwrap(Data(
            successorFixtureHex: try XCTUnwrap(vector["signature_raw_hex"] as? String)
        ))
        let presentation = try fixture.presentation()
        let approval = SuccessorApprovalStub(submission: try fixture.produce(
            presentation, fixedSignature: signature, freshNonceByte: 0xb2
        ))
        BaseCampSimulatorURLProtocol.configure(
            presentationPath: BaseCampVaultSuccessorRotationRouteV1.presentationPath,
            presentation: presentationJSON,
            transientSubmissionFailures: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BaseCampSimulatorURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test:8443")),
            expectedSPKISHA256: Data(repeating: 0x72, count: 32),
            configuration: configuration
        )
        let coordinator = BaseCampVaultSuccessorCoordinatorV1(
            transport: transport,
            trustStore: try SuccessorTrustStoreStub(
                revocation: fixture.revocation,
                installationPublic: fixture.devicePublic
            ),
            approval: approval,
            siteRootRegistration: SuccessorSiteRootRegistrationStub(
                value: SiteRootKeyRegistrationV1(
                    schema: SiteRootKeyRegistrationV1.schema,
                    deviceKeyID: fixture.deviceID,
                    publicKeyCompressedSEC1: fixture.devicePublic,
                    secureEnclaveAttestation: "not-asserted"
                )
            ),
            now: { Date(timeIntervalSince1970: TimeInterval(fixture.issuedAt + 1)) }
        )

        await coordinator.accept(qrText: qr)
        XCTAssertEqual(coordinator.phase, .review)
        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .completed)
        let approvalCalls = await approval.calls
        XCTAssertEqual(approvalCalls, 1)

        let requests = BaseCampSimulatorURLProtocol.requests()
        XCTAssertEqual(requests.map(\.httpMethod), ["GET", "POST", "POST"])
        XCTAssertEqual(requests[1].url, requests[2].url)
        let bodies = BaseCampSimulatorURLProtocol.bodies()
        XCTAssertEqual(bodies[1], expectedSubmissionJSON)
        XCTAssertEqual(bodies[2], expectedSubmissionJSON)
    }

    @MainActor
    func testSuccessorCoordinatorRequiresReviewAndLocalSiteRootBeforeApproval() async throws {
        let fixture = try SuccessorFixture()
        let presentation = try fixture.presentation()
        let transport = SuccessorTransportStub(presentation: presentation)
        let approval = SuccessorApprovalStub(submission: try fixture.produce(presentation))
        let trust = try SuccessorTrustStoreStub(
            revocation: fixture.revocation, installationPublic: fixture.devicePublic
        )
        let qr = """
        {"presentation_path":"/v1/pistis/basecamp-vault-unlock/presentation","purpose":"basecamp-vault-passphrase-delivery-v1","recipient":"mnemosyne-expedition-basecamp.service","schema":"monas.basecamp-vault-successor-rotation-qr.v1"}
        """

        let missing = BaseCampVaultSuccessorCoordinatorV1(
            transport: transport,
            trustStore: trust,
            approval: approval,
            siteRootRegistration: SuccessorSiteRootRegistrationStub(value: nil),
            now: { Date(timeIntervalSince1970: TimeInterval(fixture.issuedAt + 1)) }
        )
        await missing.accept(qrText: qr)
        XCTAssertEqual(missing.phase, .failed)
        var fetches = await transport.fetches
        var approvalCalls = await approval.calls
        XCTAssertEqual(fetches, 0)
        XCTAssertEqual(approvalCalls, 0)

        let coordinator = BaseCampVaultSuccessorCoordinatorV1(
            transport: transport,
            trustStore: trust,
            approval: approval,
            siteRootRegistration: SuccessorSiteRootRegistrationStub(
                value: SiteRootKeyRegistrationV1(
                    schema: SiteRootKeyRegistrationV1.schema,
                    deviceKeyID: fixture.deviceID,
                    publicKeyCompressedSEC1: fixture.devicePublic,
                    secureEnclaveAttestation: "not-asserted"
                )
            ),
            now: { Date(timeIntervalSince1970: TimeInterval(fixture.issuedAt + 1)) }
        )
        await coordinator.accept(qrText: qr)
        XCTAssertEqual(coordinator.phase, .review)
        XCTAssertNotNil(coordinator.presentedReview)
        approvalCalls = await approval.calls
        var submissions = await transport.submissions
        XCTAssertEqual(approvalCalls, 0)
        XCTAssertEqual(submissions, 0)

        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .completed)
        XCTAssertNil(coordinator.presentedReview)
        fetches = await transport.fetches
        approvalCalls = await approval.calls
        submissions = await transport.submissions
        XCTAssertEqual(fetches, 1)
        XCTAssertEqual(approvalCalls, 1)
        XCTAssertEqual(submissions, 1)
    }
}

private struct SuccessorFixture {
    struct Field { var tag: UInt8; var value: Data }

    let site = "site-fixture"
    let revocation: UInt64 = 7
    let correlation = Data(repeating: 0x71, count: 16)
    let delegation = "delegation-successor"
    let issuedAt: UInt64 = 1_000
    let expiresAt: UInt64 = 1_100
    let secret = Data(repeating: 0x31, count: 32)
    let deviceSigning: P256.Signing.PrivateKey
    let deviceAgreement: P256.KeyAgreement.PrivateKey
    let oldHostPrivate: P256.KeyAgreement.PrivateKey
    let freshHostPrivate: P256.KeyAgreement.PrivateKey
    let expectedPublic: Data
    let encryptedRecord: Data

    var devicePublic: Data { deviceAgreement.publicKey.compressedRepresentation }
    var oldHostPublic: Data { oldHostPrivate.publicKey.compressedRepresentation }
    var freshHostPublic: Data { freshHostPrivate.publicKey.compressedRepresentation }
    var deviceID: String {
        "site-root-" + Data(SHA256.hash(data: devicePublic)).successorHex
    }
    var recordDigest: Data { Data(SHA256.hash(data: encryptedRecord)) }
    var bindingBytes: Data {
        Data((
            "schema=thesaurophylax.iphone-custody-runtime-binding.v1\n"
                + "site_trust_domain_id=\(site)\n"
                + "key_generation=basecamp-vault-7\n"
                + "device_key_id=\(deviceID)\n"
                + "enrolled_device_public_sec1_hex=\(devicePublic.successorHex)\n"
                + "expected_ed25519_public_key_hex=\(expectedPublic.successorHex)\n"
                + "encrypted_record_sha256_hex=\(recordDigest.successorHex)\n"
                + "revocation_generation=\(revocation)\n"
                + "existing_host_public_sec1_hex=\(oldHostPublic.successorHex)\n"
        ).utf8)
    }
    var bindingDigest: Data { Data(SHA256.hash(data: bindingBytes)) }
    var canonicalChallenge: Data { challenge(fields) }

    var fields: [Field] {
        [
            .init(tag: 1, value: Data(site.utf8)),
            .init(tag: 2, value: Data("basecamp-vault-7".utf8)),
            .init(tag: 3, value: oldHostPublic),
            .init(tag: 4, value: recordDigest),
            .init(tag: 5, value: bindingDigest),
            .init(tag: 6, value: Data("basecamp-vault-8".utf8)),
            .init(tag: 7, value: Data(deviceID.utf8)),
            .init(tag: 8, value: devicePublic),
            .init(tag: 9, value: expectedPublic),
            .init(tag: 10, value: revocation.successorBigEndian),
            .init(tag: 11, value: correlation),
            .init(tag: 12, value: Data(delegation.utf8)),
            .init(tag: 13, value: issuedAt.successorBigEndian),
            .init(tag: 14, value: expiresAt.successorBigEndian),
            .init(tag: 15, value: freshHostPublic),
            .init(tag: 16, value: Data(BaseCampVaultSuccessorRotationProfileV1.purpose.utf8)),
            .init(tag: 17, value: Data(BaseCampVaultSuccessorRotationProfileV1.recipient.utf8)),
            .init(tag: 18, value: Data(BaseCampVaultSuccessorRotationProfileV1.credentialSocket.utf8)),
        ]
    }

    init() throws {
        let scalar = Data(repeating: 9, count: 32)
        deviceSigning = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        deviceAgreement = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        oldHostPrivate = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 2, count: 32)
        )
        freshHostPrivate = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 3, count: 32)
        )
        expectedPublic = try Curve25519.Signing.PrivateKey(
            rawRepresentation: secret
        ).publicKey.rawRepresentation
        let shared = try deviceAgreement.sharedSecretFromKeyAgreement(
            with: oldHostPrivate.publicKey
        ).withUnsafeBytes { Data($0) }
        let aad = Self.aad(
            site: site, generation: "basecamp-vault-7",
            device: "site-root-" + Data(SHA256.hash(data: deviceAgreement.publicKey.compressedRepresentation)).successorHex,
            host: oldHostPrivate.publicKey.compressedRepresentation
        )
        let key = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: shared, aadDigest: aad
        )
        let sealed = try AES.GCM.seal(
            secret,
            using: key,
            nonce: try AES.GCM.Nonce(data: Data(repeating: 0xa2, count: 12)),
            authenticating: aad
        )
        guard let combined = sealed.combined else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        encryptedRecord = combined
    }

    func challenge(_ fields: [Field]) -> Data {
        var result = BaseCampVaultSuccessorRotationProfileV1.challengeSchema
        for field in fields {
            result.append(field.tag)
            result.append(contentsOf: UInt16(field.value.count).successorBytes)
            result.append(field.value)
        }
        return result
    }

    func presentation(
        challenge: Data? = nil,
        expectedSite: String? = nil,
        expectedDevice: String? = nil,
        expectedRevocation: UInt64? = nil,
        now: UInt64? = nil,
        successor: String = "basecamp-vault-8"
    ) throws -> BaseCampVaultSuccessorRotationPresentationV1 {
        try BaseCampVaultSuccessorRotationPresentationV1(
            correlation: correlation,
            canonicalChallenge: challenge ?? canonicalChallenge,
            freshHostPublicSEC1: freshHostPublic,
            siteTrustDomain: site,
            successorGeneration: successor,
            deviceKeyID: deviceID,
            expectedEd25519PublicKey: expectedPublic,
            encryptedRecordDigest: recordDigest,
            currentRevocationGeneration: revocation,
            delegationSerial: delegation,
            expiresAtUnixSeconds: expiresAt,
            existingHostPublicSEC1: oldHostPublic,
            existingEncryptedRecord: encryptedRecord,
            expectedSiteTrustDomain: expectedSite ?? site,
            expectedDeviceKeyID: expectedDevice ?? deviceID,
            expectedRevocationGeneration: expectedRevocation ?? revocation,
            nowUnixSeconds: now ?? issuedAt + 1
        )
    }

    func withGenerations(current: UInt64, successor: String) throws
        -> BaseCampVaultSuccessorRotationPresentationV1
    {
        try withGenerationText(current: "basecamp-vault-\(current)", successor: successor)
    }

    func withGenerationText(current: String, successor: String) throws
        -> BaseCampVaultSuccessorRotationPresentationV1
    {
        var changed = fields
        changed[1].value = Data(current.utf8)
        changed[5].value = Data(successor.utf8)
        return try presentation(challenge: challenge(changed), successor: successor)
    }

    func aad(generation: String, host: Data) -> Data {
        Self.aad(site: site, generation: generation, device: deviceID, host: host)
    }

    static func aad(site: String, generation: String, device: String, host: Data) -> Data {
        var material = Data()
        for value in [
            Data(BaseCampVaultSuccessorRotationProfileV1.purpose.utf8), Data(site.utf8),
            Data(generation.utf8), Data(device.utf8), host,
        ] {
            material.append(contentsOf: UInt32(value.count).successorBytes)
            material.append(value)
        }
        return Data(SHA256.hash(data: material))
    }

    func shared(privateKey: P256.KeyAgreement.PrivateKey, peer: Data) throws -> Data {
        let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: peer)
        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).withUnsafeBytes {
            Data($0)
        }
    }

    func produce(
        _ value: BaseCampVaultSuccessorRotationPresentationV1,
        fixedSignature: Data? = nil,
        freshNonceByte: UInt8? = nil
    ) throws
        -> IphoneMediatedCustodyRewrapSubmissionV1
    {
        let protected = try DetachedES256Cose.protectedHeaders(kid: deviceID)
        let signingInput = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: value.canonicalChallenge
        )
        let signature = try fixedSignature ?? P256Format.rawSignature(
            fromStrictDER: deviceSigning.signature(for: signingInput).derRepresentation
        )
        return try BaseCampVaultSuccessorCryptographicCoreV1.produce(
            value,
            enrolledDevicePublicSEC1: devicePublic,
            sign: { input in
                XCTAssertEqual(input, signingInput)
                return signature
            },
            deriveSharedSecret: {
                let peer = try P256.KeyAgreement.PublicKey(compressedRepresentation: $0)
                return try deviceAgreement.sharedSecretFromKeyAgreement(with: peer)
                    .withUnsafeBytes { Data($0) }
            },
            seal: { plaintext, key, aad in
                guard let freshNonceByte else {
                    return try SecureEnclaveIphoneMediatedCustodyRewrapProducer.seal(
                        plaintext, key: key, aadDigest: aad
                    )
                }
                let sealed = try AES.GCM.seal(
                    plaintext,
                    using: key,
                    nonce: try AES.GCM.Nonce(
                        data: Data(repeating: freshNonceByte, count: 12)
                    ),
                    authenticating: aad
                )
                guard let combined = sealed.combined else {
                    throw PlatformFailure.custodyRewrapUnavailable
                }
                return combined
            }
        )
    }

    func presentationJSON() throws -> Data {
        let object: [String: Any] = [
            "schema": BaseCampVaultSuccessorRotationRouteV1.presentationSchema,
            "correlation_b64url": encode(correlation),
            "canonical_challenge_b64url": encode(canonicalChallenge),
            "fresh_host_public_sec1_b64url": encode(freshHostPublic),
            "site_trust_domain": site,
            "key_generation": "basecamp-vault-8",
            "device_key_id": deviceID,
            "expected_ed25519_public_key_b64url": encode(expectedPublic),
            "encrypted_record_digest_b64url": encode(recordDigest),
            "current_revocation_generation": revocation,
            "delegation_serial": delegation,
            "expires_at_unix_seconds": expiresAt,
            "existing_host_public_sec1_b64url": encode(oldHostPublic),
            "existing_encrypted_record_b64url": encode(encryptedRecord),
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func encode(_ value: Data) -> String {
        value.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

private extension Data {
    var successorHex: String { map { String(format: "%02x", $0) }.joined() }
}

private extension FixedWidthInteger {
    var successorBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
    var successorBigEndian: Data { Data(successorBytes) }
}

private final class SuccessorTrustStoreStub: InstallationTrustStoring, @unchecked Sendable {
    let output: AuthenticatedEnrollmentOutput

    init(revocation: UInt64, installationPublic: Data) throws {
        let user = Data(repeating: 4, count: 16)
        let external = Data(repeating: 5, count: 16)
        output = try AuthenticatedEnrollmentOutput(
            trust: InstallationTrustRecord(
                installationID: Data(repeating: 1, count: 16),
                displayName: "Base Camp successor fixture",
                audience: "pistis-login",
                authorisedProductAudiences: ["jenkins"],
                userID: user,
                externalIdentityID: external,
                fingerprint: Data(repeating: 6, count: 32),
                installationKeyID: Data(repeating: 7, count: 32),
                installationPublicKey: installationPublic,
                authorityKeyID: Data(repeating: 8, count: 32),
                authorityReceipt: Data([1]),
                policyGeneration: 1,
                revocationGeneration: revocation,
                expiresAt: Date(timeIntervalSince1970: 2_000),
                active: true
            ),
            responseContext: DeviceResponseContext(
                deviceID: Data(repeating: 9, count: 16),
                deviceKeyID: Data(repeating: 10, count: 32),
                userID: user,
                externalIdentityID: external
            ),
            allowedHosts: ["monas.example.test"],
            httpsOrigin: "https://monas.example.test:8443",
            tlsSPKISHA256: Data(repeating: 11, count: 32)
        )
    }

    func record(installationID: Data) throws -> InstallationTrustRecord? {
        installationID == output.trust.installationID ? output.trust : nil
    }
    func activeEnrollment() async throws -> AuthenticatedEnrollmentOutput? { output }
    func installAuthenticated(_: AuthenticatedEnrollmentOutput) async throws {}
    func revoke(installationID _: Data) async throws {}
}

private actor SuccessorTransportStub: BaseCampVaultSuccessorTransportingV1 {
    let presentation: BaseCampVaultSuccessorRotationPresentationV1
    private(set) var fetches = 0
    private(set) var submissions = 0

    init(presentation: BaseCampVaultSuccessorRotationPresentationV1) {
        self.presentation = presentation
    }

    func fetchBaseCampVaultSuccessorRotationV1(
        expectedDeviceKeyID: String,
        expectedRevocationGeneration: UInt64,
        nowUnixSeconds _: UInt64
    ) async throws -> BaseCampVaultSuccessorRotationPresentationV1 {
        guard expectedDeviceKeyID == presentation.deviceKeyID,
              expectedRevocationGeneration == presentation.currentRevocationGeneration
        else { throw PlatformFailure.custodyRewrapUnavailable }
        fetches += 1
        return presentation
    }

    func submitBaseCampVaultSuccessorRotationV1(
        _: IphoneMediatedCustodyRewrapSubmissionV1
    ) async throws { submissions += 1 }
}

private actor SuccessorApprovalStub: BaseCampVaultSuccessorApprovalExecutingV1 {
    let submission: IphoneMediatedCustodyRewrapSubmissionV1
    private(set) var calls = 0

    init(submission: IphoneMediatedCustodyRewrapSubmissionV1) {
        self.submission = submission
    }

    func approve(_: BaseCampVaultSuccessorRotationPresentationV1) async throws
        -> IphoneMediatedCustodyRewrapSubmissionV1
    {
        calls += 1
        return submission
    }
}

private struct SuccessorSiteRootRegistrationStub:
    BaseCampVaultSiteRootRegistrationReadingV1
{
    let value: SiteRootKeyRegistrationV1?
    func existingRegistration() throws -> SiteRootKeyRegistrationV1? { value }
}

private extension Data {
    init?(successorFixtureHex value: String) {
        guard value.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let end = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index ..< end], radix: 16) else { return nil }
            bytes.append(byte)
            index = end
        }
        self.init(bytes)
    }
}
