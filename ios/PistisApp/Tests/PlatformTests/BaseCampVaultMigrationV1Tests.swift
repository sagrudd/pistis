import CryptoKit
import PistisCore
import XCTest

@testable import Pistis

final class BaseCampVaultMigrationV1Tests: XCTestCase {
    func testCheckedInMigrationVectorIsExecutableByteForByte() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()
        let checkedIn = try baseCampVaultVector(named: "migration-vector.json")
        let expected = try XCTUnwrap(
            JSONSerialization.jsonObject(with: checkedIn) as? [String: Any]
        )
        XCTAssertEqual(expected["test_only"] as? Bool, true)
        let protected = try DetachedES256Cose.protectedHeaders(kid: fixture.deviceID)
        let signingInput = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: fixture.canonicalChallenge
        )
        let signature = try XCTUnwrap(
            Data(baseCampFixtureHex: try XCTUnwrap(expected["signature_raw_hex"] as? String))
        )
        let signingPublic = try P256.Signing.PublicKey(
            compressedRepresentation: fixture.deviceSigning.publicKey.compressedRepresentation
        )
        XCTAssertTrue(signingPublic.isValidSignature(
            try P256.Signing.ECDSASignature(rawRepresentation: signature),
            for: signingInput
        ))
        let submission = try fixture.produce(
            presentation, fixedSignature: signature, freshNonceByte: 0xb1
        )
        let presentationObject = try JSONSerialization.jsonObject(
            with: fixture.presentationJSON()
        )
        let submissionObject = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(try BaseCampVaultMigrationSubmissionWireV1(submission))
        )
        let qrJSON = #"{"presentation_path":"/v1/pistis/basecamp-vault-migration/presentation","purpose":"basecamp-vault-passphrase-delivery-v1","recipient":"mnemosyne-expedition-basecamp.service","schema":"monas.basecamp-vault-migration-qr.v1"}"#
        let presentationJSON = String(
            data: try JSONSerialization.data(withJSONObject: presentationObject, options: [.sortedKeys]),
            encoding: .utf8
        )!
        let submissionJSON = String(
            data: try JSONSerialization.data(withJSONObject: submissionObject, options: [.sortedKeys]),
            encoding: .utf8
        )!
        let object: [String: Any] = [
            "schema": "pistis.basecamp-vault-migration-test-vector.v1",
            "test_only": true,
            "device_private_scalar_hex": Data(repeating: 0x09, count: 32).hexadecimal,
            "device_public_sec1_hex": fixture.devicePublic.hexadecimal,
            "old_host_private_scalar_hex": Data(repeating: 0x02, count: 32).hexadecimal,
            "old_host_public_sec1_hex": fixture.oldHostPublic.hexadecimal,
            "fresh_host_private_scalar_hex": Data(repeating: 0x03, count: 32).hexadecimal,
            "fresh_host_public_sec1_hex": fixture.freshHostPublic.hexadecimal,
            "secret_hex": fixture.secret.hexadecimal,
            "old_nonce_hex": Data(repeating: 0xa1, count: 12).hexadecimal,
            "fresh_nonce_hex": Data(repeating: 0xb1, count: 12).hexadecimal,
            "canonical_challenge_hex": fixture.canonicalChallenge.hexadecimal,
            "signature_structure_hex": signingInput.hexadecimal,
            "signature_raw_hex": signature.hexadecimal,
            "old_ciphertext_hex": fixture.encryptedRecord.hexadecimal,
            "old_ciphertext_sha256_hex": fixture.recordDigest.hexadecimal,
            "detached_cose_sign1_hex": submission.coseSign1.hexadecimal,
            "rewrapped_ciphertext_hex": submission.rewrappedCiphertext.hexadecimal,
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

    func testCrossProductFixturePinsBothCompleteRouteContracts() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0 ..< 4 { root.deleteLastPathComponent() }
        let data = try Data(
            contentsOf: root.appendingPathComponent(
                "fixtures/basecamp-vault-v1/contract.json"
            )
        )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        XCTAssertEqual(
            object["schema"] as? String,
            "pistis.basecamp-vault-cross-product-contract.v1"
        )
        XCTAssertEqual(object["purpose"] as? String, BaseCampVaultMigrationProfileV1.purpose)
        XCTAssertEqual(
            object["recipient"] as? String, BaseCampVaultMigrationProfileV1.recipient
        )
        XCTAssertEqual(
            object["credential_socket"] as? String,
            BaseCampVaultMigrationProfileV1.credentialSocket
        )
        XCTAssertEqual((object["presentation_fields"] as? [String])?.count, 13)
        XCTAssertEqual((object["submission_fields"] as? [String])?.count, 8)

        let migration = try XCTUnwrap(object["migration"] as? [String: Any])
        let migrationQR = try XCTUnwrap(migration["qr"] as? [String: Any])
        XCTAssertEqual(migrationQR.count, 4)
        XCTAssertEqual(
            migration["canonical_challenge_prefix"] as? String,
            "thesaurophylax.basecamp-vault-custody-provisioning.v1\\0"
        )
        XCTAssertEqual((migration["ordered_tags"] as? [String])?.count, 19)
        XCTAssertNoThrow(try BaseCampVaultMigrationQRV1(
            qrText: String(
                data: try JSONSerialization.data(
                    withJSONObject: migrationQR, options: [.sortedKeys]
                ),
                encoding: .utf8
            )!
        ))

        let successor = try XCTUnwrap(object["successor"] as? [String: Any])
        let successorQR = try XCTUnwrap(successor["qr"] as? [String: Any])
        XCTAssertEqual(successorQR.count, 4)
        XCTAssertEqual(
            successor["canonical_challenge_prefix"] as? String,
            "thesaurophylax.basecamp-vault-successor-rotation.v1\\0"
        )
        XCTAssertEqual((successor["ordered_tags"] as? [String])?.count, 18)
        XCTAssertNoThrow(try BaseCampVaultSuccessorRotationQRV1(
            qrText: String(
                data: try JSONSerialization.data(
                    withJSONObject: successorQR, options: [.sortedKeys]
                ),
                encoding: .utf8
            )!
        ))

        let migrationVector = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: baseCampVaultVector(named: "migration-vector.json")
            ) as? [String: Any]
        )
        let successorVector = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: baseCampVaultVector(named: "successor-vector.json")
            ) as? [String: Any]
        )
        let migrationQRText = try XCTUnwrap(migrationVector["qr_json"] as? String)
        let successorQRText = try XCTUnwrap(successorVector["qr_json"] as? String)
        XCTAssertNoThrow(try BaseCampVaultMigrationQRV1(qrText: migrationQRText))
        XCTAssertNoThrow(try BaseCampVaultSuccessorRotationQRV1(qrText: successorQRText))
        XCTAssertThrowsError(try BaseCampVaultSuccessorRotationQRV1(qrText: migrationQRText))
        XCTAssertThrowsError(try BaseCampVaultMigrationQRV1(qrText: successorQRText))

        XCTAssertThrowsError(try BaseCampVaultMigrationQRV1(
            qrText: migrationQRText.replacingOccurrences(
                of: BaseCampVaultMigrationRouteV1.presentationPath,
                with: BaseCampVaultSuccessorRotationRouteV1.presentationPath
            )
        ))
        XCTAssertThrowsError(try BaseCampVaultSuccessorRotationQRV1(
            qrText: successorQRText.replacingOccurrences(
                of: BaseCampVaultSuccessorRotationRouteV1.presentationPath,
                with: BaseCampVaultMigrationRouteV1.presentationPath
            )
        ))

        let migrationPresentation = Data(
            try XCTUnwrap(migrationVector["presentation_json"] as? String).utf8
        )
        let successorPresentation = Data(
            try XCTUnwrap(successorVector["presentation_json"] as? String).utf8
        )
        let deviceID = try XCTUnwrap(
            (migrationVector["presentation"] as? [String: Any])?["device_key_id"] as? String
        )
        XCTAssertThrowsError(try BaseCampVaultSuccessorPresentationWireV1(
            data: migrationPresentation,
            expectedDeviceKeyID: deviceID,
            expectedRevocationGeneration: 7,
            nowUnixSeconds: 1_001
        ))
        XCTAssertThrowsError(try BaseCampVaultMigrationPresentationWireV1(
            data: successorPresentation,
            expectedDeviceKeyID: deviceID,
            expectedRevocationGeneration: 7,
            nowUnixSeconds: 1_001
        ))
    }

    func testAcceptedNineteenFieldMigrationVectorAndReview() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()

        XCTAssertEqual(
            fixture.sourceDigest.hexadecimal,
            "a080d0c9b88f8faad5f8238a64a2ae39a758d45147fb19f219af7ffc22180849"
        )

        XCTAssertEqual(presentation.correlation, fixture.correlation)
        XCTAssertEqual(presentation.enrolledDevicePublicSEC1, fixture.devicePublic)
        XCTAssertEqual(presentation.vaultDigest, fixture.vaultDigest)
        XCTAssertEqual(presentation.sourceDigest, fixture.sourceDigest)
        XCTAssertEqual(presentation.inventoryDigest, fixture.inventoryDigest)
        XCTAssertEqual(presentation.issuedAtUnixSeconds, fixture.issuedAt)
        XCTAssertEqual(
            presentation.review,
            BaseCampVaultMigrationReviewV1(
                operation: "Migrate the existing Base Camp vault credential",
                siteTrustDomain: fixture.site,
                purpose: "basecamp-vault-passphrase-delivery-v1",
                recipient: "mnemosyne-expedition-basecamp.service",
                custodyGeneration: fixture.generation,
                deviceKeyID: fixture.deviceID,
                expiresAtUnixSeconds: fixture.expiresAt
            )
        )
    }

    func testEveryTagPositionAndEveryFieldLengthAreCanonical() throws {
        let fixture = try Fixture()
        let fields = fixture.fields
        XCTAssertEqual(fields.count, 19)

        for index in fields.indices {
            var wrongTag = fields
            wrongTag[index].tag = wrongTag[index].tag == 255 ? 254 : wrongTag[index].tag + 1
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(wrongTag)),
                "accepted wrong tag at field \(index + 1)"
            )

            var empty = fields
            empty[index].value = Data()
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(empty)),
                "accepted empty field \(index + 1)"
            )
        }
    }

    func testSchemaTrailingOversizeAndAlternativeProfilesDeny() throws {
        let fixture = try Fixture()
        var trailing = fixture.canonicalChallenge
        trailing.append(0)
        XCTAssertThrowsError(try fixture.presentation(challenge: trailing))

        var generic = Data("thesaurophylax.iphone-mediated-custody-rewrap.v1\0".utf8)
        generic.append(fixture.canonicalChallenge.dropFirst(
            BaseCampVaultMigrationProfileV1.challengeSchema.count
        ))
        XCTAssertThrowsError(try fixture.presentation(challenge: generic))

        var receipt = Data("thesaurophylax.site-root-bundle-receipt-rewrap.v1\0".utf8)
        receipt.append(fixture.canonicalChallenge.dropFirst(
            BaseCampVaultMigrationProfileV1.challengeSchema.count
        ))
        XCTAssertThrowsError(try fixture.presentation(challenge: receipt))
        XCTAssertThrowsError(try fixture.presentation(
            challenge: Data(repeating: 1, count: 4_097)
        ))
    }

    func testEveryDuplicatedOrFixedCanonicalValueIsCrossBound() throws {
        let fixture = try Fixture()
        for index in fixture.fields.indices {
            // The three source-evidence digests occur only in the signed
            // challenge; Pistis displays them as server-observed evidence but
            // has no independent local value against which to compare them.
            if [6, 7, 8].contains(index) { continue }
            var mutated = fixture.fields
            mutated[index].value[mutated[index].value.startIndex] ^= 1
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(mutated)),
                "accepted changed canonical field \(index + 1)"
            )
        }
    }

    func testTrustedContextCarriageAndFreshnessDriftDeny() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try fixture.presentation(expectedSite: "foreign-site"))
        XCTAssertThrowsError(try fixture.presentation(expectedDevice: "site-root-foreign"))
        XCTAssertThrowsError(try fixture.presentation(expectedRevocation: 8))
        XCTAssertThrowsError(try fixture.presentation(now: fixture.issuedAt - 1))
        XCTAssertThrowsError(try fixture.presentation(now: fixture.expiresAt))

        XCTAssertThrowsError(try fixture.presentation(correlation: Data(repeating: 4, count: 16)))
        XCTAssertThrowsError(try fixture.presentation(site: "foreign-site"))
        XCTAssertThrowsError(try fixture.presentation(generation: "basecamp-vault-2"))
        XCTAssertThrowsError(try fixture.presentation(deviceID: "site-root-foreign"))
        XCTAssertThrowsError(try fixture.presentation(revocation: 8))
        XCTAssertThrowsError(try fixture.presentation(delegation: "delegation-foreign"))
        XCTAssertThrowsError(try fixture.presentation(expiresAt: fixture.expiresAt - 1))
        XCTAssertThrowsError(try fixture.presentation(expectedPublic: Data(repeating: 8, count: 32)))
        XCTAssertThrowsError(try fixture.presentation(recordDigest: Data(repeating: 8, count: 32)))
        XCTAssertThrowsError(try fixture.presentation(existingHost: fixture.freshHostPublic))
        XCTAssertThrowsError(try fixture.presentation(freshHost: fixture.oldHostPublic))
    }

    func testLifetimeP256DigestAndDeviceIdentityRulesDeny() throws {
        var fixture = try Fixture()
        fixture.expiresAt = fixture.issuedAt + 601
        XCTAssertThrowsError(try fixture.presentation())

        fixture = try Fixture()
        var fields = fixture.fields
        fields[6].value = Data(repeating: 0, count: 32)
        XCTAssertThrowsError(try fixture.presentation(challenge: fixture.challenge(fields)))

        fields = fixture.fields
        fields[3].value[0] = 4
        XCTAssertThrowsError(try fixture.presentation(challenge: fixture.challenge(fields)))

        fields = fixture.fields
        fields[18].value = fixture.oldHostPublic
        XCTAssertThrowsError(
            try fixture.presentation(
                challenge: fixture.challenge(fields), freshHost: fixture.oldHostPublic
            )
        )

        fields = fixture.fields
        fields[3].value = fixture.otherDevicePublic
        XCTAssertThrowsError(try fixture.presentation(challenge: fixture.challenge(fields)))
    }

    func testPurposeBoundAADMatchesIndependentEncodingAndNotGenericAAD() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()
        let actual = BaseCampVaultMigrationCryptographicCoreV1.aad(
            presentation, hostPublicSEC1: fixture.oldHostPublic
        )
        XCTAssertEqual(actual, fixture.purposeAAD(host: fixture.oldHostPublic))
        XCTAssertNotEqual(
            actual,
            SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapAADDigest(
                siteTrustDomain: fixture.site,
                keyGeneration: fixture.generation,
                deviceKeyID: fixture.deviceID,
                hostEphemeralPublicSEC1: fixture.oldHostPublic
            )
        )
    }

    func testSimulatorProducerEmitsExactEightFieldSubmissionAndRewrapsSecret() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()
        let submission = try fixture.produce(presentation)

        XCTAssertEqual(submission.correlation, fixture.correlation)
        XCTAssertEqual(submission.canonicalPayload, fixture.canonicalChallenge)
        XCTAssertEqual(submission.deviceKeyID, fixture.deviceID)
        XCTAssertEqual(submission.delegationSerial, fixture.delegation)
        XCTAssertEqual(submission.siteTrustDomain, fixture.site)
        XCTAssertEqual(submission.purpose, BaseCampVaultMigrationProfileV1.purpose)
        XCTAssertFalse(submission.coseSign1.isEmpty)
        XCTAssertEqual(submission.rewrappedCiphertext.count, 60)

        let freshShared = try fixture.deviceAgreement.sharedSecretFromKeyAgreement(
            with: fixture.freshHostPrivate.publicKey
        ).withUnsafeBytes { Data($0) }
        let aad = fixture.purposeAAD(host: fixture.freshHostPublic)
        let key = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: freshShared, aadDigest: aad
        )
        XCTAssertEqual(
            try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
                submission.rewrappedCiphertext, key: key, aadDigest: aad
            ),
            fixture.secret
        )
    }

    func testSimulatorProducerDeniesForeignDeviceAndPayloadIntegrityDrift() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()
        XCTAssertThrowsError(try BaseCampVaultMigrationCryptographicCoreV1.produce(
            presentation,
            enrolledDevicePublicSEC1: fixture.otherDevicePublic,
            sign: { _ in Data(repeating: 1, count: 64) },
            deriveSharedSecret: { try fixture.shared(with: $0) }
        ))

        let wrong = try Fixture(secretByte: 0x31, expectedSecretByte: 0x32)
        XCTAssertThrowsError(try wrong.produce(try wrong.presentation()))
    }

    func testMigrationQRIsExactNonBearerFourFieldDescriptor() throws {
        let accepted = """
        {"presentation_path":"/v1/pistis/basecamp-vault-migration/presentation","purpose":"basecamp-vault-passphrase-delivery-v1","recipient":"mnemosyne-expedition-basecamp.service","schema":"monas.basecamp-vault-migration-qr.v1"}
        """
        XCTAssertNoThrow(try BaseCampVaultMigrationQRV1(qrText: accepted))
        XCTAssertEqual(MonasJSONScanRoute.classify(accepted), .baseCampVaultMigration)
        for changed in [
            accepted.replacingOccurrences(of: "basecamp-vault-migration/presentation", with: "other"),
            String(accepted.dropLast()) + ",\"capability\":\"bearer\"}",
            accepted.replacingOccurrences(of: "basecamp-vault-migration-qr", with: "basecamp-vault-successor-rotation-qr"),
        ] {
            XCTAssertThrowsError(try BaseCampVaultMigrationQRV1(qrText: changed))
        }
    }

    func testStrictMigrationOuterCrossBindsPinnedSiteDeviceAndRevocation() throws {
        let fixture = try Fixture()
        let json = try fixture.presentationJSON()
        XCTAssertNoThrow(try BaseCampVaultMigrationPresentationWireV1(
            data: json,
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        ))
        XCTAssertThrowsError(try BaseCampVaultMigrationPresentationWireV1(
            data: json,
            expectedDeviceKeyID: "site-root-foreign",
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        ))
        XCTAssertThrowsError(try BaseCampVaultMigrationPresentationWireV1(
            data: json,
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation + 1,
            nowUnixSeconds: fixture.issuedAt + 1
        ))

        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        object["site_trust_domain"] = "foreign-site"
        XCTAssertThrowsError(try BaseCampVaultMigrationPresentationWireV1(
            data: JSONSerialization.data(withJSONObject: object),
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        ))
        object = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        var challenge = fixture.canonicalChallenge
        let siteOffset = BaseCampVaultMigrationProfileV1.challengeSchema.count + 3
        challenge[siteOffset] ^= 1
        object["canonical_challenge_b64url"] = challenge.baseCampFixtureBase64URL
        XCTAssertThrowsError(try BaseCampVaultMigrationPresentationWireV1(
            data: JSONSerialization.data(withJSONObject: object),
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        ))
        object = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        object["extra"] = true
        XCTAssertThrowsError(try BaseCampVaultMigrationPresentationWireV1(
            data: JSONSerialization.data(withJSONObject: object),
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        ))
    }

    func testSimulatorFullMigrationQRGetValidateProduceAndPostFlow() async throws {
        let fixture = try Fixture()
        let vector = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: baseCampVaultVector(named: "migration-vector.json")
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
            baseCampFixtureHex: try XCTUnwrap(vector["signature_raw_hex"] as? String)
        ))
        XCTAssertNoThrow(try BaseCampVaultMigrationQRV1(qrText: qr))

        BaseCampSimulatorURLProtocol.configure(
            presentationPath: BaseCampVaultMigrationRouteV1.presentationPath,
            presentation: presentationJSON
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BaseCampSimulatorURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test:8443")),
            expectedSPKISHA256: Data(repeating: 0x71, count: 32),
            configuration: configuration
        )
        let presentation = try await transport.fetchBaseCampVaultMigrationV1(
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        )
        let submission = try fixture.produce(
            presentation, fixedSignature: signature, freshNonceByte: 0xb1
        )
        try await transport.submitBaseCampVaultMigrationV1(submission)

        let requests = BaseCampSimulatorURLProtocol.requests()
        XCTAssertEqual(requests.map(\.httpMethod), ["GET", "POST"])
        XCTAssertEqual(
            requests.compactMap { $0.url?.path },
            [BaseCampVaultMigrationRouteV1.presentationPath,
             BaseCampVaultMigrationRouteV1.submissionPath]
        )
        XCTAssertTrue(requests.allSatisfy {
            $0.value(forHTTPHeaderField: "Authorization") == nil
                && $0.value(forHTTPHeaderField: "Cookie") == nil
        })
        let body = try XCTUnwrap(BaseCampSimulatorURLProtocol.bodies().last ?? nil)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        XCTAssertEqual(object.count, 9)
        XCTAssertEqual(
            object["schema"] as? String,
            BaseCampVaultMigrationRouteV1.submissionSchema
        )
        XCTAssertEqual(body, expectedSubmissionJSON)

        XCTAssertThrowsError(try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test:8443")),
            expectedSPKISHA256: Data(),
            configuration: configuration
        ))
        XCTAssertThrowsError(try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "http://monas.example.test:8443")),
            expectedSPKISHA256: Data(repeating: 0x71, count: 32),
            configuration: configuration
        ))
    }

    func testMigrationPresentationRequiresJSONContentType() async throws {
        let fixture = try Fixture()
        let presentationJSON = try fixture.presentationJSON()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BaseCampSimulatorURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test:8443")),
            expectedSPKISHA256: Data(repeating: 0x71, count: 32),
            configuration: configuration
        )

        BaseCampSimulatorURLProtocol.configure(
            presentationPath: BaseCampVaultMigrationRouteV1.presentationPath,
            presentation: presentationJSON,
            contentType: "text/plain"
        )
        do {
            _ = try await transport.fetchBaseCampVaultMigrationV1(
                expectedDeviceKeyID: fixture.deviceID,
                expectedRevocationGeneration: fixture.revocation,
                nowUnixSeconds: fixture.issuedAt + 1
            )
            XCTFail("accepted a non-JSON migration presentation")
        } catch {}

        BaseCampSimulatorURLProtocol.configure(
            presentationPath: BaseCampVaultMigrationRouteV1.presentationPath,
            presentation: presentationJSON,
            contentType: "application/json; charset=UTF-8"
        )
        _ = try await transport.fetchBaseCampVaultMigrationV1(
            expectedDeviceKeyID: fixture.deviceID,
            expectedRevocationGeneration: fixture.revocation,
            nowUnixSeconds: fixture.issuedAt + 1
        )
    }

    @MainActor
    func testMigrationLost204RetriesIdenticalBodyWithoutSecondApproval() async throws {
        let fixture = try Fixture()
        let vector = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: baseCampVaultVector(named: "migration-vector.json")
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
            baseCampFixtureHex: try XCTUnwrap(vector["signature_raw_hex"] as? String)
        ))
        let presentation = try fixture.presentation()
        let approval = MigrationApprovalStub(submission: try fixture.produce(
            presentation, fixedSignature: signature, freshNonceByte: 0xb1
        ))
        BaseCampSimulatorURLProtocol.configure(
            presentationPath: BaseCampVaultMigrationRouteV1.presentationPath,
            presentation: presentationJSON,
            transientSubmissionFailures: 1
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BaseCampSimulatorURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test:8443")),
            expectedSPKISHA256: Data(repeating: 0x71, count: 32),
            configuration: configuration
        )
        let coordinator = BaseCampVaultMigrationCoordinatorV1(
            transport: transport,
            trustStore: try TrustStoreStub(
                revocation: fixture.revocation,
                installationPublic: fixture.devicePublic
            ),
            approval: approval,
            siteRootRegistration: SiteRootRegistrationStub(value: SiteRootKeyRegistrationV1(
                schema: SiteRootKeyRegistrationV1.schema,
                deviceKeyID: fixture.deviceID,
                publicKeyCompressedSEC1: fixture.devicePublic,
                secureEnclaveAttestation: "not-asserted"
            )),
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

    func testBaseCampTransportRejectsOriginAndSPKISubstitution() throws {
        let certificateURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../Fixtures/pistis-example-test.der")
            .standardizedFileURL
        let certificate = try Data(contentsOf: certificateURL)
        let expected = Data(SHA256.hash(data: try CertificateSPKI.extract(from: certificate)))
        XCTAssertTrue(PinnedEnrolmentSessionDelegate.matchesSPKI(
            certificateDER: certificate,
            expectedSPKISHA256: expected
        ))
        XCTAssertFalse(PinnedEnrolmentSessionDelegate.matchesSPKI(
            certificateDER: certificate,
            expectedSPKISHA256: Data(repeating: 0x71, count: 32)
        ))

        let configuration = URLSessionConfiguration.ephemeral
        XCTAssertThrowsError(try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "http://monas.example.test:8443")),
            expectedSPKISHA256: expected,
            configuration: configuration
        ))
        XCTAssertThrowsError(try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(
                URL(string: "https://foreign.example.test:8443/injected")
            ),
            expectedSPKISHA256: expected,
            configuration: configuration
        ))
        XCTAssertThrowsError(try MonasAppAttestTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test:8443")),
            expectedSPKISHA256: Data(repeating: 0, count: 32),
            configuration: configuration
        ))
    }

    @MainActor
    func testCoordinatorRequiresExplicitReviewBeforeFaceIDApproval() async throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()
        let transport = MigrationTransportStub(presentation: presentation)
        let approval = MigrationApprovalStub(submission: try fixture.produce(presentation))
        let registration = SiteRootRegistrationStub(value: SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: fixture.deviceID,
            publicKeyCompressedSEC1: fixture.devicePublic,
            secureEnclaveAttestation: "not-asserted"
        ))
        let coordinator = BaseCampVaultMigrationCoordinatorV1(
            transport: transport,
            trustStore: try TrustStoreStub(
                revocation: fixture.revocation,
                installationPublic: fixture.devicePublic
            ),
            approval: approval,
            siteRootRegistration: registration,
            now: { Date(timeIntervalSince1970: TimeInterval(fixture.issuedAt + 1)) }
        )
        let qr = """
        {"presentation_path":"/v1/pistis/basecamp-vault-migration/presentation","purpose":"basecamp-vault-passphrase-delivery-v1","recipient":"mnemosyne-expedition-basecamp.service","schema":"monas.basecamp-vault-migration-qr.v1"}
        """

        await coordinator.accept(qrText: qr)
        XCTAssertEqual(coordinator.phase, .review)
        XCTAssertNotNil(coordinator.presentedReview)
        var approvalCalls = await approval.calls
        var submissions = await transport.submissions
        XCTAssertEqual(approvalCalls, 0)
        XCTAssertEqual(submissions, 0)

        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .completed)
        approvalCalls = await approval.calls
        submissions = await transport.submissions
        XCTAssertEqual(approvalCalls, 1)
        XCTAssertEqual(submissions, 1)
    }
}

private struct Fixture {
    struct Field {
        var tag: UInt8
        var value: Data
    }

    let site = "site-fixture"
    let generation = "basecamp-vault-1"
    let revocation: UInt64 = 7
    let correlation = Data(repeating: 0x41, count: 16)
    let delegation = "delegation-fixture"
    let issuedAt: UInt64 = 1_000
    var expiresAt: UInt64 = 1_100
    let vaultDigest = Data(repeating: 0x51, count: 32)
    var sourceDigest: Data {
        Data(SHA256.hash(data: Data((secret.hexadecimal + "\n").utf8)))
    }
    let inventoryDigest = Data(repeating: 0x53, count: 32)
    let deviceSigning: P256.Signing.PrivateKey
    let deviceAgreement: P256.KeyAgreement.PrivateKey
    let otherDeviceAgreement: P256.KeyAgreement.PrivateKey
    let oldHostPrivate: P256.KeyAgreement.PrivateKey
    let freshHostPrivate: P256.KeyAgreement.PrivateKey
    let secret: Data
    let expectedPublic: Data
    let encryptedRecord: Data

    var devicePublic: Data { deviceAgreement.publicKey.compressedRepresentation }
    var otherDevicePublic: Data { otherDeviceAgreement.publicKey.compressedRepresentation }
    var oldHostPublic: Data { oldHostPrivate.publicKey.compressedRepresentation }
    var freshHostPublic: Data { freshHostPrivate.publicKey.compressedRepresentation }
    var deviceID: String {
        "site-root-" + Data(SHA256.hash(data: devicePublic)).hexadecimal
    }
    var recordDigest: Data { Data(SHA256.hash(data: encryptedRecord)) }
    var canonicalChallenge: Data { challenge(fields) }

    var fields: [Field] {
        [
            Field(tag: 1, value: Data(site.utf8)),
            Field(tag: 2, value: Data(generation.utf8)),
            Field(tag: 3, value: Data(deviceID.utf8)),
            Field(tag: 4, value: devicePublic),
            Field(tag: 5, value: revocation.bigEndianData),
            Field(tag: 6, value: correlation),
            Field(tag: 7, value: vaultDigest),
            Field(tag: 8, value: sourceDigest),
            Field(tag: 9, value: inventoryDigest),
            Field(tag: 10, value: recordDigest),
            Field(tag: 11, value: expectedPublic),
            Field(tag: 12, value: oldHostPublic),
            Field(tag: 13, value: Data(BaseCampVaultMigrationProfileV1.purpose.utf8)),
            Field(tag: 14, value: Data(BaseCampVaultMigrationProfileV1.recipient.utf8)),
            Field(tag: 15, value: Data(BaseCampVaultMigrationProfileV1.credentialSocket.utf8)),
            Field(tag: 16, value: Data(delegation.utf8)),
            Field(tag: 17, value: issuedAt.bigEndianData),
            Field(tag: 18, value: expiresAt.bigEndianData),
            Field(tag: 19, value: freshHostPublic),
        ]
    }

    init(secretByte: UInt8 = 0x31, expectedSecretByte: UInt8? = nil) throws {
        let deviceScalar = Data(repeating: 0x09, count: 32)
        deviceSigning = try P256.Signing.PrivateKey(rawRepresentation: deviceScalar)
        deviceAgreement = try P256.KeyAgreement.PrivateKey(rawRepresentation: deviceScalar)
        otherDeviceAgreement = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x08, count: 32)
        )
        oldHostPrivate = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x02, count: 32)
        )
        freshHostPrivate = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x03, count: 32)
        )
        secret = Data(repeating: secretByte, count: 32)
        expectedPublic = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: expectedSecretByte ?? secretByte, count: 32)
        ).publicKey.rawRepresentation

        let oldShared = try deviceAgreement.sharedSecretFromKeyAgreement(
            with: oldHostPrivate.publicKey
        ).withUnsafeBytes { Data($0) }
        var material = Data()
        let derivedDeviceID = "site-root-" + Data(
            SHA256.hash(data: deviceAgreement.publicKey.compressedRepresentation)
        ).hexadecimal
        for value in [
            Data(BaseCampVaultMigrationProfileV1.purpose.utf8), Data(site.utf8),
            Data(generation.utf8), Data(derivedDeviceID.utf8),
            oldHostPrivate.publicKey.compressedRepresentation,
        ] {
            material.append(contentsOf: UInt32(value.count).bigEndianBytes)
            material.append(value)
        }
        let aad = Data(SHA256.hash(data: material))
        let key = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: oldShared, aadDigest: aad
        )
        let sealed = try AES.GCM.seal(
            secret,
            using: key,
            nonce: try AES.GCM.Nonce(data: Data(repeating: 0xa1, count: 12)),
            authenticating: aad
        )
        guard let combined = sealed.combined else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        encryptedRecord = combined
    }

    func challenge(_ fields: [Field]) -> Data {
        var result = BaseCampVaultMigrationProfileV1.challengeSchema
        for field in fields {
            result.append(field.tag)
            result.append(contentsOf: UInt16(field.value.count).bigEndianBytes)
            result.append(field.value)
        }
        return result
    }

    func purposeAAD(host: Data) -> Data {
        var material = Data()
        for value in [
            Data(BaseCampVaultMigrationProfileV1.purpose.utf8), Data(site.utf8),
            Data(generation.utf8), Data(deviceID.utf8), host,
        ] {
            material.append(contentsOf: UInt32(value.count).bigEndianBytes)
            material.append(value)
        }
        return Data(SHA256.hash(data: material))
    }

    func presentation(
        challenge: Data? = nil,
        correlation: Data? = nil,
        site: String? = nil,
        generation: String? = nil,
        deviceID: String? = nil,
        expectedPublic: Data? = nil,
        recordDigest: Data? = nil,
        revocation: UInt64? = nil,
        delegation: String? = nil,
        expiresAt: UInt64? = nil,
        existingHost: Data? = nil,
        freshHost: Data? = nil,
        expectedSite: String? = nil,
        expectedDevice: String? = nil,
        expectedRevocation: UInt64? = nil,
        now: UInt64? = nil
    ) throws -> BaseCampVaultMigrationPresentationV1 {
        try BaseCampVaultMigrationPresentationV1(
            correlation: correlation ?? self.correlation,
            canonicalChallenge: challenge ?? canonicalChallenge,
            freshHostPublicSEC1: freshHost ?? freshHostPublic,
            siteTrustDomain: site ?? self.site,
            keyGeneration: generation ?? self.generation,
            deviceKeyID: deviceID ?? self.deviceID,
            expectedEd25519PublicKey: expectedPublic ?? self.expectedPublic,
            encryptedRecordDigest: recordDigest ?? self.recordDigest,
            currentRevocationGeneration: revocation ?? self.revocation,
            delegationSerial: delegation ?? self.delegation,
            expiresAtUnixSeconds: expiresAt ?? self.expiresAt,
            existingHostPublicSEC1: existingHost ?? oldHostPublic,
            existingEncryptedRecord: encryptedRecord,
            expectedSiteTrustDomain: expectedSite ?? self.site,
            expectedDeviceKeyID: expectedDevice ?? self.deviceID,
            expectedRevocationGeneration: expectedRevocation ?? self.revocation,
            nowUnixSeconds: now ?? issuedAt + 1
        )
    }

    func shared(with peer: Data) throws -> Data {
        let key = try P256.KeyAgreement.PublicKey(compressedRepresentation: peer)
        return try deviceAgreement.sharedSecretFromKeyAgreement(with: key).withUnsafeBytes {
            Data($0)
        }
    }

    func produce(
        _ presentation: BaseCampVaultMigrationPresentationV1,
        fixedSignature: Data? = nil,
        freshNonceByte: UInt8? = nil
    ) throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        let protected = try DetachedES256Cose.protectedHeaders(kid: deviceID)
        let signingInput = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: presentation.canonicalChallenge
        )
        let signature = try fixedSignature ?? P256Format.rawSignature(
            fromStrictDER: deviceSigning.signature(for: signingInput).derRepresentation
        )
        return try BaseCampVaultMigrationCryptographicCoreV1.produce(
            presentation,
            enrolledDevicePublicSEC1: devicePublic,
            sign: { input in
                XCTAssertEqual(input, signingInput)
                return signature
            },
            deriveSharedSecret: { try shared(with: $0) },
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
        let encode: (Data) -> String = {
            $0.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return try JSONSerialization.data(withJSONObject: [
            "schema": BaseCampVaultMigrationRouteV1.presentationSchema,
            "correlation_b64url": encode(correlation),
            "canonical_challenge_b64url": encode(canonicalChallenge),
            "fresh_host_public_sec1_b64url": encode(freshHostPublic),
            "site_trust_domain": site,
            "key_generation": generation,
            "device_key_id": deviceID,
            "expected_ed25519_public_key_b64url": encode(expectedPublic),
            "encrypted_record_digest_b64url": encode(recordDigest),
            "current_revocation_generation": revocation,
            "delegation_serial": delegation,
            "expires_at_unix_seconds": expiresAt,
            "existing_host_public_sec1_b64url": encode(oldHostPublic),
            "existing_encrypted_record_b64url": encode(encryptedRecord),
        ], options: [.sortedKeys])
    }
}

private extension Data {
    var hexadecimal: String { map { String(format: "%02x", $0) }.joined() }

    var baseCampFixtureBase64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(baseCampFixtureHex value: String) {
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

func baseCampVaultVector(named name: String) throws -> Data {
    var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    for _ in 0 ..< 4 { root.deleteLastPathComponent() }
    return try Data(
        contentsOf: root.appendingPathComponent("fixtures/basecamp-vault-v1/\(name)")
    )
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
    var bigEndianData: Data { Data(bigEndianBytes) }
}

private final class TrustStoreStub: InstallationTrustStoring, @unchecked Sendable {
    let output: AuthenticatedEnrollmentOutput

    init(revocation: UInt64, installationPublic: Data) throws {
        let user = Data(repeating: 4, count: 16)
        let external = Data(repeating: 5, count: 16)
        output = try AuthenticatedEnrollmentOutput(
            trust: InstallationTrustRecord(
                installationID: Data(repeating: 1, count: 16),
                displayName: "Base Camp fixture",
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

private actor MigrationTransportStub: BaseCampVaultMigrationTransportingV1 {
    let presentation: BaseCampVaultMigrationPresentationV1
    private(set) var submissions = 0
    init(presentation: BaseCampVaultMigrationPresentationV1) { self.presentation = presentation }
    func fetchBaseCampVaultMigrationV1(
        expectedDeviceKeyID: String,
        expectedRevocationGeneration: UInt64,
        nowUnixSeconds _: UInt64
    ) async throws -> BaseCampVaultMigrationPresentationV1 {
        guard expectedDeviceKeyID == presentation.deviceKeyID,
              expectedRevocationGeneration == presentation.currentRevocationGeneration
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return presentation
    }
    func submitBaseCampVaultMigrationV1(
        _: IphoneMediatedCustodyRewrapSubmissionV1
    ) async throws { submissions += 1 }
}

private actor MigrationApprovalStub: BaseCampVaultMigrationApprovalExecutingV1 {
    let submission: IphoneMediatedCustodyRewrapSubmissionV1
    private(set) var calls = 0
    init(submission: IphoneMediatedCustodyRewrapSubmissionV1) { self.submission = submission }
    func approve(_: BaseCampVaultMigrationPresentationV1) async throws
        -> IphoneMediatedCustodyRewrapSubmissionV1
    {
        calls += 1
        return submission
    }
}

private struct SiteRootRegistrationStub: BaseCampVaultSiteRootRegistrationReadingV1 {
    let value: SiteRootKeyRegistrationV1
    func existingRegistration() throws -> SiteRootKeyRegistrationV1? { value }
}

final class BaseCampSimulatorURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var configuredPresentationPath = ""
    private nonisolated(unsafe) static var configuredPresentation = Data()
    private nonisolated(unsafe) static var configuredContentType = "application/json"
    private nonisolated(unsafe) static var transientSubmissionFailuresRemaining = 0
    private nonisolated(unsafe) static var receivedRequests = [URLRequest]()
    private nonisolated(unsafe) static var receivedBodies = [Data?]()

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.receivedRequests.append(request)
        Self.receivedBodies.append(
            request.httpBody ?? Self.readBodyStream(request.httpBodyStream)
        )
        let path = Self.configuredPresentationPath
        let body = Self.configuredPresentation
        let contentType = Self.configuredContentType
        let shouldFailSubmission = request.httpMethod == "POST"
            && request.url?.path.hasSuffix("/submit") == true
            && Self.transientSubmissionFailuresRemaining > 0
        if shouldFailSubmission {
            Self.transientSubmissionFailuresRemaining -= 1
        }
        Self.lock.unlock()

        if shouldFailSubmission {
            client?.urlProtocol(self, didFailWithError: URLError(.networkConnectionLost))
            return
        }

        let isPresentation = request.httpMethod == "GET" && request.url?.path == path
        let isSubmission = request.httpMethod == "POST"
            && request.url?.path.hasSuffix("/submit") == true
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: isPresentation ? 200 : (isSubmission ? 204 : 404),
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Cache-Control": "no-store",
                "Content-Type": contentType,
            ]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if isPresentation { client?.urlProtocol(self, didLoad: body) }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func configure(
        presentationPath: String,
        presentation: Data,
        contentType: String = "application/json",
        transientSubmissionFailures: Int = 0
    ) {
        lock.lock(); defer { lock.unlock() }
        configuredPresentationPath = presentationPath
        configuredPresentation = presentation
        configuredContentType = contentType
        transientSubmissionFailuresRemaining = transientSubmissionFailures
        receivedRequests = []
        receivedBodies = []
    }

    static func requests() -> [URLRequest] {
        lock.lock(); defer { lock.unlock() }
        return receivedRequests
    }

    static func bodies() -> [Data?] {
        lock.lock(); defer { lock.unlock() }
        return receivedBodies
    }

    private static func readBodyStream(_ stream: InputStream?) -> Data? {
        guard let stream else { return nil }
        stream.open(); defer { stream.close() }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count >= 0 else { return nil }
            if count == 0 { break }
            result.append(buffer, count: count)
        }
        return result
    }
}
