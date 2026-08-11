import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class PlatformPolicyTests: XCTestCase {
    @MainActor
    func testCommittedProviderIdentitySkipsRepeatedGitHubPrompt() async {
        let flow = FirstDeviceEnrolmentFlow()
        let prompt = GitHubDeviceAuthorizationPrompt(
            userCode: "REC0-VERY",
            verificationURI: URL(string: "https://github.com/login/device")!,
            expiresInSeconds: 300,
            intervalSeconds: 1
        )

        await flow.applyProviderStatus(
            .verified(
                numericSubject: 3_848_500,
                displayLogin: "sagrudd",
                policyGeneration: 1,
                authorityChallenge: Data(repeating: 0x44, count: 32),
                authorityChallengeExpiresAtMilliseconds: 1_900_000_000_000
            ),
            pendingPrompt: prompt
        )

        XCTAssertNil(flow.prompt)
        XCTAssertEqual(flow.verifiedSubject, 3_848_500)
        XCTAssertEqual(flow.displayLogin, "sagrudd")
        XCTAssertEqual(
            flow.status,
            "Review the verified GitHub account before enrolling"
        )
    }

    func testPKCEFixture() throws {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        XCTAssertEqual(
            try PKCE.challenge(for: verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        )
    }

    func testExactCallback() throws {
        let registered = try XCTUnwrap(URL(string: "pistis://oauth/callback"))
        let attempt = OAuthAttempt(
            authorizationURL: try XCTUnwrap(
                URL(string: "https://github.com/login/oauth/authorize")
            ),
            callbackURL: registered,
            state: "expected-state",
            codeVerifier: String(repeating: "v", count: 43),
            codeChallenge: "challenge"
        )
        let callback = try XCTUnwrap(
            URL(string: "pistis://oauth/callback?code=one-use-code&state=expected-state")
        )
        XCTAssertEqual(
            try attempt.validate(callback: callback),
            OAuthAuthorizationCode(
                code: "one-use-code",
                codeVerifier: String(repeating: "v", count: 43)
            )
        )
    }

    func testInvalidCallbacks() throws {
        let attempt = OAuthAttempt(
            authorizationURL: try XCTUnwrap(
                URL(string: "https://github.com/login/oauth/authorize")
            ),
            callbackURL: try XCTUnwrap(URL(string: "pistis://oauth/callback")),
            state: "expected-state",
            codeVerifier: String(repeating: "v", count: 43),
            codeChallenge: "challenge"
        )
        let invalidValues = [
            "pistis://oauth/other?code=a&state=expected-state",
            "pistis://oauth/callback?code=a&state=wrong",
            "pistis://oauth/callback?code=a&state=expected-state&state=expected-state",
            "pistis://oauth/callback?error=access_denied&state=expected-state",
        ]
        for value in invalidValues {
            let callback = try XCTUnwrap(URL(string: value))
            XCTAssertThrowsError(try attempt.validate(callback: callback))
        }
    }

    func testStrictDERToRaw() throws {
        let der = Data([0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x01, 0x00])
        let raw = try P256Format.rawSignature(fromStrictDER: der)
        XCTAssertEqual(raw.count, 64)
        XCTAssertEqual(raw[31], 0x80)
        XCTAssertEqual(raw[62], 0x01)
        XCTAssertEqual(raw[63], 0x00)
    }

    func testStrictDERRejectsAmbiguousOrNegativeIntegers() {
        let invalid = [
            Data([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]),
            Data([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01]),
            Data([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]),
            Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]),
        ]
        for value in invalid {
            XCTAssertThrowsError(try P256Format.rawSignature(fromStrictDER: value))
        }
    }

    func testStrictDERNormalizesHighS() throws {
        // P-256 order minus one is a valid high-S scalar. Its canonical
        // low-S twin is one.
        let orderMinusOne: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50,
        ]
        let der = Data([0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00] + orderMinusOne)
        let raw = try P256Format.rawSignature(fromStrictDER: der)
        XCTAssertEqual(raw.suffix(32), Data(repeating: 0, count: 31) + Data([1]))
    }

    func testPublicKeyCompressionPreservesXAndYParity() throws {
        var x963 = Data([0x04])
        x963.append(Data(repeating: 0x11, count: 32))
        x963.append(Data(repeating: 0x22, count: 31))
        x963.append(0x03)
        XCTAssertEqual(
            try P256Format.compressX963PublicKey(x963),
            Data([0x03]) + Data(repeating: 0x11, count: 32)
        )
    }

    func testProductionEnvelopeFailsClosed() async {
        do {
            _ = try await UnsupportedProductionEnvelope().produceEnvelope(
                canonicalPayload: Data([0xa0])
            )
            XCTFail("production envelope unexpectedly succeeded")
        } catch {
            XCTAssertEqual(
                error as? PlatformFailure,
                PlatformFailure.productionEnvelopeUnavailable
            )
        }
    }

    func testMonasSiteRootAuthorityConfigurationAcceptsOnlyAnExactSignedOrigin() throws {
        let configuration = try MonasSiteRootAuthorityConfiguration(
            infoDictionary: [
                MonasSiteRootAuthorityConfiguration.infoDictionaryKey:
                    "https://monas.example.test",
                MonasSiteRootAuthorityConfiguration.spkiInfoDictionaryKey:
                    "ERERERERERERERERERERERERERERERERERERERERERE",
            ]
        )
        XCTAssertEqual(configuration.authorityOrigin.absoluteString, "https://monas.example.test")
        XCTAssertNoThrow(try configuration.makeTransport())

        for invalid in [
            "",
            "$(PISTIS_MONAS_SITE_ROOT_AUTHORITY_ORIGIN)",
            "http://monas.example.test",
            "https://monas.example.test/authority",
            "https://user@monas.example.test",
            "https://monas.example.test?selected=by-qr",
        ] {
            XCTAssertThrowsError(try MonasSiteRootAuthorityConfiguration(
                rawValue: invalid,
                spkiB64URL: "ERERERERERERERERERERERERERERERERERERERERERE"
            ))
        }
    }

    func testMonasSiteRootTransportFactoryFailsClosedWithoutBuildConfiguration() {
        let transport = ProductionMonasSiteRootTransportFactory.make(infoDictionary: [:])
        XCTAssertTrue(transport is UnavailableMonasSiteRootDelegationTransport)
    }

    func testAppleAppAttestRegistrationEnvelopeUsesReviewedV1Contract() throws {
        let appleKeyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let envelope = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: "ceremony-7f2e",
            siteTrustDomain: "site-demo-1",
            appleKeyID: appleKeyID,
            clientDataHash: Data(repeating: 0x22, count: 32),
            attestationObject: Data(repeating: 0x33, count: 128)
        )

        XCTAssertEqual(envelope.wireProtocol, "pistis.apple-app-attest-registration.v1")
        XCTAssertEqual(envelope.appIdentifier, "C7A6NQTSY4.org.mnemosynebiosciences.pistis")
        XCTAssertEqual(envelope.keyIDB64URL, String(repeating: "ERERERERERERERERERERERERERERERERERERERERERE", count: 1))
        XCTAssertEqual(envelope.clientDataHashB64URL.count, 43)
        XCTAssertFalse(envelope.redactedDiagnostic.contains(envelope.keyIDB64URL))
        XCTAssertFalse(envelope.redactedDiagnostic.contains(envelope.clientDataHashB64URL))
        XCTAssertFalse(envelope.redactedDiagnostic.contains(envelope.attestationObjectB64URL))

        let encoded = try JSONEncoder().encode(envelope)
        let encodedObject = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(
            encodedObject["protocol"] as? String,
            "pistis.apple-app-attest-registration.v1"
        )
        XCTAssertNil(encodedObject["version"])
        let decoded = try JSONDecoder().decode(
            AppleAppAttestRegistrationEnvelope.self,
            from: encoded
        )
        XCTAssertEqual(decoded, envelope)
    }

    func testAppleAppAttestRegistrationEnvelopeRejectsUnboundedOrInvalidInput() {
        let validKeyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        XCTAssertThrowsError(
            try AppleAppAttestRegistrationEnvelope(
                ceremonyID: "has whitespace",
                siteTrustDomain: "site-demo-1",
                appleKeyID: validKeyID,
                clientDataHash: Data(repeating: 0x22, count: 32),
                attestationObject: Data([0x01])
            )
        )
        XCTAssertThrowsError(
            try AppleAppAttestRegistrationEnvelope(
                ceremonyID: "ceremony-7f2e",
                siteTrustDomain: "site-demo-1",
                appleKeyID: "not-base64url",
                clientDataHash: Data(repeating: 0x22, count: 32),
                attestationObject: Data([0x01])
            )
        )
        XCTAssertThrowsError(
            try AppleAppAttestRegistrationEnvelope(
                ceremonyID: "ceremony-7f2e",
                siteTrustDomain: "site-demo-1",
                appleKeyID: validKeyID,
                clientDataHash: Data(repeating: 0x22, count: 31),
                attestationObject: Data([0x01])
            )
        )
    }

    func testScannerFailuresExposeOnlyBoundedRecoveryMessages() {
        XCTAssertEqual(
            PlatformFailure.qrPayloadTooLarge.safeUserMessage,
            "This QR code is larger than the Pistis safety limit."
        )
        XCTAssertEqual(
            PlatformFailure.qrPayloadUnsupported.safeUserMessage,
            "This is not a supported Pistis QR code."
        )
        XCTAssertFalse(
            PlatformFailure.signingFailed.safeUserMessage.localizedCaseInsensitiveContains(
                "key"
            )
        )
        XCTAssertEqual(
            PlatformFailure.existingEnrolmentMustBeRemoved.safeUserMessage,
            "An existing Pistis identity already occupies this device. Remove or revoke it before beginning a new enrolment."
        )
        XCTAssertTrue(
            PlatformFailure.userVerificationLockedOut.safeUserMessage.contains("Face ID")
        )
        XCTAssertTrue(
            PlatformFailure.enrolmentReceiptInvalid.safeUserMessage
                .contains("signed response did not verify")
        )
        XCTAssertTrue(
            PlatformFailure.enrolmentStorageFailed.safeUserMessage
                .contains("retain it securely")
        )
    }

    func testPasswordlessReadinessRequiresEveryIndependentGate() {
        let ready = PasswordlessReadiness(
            camera: .init(id: "camera", title: "Camera", detail: "Ready.", state: .ready),
            faceID: .init(id: "face-id", title: "Face ID", detail: "Ready.", state: .ready),
            deviceKey: .init(
                id: "device-key",
                title: "Device signing key",
                detail: "Ready.",
                state: .ready
            ),
            authorityKey: .init(
                id: "authority-key",
                title: "Installation authority",
                detail: "Ready.",
                state: .ready
            ),
            verifier: .init(
                id: "verifier",
                title: "Production verifier",
                detail: "Ready.",
                state: .ready
            )
        )
        XCTAssertTrue(ready.approvalEnabled)

        for blockedID in ready.items.map(\.id) {
            let items = ready.items.map {
                ReadinessItem(
                    id: $0.id,
                    title: $0.title,
                    detail: $0.detail,
                    state: $0.id == blockedID ? .unavailable : .ready
                )
            }
            let blocked = PasswordlessReadiness(
                camera: items[0],
                faceID: items[1],
                deviceKey: items[2],
                authorityKey: items[3],
                verifier: items[4]
            )
            XCTAssertFalse(blocked.approvalEnabled, "gate \(blockedID) was bypassed")
        }
    }

    func testGitHubEnrolmentConfigurationIsExactAndCredentialFree() throws {
        let configuration = try GitHubEnrolmentConfiguration(
            clientID: GitHubEnrolmentConfiguration.reviewedClientID,
            deviceCodeEndpoint: try XCTUnwrap(
                URL(string: "https://github.com/login/device/code")
            ),
            accessTokenEndpoint: try XCTUnwrap(
                URL(string: "https://github.com/login/oauth/access_token")
            ),
            authenticatedUserEndpoint: try XCTUnwrap(URL(string: "https://api.github.com/user")),
            apiVersion: "2022-11-28",
            appConfigurationDigest:
                GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest
        )
        XCTAssertEqual(
            configuration.clientID,
            GitHubEnrolmentConfiguration.reviewedClientID
        )

        let invalidDeviceEndpoints = [
            "http://github.com/login/device/code",
            "https://github.com/login/oauth/authorize",
            "https://attacker.example/login/device/code",
        ]
        for value in invalidDeviceEndpoints {
            XCTAssertThrowsError(
                try GitHubEnrolmentConfiguration(
                    clientID: GitHubEnrolmentConfiguration.reviewedClientID,
                    deviceCodeEndpoint: XCTUnwrap(URL(string: value)),
                    accessTokenEndpoint: XCTUnwrap(
                        URL(string: "https://github.com/login/oauth/access_token")
                    ),
                    authenticatedUserEndpoint: XCTUnwrap(
                        URL(string: "https://api.github.com/user")
                    ),
                    apiVersion: "2022-11-28",
                    appConfigurationDigest:
                        GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest
                )
            )
        }
        XCTAssertThrowsError(
            try GitHubEnrolmentConfiguration(
                clientID: "Iv23lievAttackerClient",
                deviceCodeEndpoint: XCTUnwrap(
                    URL(string: "https://github.com/login/device/code")
                ),
                accessTokenEndpoint: XCTUnwrap(
                    URL(string: "https://github.com/login/oauth/access_token")
                ),
                authenticatedUserEndpoint: XCTUnwrap(
                    URL(string: "https://api.github.com/user")
                ),
                apiVersion: "2022-11-28",
                appConfigurationDigest:
                    GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest
            )
        )
        XCTAssertThrowsError(
            try GitHubEnrolmentConfiguration(
                clientID: GitHubEnrolmentConfiguration.reviewedClientID,
                deviceCodeEndpoint: XCTUnwrap(
                    URL(string: "https://github.com/login/device/code")
                ),
                accessTokenEndpoint: XCTUnwrap(
                    URL(string: "https://github.com/login/oauth/access_token")
                ),
                authenticatedUserEndpoint: XCTUnwrap(
                    URL(string: "https://api.github.com/user")
                ),
                apiVersion: "2022-11-28",
                appConfigurationDigest: Data(repeating: 0x55, count: 32)
            )
        )
    }

    func testGitHubIdentityProofUsesNumericSubjectAndBoundedDisplayOnly() throws {
        let proof = try GitHubStableIdentityProof(
            numericSubject: 1_842_030,
            displayLogin: "synthetic-user"
        )
        XCTAssertEqual(proof.numericSubject, 1_842_030)
        XCTAssertThrowsError(
            try GitHubStableIdentityProof(
                numericSubject: 0,
                displayLogin: "synthetic-user"
            )
        )
        XCTAssertThrowsError(
            try GitHubStableIdentityProof(
                numericSubject: 1,
                displayLogin: "attacker\ncontent"
            )
        )
    }

    func testGitHubDeviceFlowIsReadyWithoutClaimingAuthorityEnrolment() {
        let readiness = GitHubEnrolmentReadiness.current()
        XCTAssertTrue(readiness.state.mayStart)
        XCTAssertFalse(readiness.configurationLabel.localizedCaseInsensitiveContains("secret"))
        XCTAssertFalse(readiness.identityRule.contains("@"))
    }

    @MainActor
    func testReadinessSnapshotContainsNoKeyOrAttackerMaterial() async {
        let snapshot = await PasswordlessReadinessProbe.current(
            trustStore: EmptyTrustStore()
        )
        let rendered = snapshot.items
            .flatMap { [$0.id, $0.title, $0.detail] }
            .joined(separator: " ")
            .lowercased()

        XCTAssertFalse(rendered.contains("pistis1:"))
        XCTAssertFalse(rendered.contains("key_id"))
        XCTAssertFalse(rendered.contains("endpoint"))
        XCTAssertFalse(rendered.contains("github"))
    }

    func testTransportUsesProtocolTwoKiBBounds() {
        XCTAssertEqual(AuthenticationResponseTransport.maximumEnvelopeBytes, 2_048)
        XCTAssertEqual(AuthenticationResponseTransport.maximumResponseBytes, 2_048)
    }

    func testAuthorityStatusDecodesExactMonasWireNames() throws {
        let status = try JSONDecoder().decode(
            AuthoritativeCeremonyStatus.self,
            from: Data(#"{"state":"completed","evidence_id":null}"#.utf8)
        )
        XCTAssertEqual(status.state, .completed)
        XCTAssertNil(status.evidenceID)
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AuthoritativeCeremonyStatus.self,
                from: Data(#"{"state":"accepted","evidence_id":null}"#.utf8)
            )
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AuthoritativeCeremonyStatus.self,
                from: Data(
                    #"{"state":"completed","evidence_id":null,"redirect":"https://attacker.test"}"#
                        .utf8
                )
            )
        )
    }

    func testTransportRejectsNonCanonicalAllowedHosts() {
        for host in [
            "Jenkins.mnemosyne.test",
            "jenkins.mnemosyne.test.",
            "jenkins..mnemosyne.test",
            "jenkins.mnemosyne.test/path",
            "jënkins.mnemosyne.test",
            "127.0.0.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "127.1",
            "::1",
        ] {
            XCTAssertThrowsError(
                try AuthenticationResponseTransport(allowedHosts: [host]),
                "non-canonical host unexpectedly accepted: \(host)"
            )
        }
    }

    func testTransportDelegateRefusesRedirectBeforeBodyReplay() throws {
        let original = try XCTUnwrap(
            URL(string: "https://jenkins.mnemosyne.test/auth/pistis")
        )
        let redirected = try XCTUnwrap(
            URL(string: "https://attacker.test/capture")
        )
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: original,
                statusCode: 307,
                httpVersion: "HTTP/1.1",
                headerFields: ["Location": redirected.absoluteString]
            )
        )
        var followedRequest: URLRequest? = URLRequest(url: redirected)
        RedirectRejectingSessionDelegate().urlSession(
            .shared,
            task: URLSession.shared.dataTask(with: original),
            willPerformHTTPRedirection: response,
            newRequest: URLRequest(url: redirected)
        ) {
            followedRequest = $0
        }
        XCTAssertNil(followedRequest)
    }

    func testPersistedEnrollmentOutputRejectsUnknownFields() throws {
        let trust = try InstallationTrustRecord(
            installationID: Data(repeating: 1, count: 16),
            displayName: "Mnemosyne Jenkins",
            audience: "prosopikon:pistis:enrolment",
            authorisedProductAudiences: ["jenkins"],
            userID: Data(repeating: 2, count: 16),
            externalIdentityID: Data(repeating: 3, count: 16),
            fingerprint: Data(repeating: 4, count: 32),
            installationKeyID: Data(repeating: 5, count: 32),
            installationPublicKey: Data([2]) + Data(repeating: 6, count: 32),
            authorityKeyID: Data(repeating: 7, count: 32),
            authorityReceipt: Data([1]),
            policyGeneration: 1,
            revocationGeneration: 1,
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            active: true
        )
        let context = try DeviceResponseContext(
            deviceID: Data(repeating: 8, count: 16),
            deviceKeyID: Data(repeating: 9, count: 32),
            userID: trust.userID,
            externalIdentityID: trust.externalIdentityID
        )
        let output = try AuthenticatedEnrollmentOutput(
            trust: trust,
            responseContext: context,
            allowedHosts: ["jenkins.mnemosyne.test"]
        )
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(output))
                as? [String: Any]
        )
        object["unexpected"] = true
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AuthenticatedEnrollmentOutput.self,
                from: JSONSerialization.data(withJSONObject: object)
            )
        )
    }

    func testFirstDeviceInstallIsCreateOnceOrExactReplay() throws {
        let first = try enrollmentOutput(marker: 1)
        let different = try enrollmentOutput(marker: 2)
        XCTAssertEqual(
            try InstallationTrustKeychain.firstInstallDisposition(
                existing: nil,
                proposed: first
            ),
            .create
        )
        XCTAssertEqual(
            try InstallationTrustKeychain.firstInstallDisposition(
                existing: first,
                proposed: first
            ),
            .idempotent
        )
        XCTAssertThrowsError(
            try InstallationTrustKeychain.firstInstallDisposition(
                existing: first,
                proposed: different
            )
        ) { error in
            XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration)
        }
    }

    func testFirstDeviceInstallAcceptsOnlyGenerationAdvancedReplacement() throws {
        let first = try enrollmentOutput(marker: 1)
        let replacement = try replacementOutput(for: first, marker: 20)
        XCTAssertEqual(
            try InstallationTrustKeychain.firstInstallDisposition(
                existing: first,
                proposed: replacement
            ),
            .replace
        )

        let wrongIdentity = try enrollmentOutput(marker: 2)
        XCTAssertThrowsError(
            try InstallationTrustKeychain.firstInstallDisposition(
                existing: first,
                proposed: wrongIdentity
            )
        )

        let generationJump = try replacementOutput(
            for: first,
            marker: 21,
            revocationGeneration: first.trust.revocationGeneration + 2
        )
        XCTAssertThrowsError(
            try InstallationTrustKeychain.firstInstallDisposition(
                existing: first,
                proposed: generationJump
            )
        )
    }

    func testUnenrolledKeyCleanupRetainsRetriesAndNeverDeletesActiveKey() {
        XCTAssertTrue(
            UnenrolledKeyLifecycle.shouldDiscard(
                after: .cancelled,
                hasStoredEnrollment: false
            )
        )
        XCTAssertTrue(
            UnenrolledKeyLifecycle.shouldDiscard(
                after: .expired,
                hasStoredEnrollment: false
            )
        )
        XCTAssertFalse(
            UnenrolledKeyLifecycle.shouldDiscard(
                after: .pending,
                hasStoredEnrollment: false
            )
        )
        XCTAssertFalse(
            UnenrolledKeyLifecycle.shouldDiscard(
                after: .transientFailure,
                hasStoredEnrollment: false
            )
        )
        XCTAssertFalse(
            UnenrolledKeyLifecycle.shouldDiscard(
                after: .consumed,
                hasStoredEnrollment: false
            )
        )
        XCTAssertFalse(
            UnenrolledKeyLifecycle.shouldDiscard(
                after: .cancelled,
                hasStoredEnrollment: true
            )
        )
    }

    func testBeginRetryReusesExactOperationUntilAcceptedOrReset() throws {
        let first = Data(repeating: 0x41, count: 16)
        let divergent = Data(repeating: 0x42, count: 16)
        var generated = 0
        var state = EnrolmentBeginRetryState()

        XCTAssertEqual(
            try state.operationID {
                generated += 1
                return first
            },
            first
        )
        XCTAssertEqual(
            try state.operationID {
                generated += 1
                return divergent
            },
            first
        )
        XCTAssertEqual(generated, 1)

        state.markAccepted()
        XCTAssertEqual(
            try state.operationID {
                generated += 1
                return divergent
            },
            divergent
        )
        state.reset()
        XCTAssertNil(state.retainedOperationID)
    }

    func testBeginRetryRejectsInvalidGeneratedOperation() {
        var state = EnrolmentBeginRetryState()
        XCTAssertThrowsError(
            try state.operationID { Data(repeating: 0, count: 16) }
        ) { error in
            XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration)
        }
        XCTAssertNil(state.retainedOperationID)
    }

    func testVerifiedAccountRequiresSeparateExplicitConfirmation() throws {
        let approval = VerifiedProviderApproval(
            subject: 123_456_789,
            login: "sagrudd",
            policyGeneration: 1,
            authorityChallenge: Data(repeating: 0x44, count: 32),
            challengeExpiry: 1_900_000_000_000
        )
        var gate = AttendedEnrolmentGate()
        gate.recordProviderVerification(approval)
        XCTAssertEqual(
            gate.state,
            .awaitingExplicitConfirmation(approval)
        )
        XCTAssertEqual(
            try gate.takeForExplicitConfirmation(),
            approval
        )
        XCTAssertEqual(gate.state, .confirming(approval))
    }

    @MainActor
    func testCoordinatorFailsClosedWithoutAuthenticatedEnrolment() async {
        let coordinator = ProductionCeremonyCoordinator(
            trustStore: EmptyTrustStore(),
            now: { Date(timeIntervalSince1970: 1_700_000_000) }
        )
        await coordinator.accept(qrText: "PISTIS1:attacker.0000000000000000")
        XCTAssertEqual(coordinator.phase, .failed(.enrolmentRequired))
    }

    @MainActor
    func testBrowserEnrolmentNeverWritesUnverifiedBrokerOutput() async {
        let store = RecordingTrustStore()
        let coordinator = SystemBrowserEnrollmentCoordinator(
            authorize: {
                OAuthAuthorizationCode(code: "one-use", codeVerifier: String(repeating: "v", count: 43))
            },
            broker: RejectingEnrollmentBroker(),
            trustStore: store
        )
        do {
            try await coordinator.enroll(
                exactDeviceRegistrationEnvelope: Data([0x84, 0x01])
            )
            XCTFail("unverified broker exchange unexpectedly succeeded")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .productionEnvelopeUnavailable)
        }
        let installCount = await store.installCount()
        XCTAssertEqual(installCount, 0)
    }

    @MainActor
    func testBrowserEnrolmentRejectsOversizeBeforeAuthorization() async {
        var authorized = false
        let coordinator = SystemBrowserEnrollmentCoordinator(
            authorize: {
                authorized = true
                return OAuthAuthorizationCode(
                    code: "one-use",
                    codeVerifier: String(repeating: "v", count: 43)
                )
            },
            broker: RejectingEnrollmentBroker(),
            trustStore: RecordingTrustStore()
        )
        do {
            try await coordinator.enroll(
                exactDeviceRegistrationEnvelope: Data(repeating: 0, count: 2_049)
            )
            XCTFail("oversized registration unexpectedly succeeded")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration)
        }
        XCTAssertFalse(authorized)
    }
}

private func enrollmentOutput(marker: UInt8)
    throws -> AuthenticatedEnrollmentOutput
{
    let trust = try InstallationTrustRecord(
        installationID: Data(repeating: marker, count: 16),
        displayName: "Mnemosyne \(marker)",
        audience: "prosopikon:pistis:enrolment",
        authorisedProductAudiences: ["propylaion"],
        userID: Data(repeating: marker &+ 1, count: 16),
        externalIdentityID: Data(repeating: marker &+ 2, count: 16),
        fingerprint: Data(repeating: marker &+ 3, count: 32),
        installationKeyID: Data(repeating: marker &+ 4, count: 32),
        installationPublicKey:
            Data([0x02]) + Data(repeating: marker &+ 5, count: 32),
        authorityKeyID: Data(repeating: marker &+ 6, count: 32),
        authorityReceipt: Data([marker]),
        policyGeneration: 1,
        revocationGeneration: 1,
        expiresAt: Date(timeIntervalSince1970: 1_900_000_000),
        active: true
    )
    return try AuthenticatedEnrollmentOutput(
        trust: trust,
        responseContext: DeviceResponseContext(
            deviceID: Data(repeating: marker &+ 7, count: 16),
            deviceKeyID: Data(repeating: marker &+ 8, count: 32),
            userID: trust.userID,
            externalIdentityID: trust.externalIdentityID
        ),
        allowedHosts: ["pistis.example.test"]
    )
}

private func replacementOutput(
    for existing: AuthenticatedEnrollmentOutput,
    marker: UInt8,
    revocationGeneration: UInt64? = nil
) throws -> AuthenticatedEnrollmentOutput {
    let old = existing.trust
    let trust = try InstallationTrustRecord(
        installationID: old.installationID,
        displayName: old.displayName,
        audience: old.audience,
        authorisedProductAudiences: old.authorisedProductAudiences,
        userID: old.userID,
        externalIdentityID: old.externalIdentityID,
        fingerprint: old.fingerprint,
        installationKeyID: old.installationKeyID,
        installationPublicKey: old.installationPublicKey,
        authorityKeyID: old.authorityKeyID,
        authorityReceipt: Data([marker]),
        policyGeneration: old.policyGeneration,
        revocationGeneration: revocationGeneration ?? old.revocationGeneration + 1,
        expiresAt: old.expiresAt.addingTimeInterval(3_600),
        active: true
    )
    return try AuthenticatedEnrollmentOutput(
        trust: trust,
        responseContext: DeviceResponseContext(
            deviceID: Data(repeating: marker, count: 16),
            deviceKeyID: Data(repeating: marker &+ 1, count: 32),
            userID: trust.userID,
            externalIdentityID: trust.externalIdentityID
        ),
        allowedHosts: existing.allowedHosts
    )
}

private actor EmptyTrustStore: InstallationTrustStoring {
    func record(installationID _: Data) -> InstallationTrustRecord? { nil }
    func activeEnrollment() -> AuthenticatedEnrollmentOutput? { nil }
    func installAuthenticated(_: AuthenticatedEnrollmentOutput) {}
    func revoke(installationID _: Data) {}
}

private struct RejectingEnrollmentBroker: EnrollmentReceiptExchanging {
    func exchangeAndVerify(
        authorization _: OAuthAuthorizationCode,
        exactDeviceRegistrationEnvelope _: Data
    ) throws -> AuthenticatedEnrollmentOutput {
        throw PlatformFailure.productionEnvelopeUnavailable
    }
}

private actor RecordingTrustStore: InstallationTrustStoring {
    private var installs = 0
    func record(installationID _: Data) -> InstallationTrustRecord? { nil }
    func activeEnrollment() -> AuthenticatedEnrollmentOutput? { nil }
    func installAuthenticated(_: AuthenticatedEnrollmentOutput) { installs += 1 }
    func revoke(installationID _: Data) {}
    func installCount() -> Int { installs }
}
