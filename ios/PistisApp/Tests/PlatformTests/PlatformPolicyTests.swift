import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class PlatformPolicyTests: XCTestCase {
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
            audience: "jenkins.mnemosyne.test",
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
