import Foundation
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
    func testReadinessSnapshotContainsNoKeyOrAttackerMaterial() {
        let snapshot = PasswordlessReadinessProbe.current()
        let rendered = snapshot.items
            .flatMap { [$0.id, $0.title, $0.detail] }
            .joined(separator: " ")
            .lowercased()

        XCTAssertFalse(rendered.contains("pistis1:"))
        XCTAssertFalse(rendered.contains("key_id"))
        XCTAssertFalse(rendered.contains("endpoint"))
        XCTAssertFalse(rendered.contains("github"))
    }
}
