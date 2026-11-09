import Foundation
import CryptoKit
import XCTest
@testable import Pistis

final class SiteRootBrokerWireV2Tests: XCTestCase {
    private let now: UInt64 = 1_900_000_000_000
    private let operation = Data(1...16)

    private func fixture(_ name: String) throws -> Data {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Fixtures/broker-v2-\(name).json")
        return try Data(contentsOf: url)
    }
    func testSharedQRAndCanonicalRequestFixtures() throws {
        let qr = try XCTUnwrap(String(data: fixture("qr"), encoding: .utf8))
        let presentation = try SiteRootBrokerPresentationV2(qrText: qr, nowMillis: now)
        XCTAssertEqual(presentation.reference, "genesis-reference-1")
        XCTAssertEqual(presentation.correlation, Data(32...63))
        let request = try fixture("request")
        XCTAssertEqual(try SiteRootBrokerRegistrationWireV2.canonicalWire(request), request)
        // The shared wire-only fixture deliberately contains an invalid P-256 key.
        XCTAssertThrowsError(try SiteRootBrokerRegistrationWireV2.validate(
            request, presentation: presentation, operationID: operation))
        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: qr, authorityOrigin: URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin)!,
            nowUnixMillis: now))
    }
    func testGeneratedRequestUsesCanonicalBytesAndValidKeyBinding() throws {
        let qr = try XCTUnwrap(String(data: fixture("qr"), encoding: .utf8))
        let presentation = try SiteRootBrokerPresentationV2(qrText: qr, nowMillis: now)
        let publicKey = P256.Signing.PrivateKey().publicKey.compressedRepresentation
        let key = SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-" + SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined(),
            publicKeyCompressedSEC1: publicKey, secureEnclaveAttestation: "not-asserted"
        )
        let hash = try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: operation, correlation: presentation.correlation,
            reference: presentation.reference, hostChallenge: presentation.challenge)
        let apple = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: presentation.ceremonyID, siteTrustDomain: presentation.site,
            appleKeyID: Data(repeating: 0x12, count: 32).base64EncodedString(),
            clientDataHash: hash, attestationObject: Data(repeating: 0x13, count: 8))
        let bytes = try SiteRootBrokerRegistrationWireV2.encode(
            presentation: presentation, operationID: operation, siteRootKey: key, appAttest: apple)
        XCTAssertEqual(try SiteRootBrokerRegistrationWireV2.canonicalWire(bytes), bytes)
        try SiteRootBrokerRegistrationWireV2.validate(bytes, presentation: presentation, operationID: operation)
        XCTAssertThrowsError(try SiteRootBrokerRegistrationWireV2.validate(
            bytes, presentation: presentation, operationID: Data(repeating: 9, count: 16)))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        object["unknown"] = "x"
        let unknown = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        XCTAssertThrowsError(try SiteRootBrokerRegistrationWireV2.validate(
            unknown, presentation: presentation, operationID: operation))
        let badKey = SiteRootKeyRegistrationV1(schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-" + String(repeating: "0", count: 64),
            publicKeyCompressedSEC1: publicKey, secureEnclaveAttestation: "not-asserted")
        XCTAssertThrowsError(try SiteRootBrokerRegistrationWireV2.encode(
            presentation: presentation, operationID: operation, siteRootKey: badKey, appAttest: apple))
    }
    func testRejectsMalformedQRAndNoncanonicalRequest() throws {
        let qr = try XCTUnwrap(String(data: fixture("qr"), encoding: .utf8))
        for changed in [
            qr.replacingOccurrences(of: "https://install.mnemosyne.co.uk", with: "https://other.example"),
            qr.replacingOccurrences(of: "\"schema\":", with: "\"schema\":\"duplicate\",\"schema\":"),
            qr.replacingOccurrences(of: "\"reference\":", with: "\"extra\":\"x\",\"reference\":"),
            qr.replacingOccurrences(of: "1900000900000", with: "1900000900000e0"),
            qr.replacingOccurrences(of: "genesis-reference-1", with: "genesis\\u002dreference-1"),
            qr.replacingOccurrences(of: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8", with: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="),
        ] { XCTAssertThrowsError(try SiteRootBrokerPresentationV2(qrText: changed, nowMillis: now)) }
        let request = try XCTUnwrap(String(data: fixture("request"), encoding: .utf8))
        for changed in [
            " " + request,
            request.replacingOccurrences(of: "\"schema\":", with: "\"schema\":\"x\",\"schema\":"),
            request.replacingOccurrences(of: "genesis-reference-1", with: "genesis\\u002dreference-1"),
            request.replacingOccurrences(of: "\"reference\":", with: "\"reference\":null,\"discard\":"),
        ] { XCTAssertThrowsError(try SiteRootBrokerRegistrationWireV2.canonicalWire(Data(changed.utf8))) }
    }

    @MainActor
    func testNormalScannerRecognisesV2ButCannotApprove() async throws {
        let qr = try XCTUnwrap(String(data: fixture("qr"), encoding: .utf8))
        XCTAssertTrue(QRPayloadProfile.pistisAuthenticationOrMonasSiteRoot.accepts(qr))
        XCTAssertEqual(MonasJSONScanRoute.classify(qr), .siteRootDelegation)
        let coordinator = SiteRootDelegationCoordinator(nowMillis: { self.now })
        coordinator.accept(qrText: qr)
        guard case .review = coordinator.phase else { return XCTFail("expected V2 review") }
        XCTAssertTrue(coordinator.isValidatedBrokerFirstDevice)
        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .failed(.siteRootBindingUnavailable))
    }
}
