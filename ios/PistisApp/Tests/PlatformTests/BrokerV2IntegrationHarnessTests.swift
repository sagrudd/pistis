import CryptoKit
import Foundation
import XCTest
@testable import Pistis

/// Test-target orchestration only. The authority and Apple results below are
/// synthetic; this does not implement a transport or establish installation B.
@MainActor
final class BrokerV2IntegrationHarnessTests: XCTestCase {
    private func qr() throws -> String {
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Fixtures/broker-v2-qr.json")
        return try String(contentsOf: path, encoding: .utf8)
    }

    func testInterruptedSubmissionRetainsExactBAndDoesNotTouchLegacyA() async throws {
        let text = try qr()
        XCTAssertTrue(QRPayloadProfile.pistisAuthenticationOrMonasSiteRoot.accepts(text))
        XCTAssertEqual(MonasJSONScanRoute.classify(text), .siteRootDelegation)
        let presentation = try SiteRootBrokerPresentationV2(qrText: text, nowMillis: 1_900_000_000_000)
        let coordinator = SiteRootDelegationCoordinator(nowMillis: { 1_900_000_000_000 })
        coordinator.accept(qrText: text)
        guard case .review = coordinator.phase else { return XCTFail("V2 did not reach review") }
        // Production approval remains deliberately blocked.
        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .failed(.siteRootBindingUnavailable))

        let operationID = Data(1...16)
        let attempt = try XCTUnwrap(UUID(uuidString: "01020304-0506-0708-090A-0B0C0D0E0F10"))
        let rootPublicKey = P256.Signing.PrivateKey().publicKey.compressedRepresentation
        let rootKey = SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-" + SHA256.hash(data: rootPublicKey).map { String(format: "%02x", $0) }.joined(),
            publicKeyCompressedSEC1: rootPublicKey, secureEnclaveAttestation: "not-asserted"
        )
        let bKey = Data(repeating: 0x12, count: 32).base64EncodedString()
        let hash = try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: operationID, correlation: presentation.correlation,
            reference: presentation.reference, hostChallenge: presentation.challenge)
        let apple = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: presentation.ceremonyID, siteTrustDomain: presentation.site,
            appleKeyID: bKey, clientDataHash: hash, attestationObject: Data([1, 2, 3]))
        let request = try SiteRootBrokerRegistrationWireV2.encode(
            presentation: presentation, operationID: operationID, siteRootKey: rootKey, appAttest: apple)
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        let pending = ScopedAppAttestPending(
            attemptID: attempt, correlation: presentation.correlation,
            registrationReference: presentation.reference, siteClaim: presentation.site,
            appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environmentClaim: "Production", keyID: bKey, preparedRegistration: request)
        try store.stage(pending)
        let authority = SyntheticBrokerAuthority()
        try store.markSubmitted(attemptID: attempt)
        XCTAssertNotNil(try store.submittedAttempt(attemptID: attempt))
        do {
            try await authority.sendThenLoseResponse(request)
            XCTFail("expected ambiguous delivery")
        } catch is CancellationError { }
        XCTAssertThrowsError(try store.cancel(attemptID: attempt))
        let restarted = ScopedAppAttestStore(persistence: persistence)
        XCTAssertEqual(try restarted.pending(attemptID: attempt), pending)
        let retainedRequest = await authority.acceptedBytes()
        XCTAssertEqual(retainedRequest, request)
        XCTAssertNil(try restarted.binding(installationID: Data(repeating: 2, count: 16)))
        XCTAssertEqual(try restarted.reference(for: .legacy) { "legacy-a" }, "legacy-a")
        XCTAssertNil(try restarted.reference(for: .installation(Data(repeating: 2, count: 16))) { "legacy-a" })
        let sentCount = await authority.submissionCount()
        XCTAssertEqual(sentCount, 1)
    }

    func testNeverSubmittedCancellationCannotBecomeSubmitted() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        let id = UUID()
        let pending = ScopedAppAttestPending(
            attemptID: id, correlation: Data(repeating: 3, count: 32), registrationReference: "test",
            siteClaim: "site-b", appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environmentClaim: "Production", keyID: Data(repeating: 4, count: 32).base64EncodedString(),
            preparedRegistration: Data([1]))
        try store.stage(pending)
        try store.cancel(attemptID: id)
        XCTAssertThrowsError(try store.markSubmitted(attemptID: id))
        XCTAssertEqual(try store.reference(for: .legacy) { "legacy-a" }, "legacy-a")
    }
}

private actor SyntheticBrokerAuthority {
    private var exactRequest: Data?
    private var sends = 0
    func sendThenLoseResponse(_ request: Data) throws {
        sends += 1
        exactRequest = request
        throw CancellationError()
    }
    func acceptedBytes() -> Data? { exactRequest }
    func submissionCount() -> Int { sends }
}
