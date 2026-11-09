import Foundation
import XCTest
import PistisCore
@testable import Pistis

final class FirstDeviceAdmissionPolicyTests: XCTestCase {
    func testAdditionalBRequiresExactSubmittedBindingAndNeverReplacesA() throws {
        let a = Data(repeating: 0x11, count: 16)
        let b = Data(repeating: 0x22, count: 16)
        let digest = Data(repeating: 0x33, count: 32)
        let attempt = UUID()
        let accepted = AdditionalEnrolmentAdmission.testOnly(
            attemptID: attempt, installationID: b, presentationDigest: digest)
        XCTAssertNil(try FirstDeviceAdmissionPolicy.additionalAttempt(
            installationID: b, presentationDigest: digest, existingIDs: [], admission: nil, pendingIsSubmitted: false))
        XCTAssertThrowsError(try FirstDeviceAdmissionPolicy.additionalAttempt(
            installationID: b, presentationDigest: digest, existingIDs: [a], admission: nil, pendingIsSubmitted: false))
        XCTAssertThrowsError(try FirstDeviceAdmissionPolicy.additionalAttempt(
            installationID: b, presentationDigest: digest, existingIDs: [a], admission: accepted, pendingIsSubmitted: false))
        XCTAssertEqual(try FirstDeviceAdmissionPolicy.additionalAttempt(
            installationID: b, presentationDigest: digest, existingIDs: [a], admission: accepted, pendingIsSubmitted: true), attempt)
        XCTAssertThrowsError(try FirstDeviceAdmissionPolicy.additionalAttempt(
            installationID: a, presentationDigest: digest, existingIDs: [a], admission: accepted, pendingIsSubmitted: true))
        XCTAssertThrowsError(try FirstDeviceAdmissionPolicy.additionalAttempt(
            installationID: b, presentationDigest: Data(repeating: 0x44, count: 32),
            existingIDs: [a], admission: accepted, pendingIsSubmitted: true))
        XCTAssertThrowsError(try FirstDeviceAdmissionPolicy.additionalAttempt(
            installationID: Data(repeating: 0x55, count: 16), presentationDigest: digest,
            existingIDs: [a], admission: accepted, pendingIsSubmitted: true))
    }
    @MainActor
    func testScannedSignedV4UsesControlledSubmittedAttemptWithoutReplacingA() async throws {
        let fixtureURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../fixtures/protocol-v4/first-device/presentation-positive.json")
            .standardizedFileURL
        let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [String: Any])
        let qr = try XCTUnwrap(fixture["qr_text"] as? String)
        let ms = try XCTUnwrap(fixture["now_ms"] as? NSNumber)
        let now = Date(timeIntervalSince1970: ms.doubleValue / 1_000)
        let presentation = try FirstDevicePresentationV4.verify(
            qrText: qr, expectedAppConfigurationDigest: GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest,
            now: now)
        let a = Data(repeating: 0xa1, count: 16)
        XCTAssertNotEqual(a, presentation.installationID)
        let attempt = UUID()
        let persistence = ScopedMemoryPersistence()
        let storage = ScopedAppAttestStore(persistence: persistence)
        let pending = ScopedAppAttestPending(
            attemptID: attempt, correlation: Data(repeating: 0x55, count: 32), registrationReference: "fixture",
            siteClaim: "fixture-site", appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environmentClaim: "Production", keyID: Data(repeating: 0x22, count: 32).base64EncodedString(),
            preparedRegistration: Data([1]))
        try storage.stage(pending); try storage.markSubmitted(attemptID: attempt)
        var admissionCalls = 0
        let flow = FirstDeviceEnrolmentFlow(
            testingScopedStore: storage,
            additionalAdmission: { scanned in
                admissionCalls += 1
                return .testOnly(attemptID: attempt, installationID: scanned.installationID,
                          presentationDigest: scanned.presentationDigest)
            }, now: { now }, eventRecorder: AdmissionEventSink())
        flow.handleScan(.success(ScannedQRPayload(text: qr)))
        XCTAssertNotNil(flow.presentation)
        let decision = try await flow.testOnlyResolveScannedAdmission(existingIDs: [a])
        XCTAssertEqual(decision, attempt)
        XCTAssertEqual(try storage.pending(attemptID: attempt), pending)
        XCTAssertNil(try storage.binding(installationID: presentation.installationID))
        let callsBeforeDuplicate = admissionCalls
        do {
            _ = try await flow.testOnlyResolveScannedAdmission(existingIDs: [a, presentation.installationID])
            XCTFail("duplicate installation accepted")
        } catch { XCTAssertEqual(error as? PlatformFailure, .siteRootBindingUnavailable) }
        XCTAssertEqual(admissionCalls, callsBeforeDuplicate)
    }

}

private final class AdmissionEventSink: OnboardingEventRecording {
    func append(_: OnboardingEvent) throws {}
}
