import Foundation
import XCTest
@testable import Pistis

private struct MTGSRecoveryServiceStub: MTGSRecoveryExecuting {
    let failure: PlatformFailure?
    func execute(_: MTGSRecoveryPresentationV1) async throws {
        if let failure { throw failure }
    }
}

@MainActor
final class MTGSRecoveryCoordinatorTests: XCTestCase {
    private let origin = URL(string: "https://monas.example.test")!

    func testSuccessfulAttendedRecoveryRecordsTerminalHistory() async throws {
        var events: [HistoryEvent] = []
        let coordinator = MTGSRecoveryCoordinator(
            authorityOrigin: origin,
            service: MTGSRecoveryServiceStub(failure: nil),
            history: { events.append($0) }
        )
        coordinator.accept(qrText: invitation(), nowUnixSeconds: 1_050)
        guard case .review = coordinator.phase else { return XCTFail("missing review") }
        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .submitted)
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].action, "Site Trust MTGS recovery")
        XCTAssertEqual(events[0].decision, "Verified")
        XCTAssertTrue(events[0].signature.contains("Face ID"))
        XCTAssertTrue(events[0].transfer.contains("Submitted once"))
    }

    func testFailedAssertionRecordsFailureWithoutSuccess() async throws {
        var events: [HistoryEvent] = []
        let coordinator = MTGSRecoveryCoordinator(
            authorityOrigin: origin,
            service: MTGSRecoveryServiceStub(failure: .appAttestAssertionFailed),
            history: { events.append($0) }
        )
        coordinator.accept(qrText: invitation(), nowUnixSeconds: 1_050)
        await coordinator.approve()
        XCTAssertEqual(coordinator.phase, .failed(.appAttestAssertionFailed))
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].decision, "Not completed")
        XCTAssertFalse(events[0].signature.contains("accepted"))
    }

    func testInvalidInvitationRecordsFailureAndNeverPresentsReview() {
        var events: [HistoryEvent] = []
        let coordinator = MTGSRecoveryCoordinator(
            authorityOrigin: origin,
            service: MTGSRecoveryServiceStub(failure: nil),
            history: { events.append($0) }
        )
        coordinator.accept(
            qrText: invitation().replacingOccurrences(
                of: MTGSRecoveryPresentationV1.audience, with: "monas-local"
            ), nowUnixSeconds: 1_050
        )
        XCTAssertEqual(coordinator.phase, .failed(.qrPayloadUnsupported))
        XCTAssertNil(coordinator.presentedReview)
        XCTAssertEqual(events.map(\.decision), ["Not completed"])
    }

    private func invitation() -> String {
        func encoded(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return """
        {"app_identifier":"C7A6NQTSY4.org.mnemosynebiosciences.pistis","audience":"monas:site-trust:mtgs-recovery:v1","authority_origin":"https://monas.example.test","ceremony_id_b64url":"\(encoded(Data(repeating: 1, count: 16)))","challenge_digest_b64url":"\(encoded(Data(repeating: 2, count: 32)))","expires_at_unix_seconds":1100,"issued_at_unix_seconds":1000,"key_id_b64url":"\(encoded(Data(repeating: 3, count: 32)))","reference":"mtgs-recovery-1234","schema":"monas.site-trust-mtgs-recovery-presentation.v1","site_trust_domain":"site-1234"}
        """
    }
}
