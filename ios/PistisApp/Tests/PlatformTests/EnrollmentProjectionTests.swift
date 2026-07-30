import Foundation
import PistisCore
import XCTest
@testable import Pistis

@MainActor
final class EnrollmentProjectionTests: XCTestCase {
    func testEmptyRepositoryProjectsEmptyHomeScreens() async {
        let store = EnrollmentProjectionStore { nil }

        await store.refresh()

        XCTAssertEqual(store.state, .loaded(.empty))
    }

    func testVerifiedEnrollmentProjectsOnlyPublicHomeScreenFacts() async throws {
        let enrollment = try fixtureEnrollment()
        let store = EnrollmentProjectionStore { enrollment }

        await store.refresh()

        guard case let .loaded(projection) = store.state else {
            return XCTFail("verified enrollment was not loaded")
        }
        XCTAssertEqual(projection.identities.count, 1)
        XCTAssertEqual(projection.identities[0].provider, "GitHub")
        XCTAssertEqual(projection.identities[0].displayName, "GitHub account")
        XCTAssertEqual(projection.identities[0].stableSubject, "Identity 0303030303030303")
        XCTAssertEqual(projection.identities[0].status, "Enrolled")
        XCTAssertFalse(projection.identities[0].allowsLocalForget)
        XCTAssertEqual(projection.installations.count, 1)
        XCTAssertEqual(projection.installations[0].name, "Laboratory Jenkins")
        XCTAssertEqual(projection.installations[0].localAlias, "pistis.example.test")
        XCTAssertEqual(
            projection.installations[0].fingerprint,
            "0404 0404 0404 0404 0404 0404 0404 0404"
        )
        XCTAssertEqual(projection.installations[0].status, "Trusted")
        XCTAssertFalse(projection.installations[0].allowsLocalForget)
        XCTAssertEqual(projection.history.count, 1)
        XCTAssertEqual(projection.history[0].action, "Device enrolled")
        XCTAssertEqual(projection.history[0].decision, "Verified")
        XCTAssertEqual(
            projection.history[0].occurredAt,
            "Exact time not retained locally"
        )
        XCTAssertFalse(
            String(describing: projection).contains(
                enrollment.trust.authorityReceipt.base64EncodedString()
            )
        )
    }

    func testRepositoryFailureIsNotPresentedAsEmptyEnrollment() async {
        let store = EnrollmentProjectionStore {
            throw ProjectionTestFailure.unavailable
        }

        await store.refresh()

        XCTAssertEqual(store.state, .failed)
    }

    func testExpiredEnrollmentRemainsVisibleButIsNotTrusted() throws {
        let projection = EnrollmentProjection(
            enrollment: try fixtureEnrollment(expiresAt: Date(timeIntervalSince1970: 100)),
            now: Date(timeIntervalSince1970: 101)
        )

        XCTAssertEqual(projection.identities[0].status, "Expired")
        XCTAssertTrue(projection.identities[0].allowsLocalForget)
        XCTAssertEqual(projection.installations[0].status, "Expired")
        XCTAssertTrue(projection.installations[0].allowsLocalForget)
        XCTAssertEqual(projection.history[0].decision, "Verified")
    }

    func testRetainedHistorySurvivesWithoutAnEnrollmentRecord() {
        let event = HistoryEvent(
            id: UUID(),
            action: "Local installation record forgotten",
            installation: "Laboratory Jenkins",
            occurredAt: "30 Jul 2026",
            decision: "Completed locally",
            signature: "No authority action requested",
            transfer: "No server state changed",
            verification: "Expired trust and local device key removed"
        )

        let projection = EnrollmentProjection(retainedHistory: [event])

        XCTAssertTrue(projection.identities.isEmpty)
        XCTAssertTrue(projection.installations.isEmpty)
        XCTAssertEqual(projection.history, [event])
    }

    func testLocalForgetPolicyNeverAllowsCurrentActiveTrust() {
        let now = Date(timeIntervalSince1970: 1_000)

        XCTAssertFalse(
            InstallationTrustKeychain.allowsLocalForget(
                active: true,
                expiresAt: Date(timeIntervalSince1970: 1_001),
                now: now
            )
        )
        XCTAssertTrue(
            InstallationTrustKeychain.allowsLocalForget(
                active: true,
                expiresAt: now,
                now: now
            )
        )
        XCTAssertTrue(
            InstallationTrustKeychain.allowsLocalForget(
                active: false,
                expiresAt: Date(timeIntervalSince1970: 1_001),
                now: now
            )
        )
    }

    func testLocalForgetRemovesTrustBeforeTheDeviceKey() async throws {
        var steps: [String] = []

        let keyRemoved = try await LocalForgetTransaction.run(
            removeTrust: { steps.append("trust") },
            removeKey: { steps.append("key") }
        )

        XCTAssertTrue(keyRemoved)
        XCTAssertEqual(steps, ["trust", "key"])
    }

    func testDeviceKeyFailureCannotRetainExpiredTrust() async throws {
        enum ExpectedFailure: Error { case keyUnavailable }
        var steps: [String] = []

        let keyRemoved = try await LocalForgetTransaction.run(
            removeTrust: { steps.append("trust") },
            removeKey: {
                steps.append("key")
                throw ExpectedFailure.keyUnavailable
            }
        )

        XCTAssertFalse(keyRemoved)
        XCTAssertEqual(steps, ["trust", "key"])
    }

    private func fixtureEnrollment(
        expiresAt: Date = Date(timeIntervalSince1970: 2_000_000_000)
    ) throws -> AuthenticatedEnrollmentOutput {
        try AuthenticatedEnrollmentOutput(
            trust: InstallationTrustRecord(
                installationID: Data(repeating: 0x01, count: 16),
                displayName: "Laboratory Jenkins",
                audience: "prosopikon:pistis:enrolment",
                authorisedProductAudiences: ["jenkins"],
                userID: Data(repeating: 0x02, count: 16),
                externalIdentityID: Data(repeating: 0x03, count: 16),
                fingerprint: Data(repeating: 0x04, count: 32),
                installationKeyID: Data(repeating: 0x05, count: 32),
                installationPublicKey: Data([0x02]) + Data(repeating: 0x06, count: 32),
                authorityKeyID: Data(repeating: 0x07, count: 32),
                authorityReceipt: Data(repeating: 0x08, count: 64),
                policyGeneration: 2,
                revocationGeneration: 3,
                expiresAt: expiresAt,
                active: true
            ),
            responseContext: DeviceResponseContext(
                deviceID: Data(repeating: 0x09, count: 16),
                deviceKeyID: Data(repeating: 0x0a, count: 32),
                userID: Data(repeating: 0x02, count: 16),
                externalIdentityID: Data(repeating: 0x03, count: 16)
            ),
            allowedHosts: ["pistis.example.test"]
        )
    }
}

private enum ProjectionTestFailure: Error {
    case unavailable
}
