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
        let store = EnrollmentProjectionStore { .current(enrollment) }

        await store.refresh()

    guard case .loaded(let projection) = store.state else {
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

    func testLegacyEnrollmentIsVisibleButCannotAuthorise() throws {
        let legacy = try fixtureLegacyEnrollment()
        let encoded = try JSONEncoder().encode(legacy)
        let inventory = try InstallationTrustKeychain.decodeInventory(encoded)

        XCTAssertEqual(inventory, .legacy(legacy))
        XCTAssertNil(
            InstallationTrustKeychain.currentEnrollment(from: inventory)
        )

        let projection = EnrollmentProjection(inventory: inventory)
        XCTAssertEqual(
            projection.identities[0].status,
            "Re-enrolment required"
        )
        XCTAssertTrue(projection.identities[0].allowsLocalForget)
        XCTAssertEqual(
            projection.installations[0].status,
            "Re-enrolment required"
        )
        XCTAssertTrue(projection.installations[0].allowsLocalForget)
        XCTAssertEqual(projection.history[0].action, "Legacy enrolment detected")
    }

    func testLegacyRemovalRequiresBothExactIdentifiers() throws {
        let legacy = try fixtureLegacyEnrollment()

        XCTAssertTrue(
            InstallationTrustKeychain.matchesLegacyRemoval(
                legacy,
                installationID: legacy.trust.installationID,
                externalIdentityID: legacy.trust.externalIdentityID
            )
        )
        XCTAssertFalse(
            InstallationTrustKeychain.matchesLegacyRemoval(
                legacy,
                installationID: Data(repeating: 0xff, count: 16),
                externalIdentityID: legacy.trust.externalIdentityID
            )
        )
        XCTAssertFalse(
            InstallationTrustKeychain.matchesLegacyRemoval(
                legacy,
                installationID: legacy.trust.installationID,
                externalIdentityID: Data(repeating: 0xff, count: 16)
            )
        )
    }

    func testMixedAndUnknownLegacyProfilesFailClosed() throws {
        let legacyData = try JSONEncoder().encode(fixtureLegacyEnrollment())
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: legacyData) as? [String: Any]
        )
        var trust = try XCTUnwrap(object["trust"] as? [String: Any])
        trust["authorisedProductAudiences"] = ["jenkins"]
        object["trust"] = trust
        XCTAssertThrowsError(
            try InstallationTrustKeychain.decodeInventory(
                JSONSerialization.data(withJSONObject: object)
            )
        )

        object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: legacyData) as? [String: Any]
        )
        object["unexpected"] = true
        XCTAssertThrowsError(
            try InstallationTrustKeychain.decodeInventory(
                JSONSerialization.data(withJSONObject: object)
            )
        )
    }

    func testCurrentStorageProfileIsExplicitAndClosed() throws {
        let current = try fixtureEnrollment()
        let data = try JSONEncoder().encode(current)
        XCTAssertEqual(
            try InstallationTrustKeychain.decodeInventory(data),
            .current(current)
        )

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        object["storageProfile"] = 1
        XCTAssertThrowsError(
            try InstallationTrustKeychain.decodeInventory(
                JSONSerialization.data(withJSONObject: object)
            )
        )
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

    func testCompletedSiteRootCeremonyProjectsAnIncompleteInstallationOnly() throws {
        let installation = try IncompleteSiteRootInstallation(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            authorityHost: "monas.example.test",
            redactedReference: "abc123…def4",
            recordedAt: Date(timeIntervalSince1970: 1_000)
        )

        let projection = EnrollmentProjection(
            retainedHistory: [],
            incompleteSiteRootInstallations: [installation]
        )

        XCTAssertTrue(projection.identities.isEmpty)
        XCTAssertEqual(projection.installations.count, 1)
        XCTAssertEqual(projection.installations[0].name, "Monas Site Root")
        XCTAssertEqual(projection.installations[0].status, "Setup in progress")
        XCTAssertEqual(
            projection.installations[0].evidenceLabel,
            "Verified ceremony reference"
        )
        XCTAssertFalse(projection.installations[0].allowsLocalForget)
        XCTAssertNotEqual(projection.installations[0].status, "Trusted")
    }

    func testIncompleteSiteRootInstallationDoesNotChangeTrustedEnrollment() throws {
        let incomplete = try IncompleteSiteRootInstallation(
            authorityHost: "monas.example.test",
            redactedReference: "abc123…def4",
            recordedAt: Date(timeIntervalSince1970: 1_000)
        )
        let projection = EnrollmentProjection(
            enrollment: try fixtureEnrollment(),
            incompleteSiteRootInstallations: [incomplete]
        )

        XCTAssertEqual(projection.installations.count, 2)
        XCTAssertEqual(
            projection.installations.filter { $0.status == "Trusted" }.count,
            1
        )
        XCTAssertEqual(
            projection.installations.filter { $0.status == "Setup in progress" }.count,
            1
        )
    }

  func testMatchingSetupProgressCoalescesWithAuthenticatedInstallation() throws {
    let incomplete = try IncompleteSiteRootInstallation(
      authorityHost: "PISTIS.EXAMPLE.TEST.", redactedReference: "abc123…def4",
      setupPhase: .identityEnrolmentRequired
    )
    let projection = EnrollmentProjection(
      enrollment: try fixtureEnrollment(),
      incompleteSiteRootInstallations: [incomplete]
    )

    XCTAssertEqual(projection.installations.count, 1)
    XCTAssertEqual(projection.identities.count, 1)
    XCTAssertNil(projection.installations[0].setupPhase)
    XCTAssertEqual(projection.installations[0].status, "Trusted")
    XCTAssertEqual(InstallationDetailAction(installation: projection.installations[0]), .none)
  }

    func testLegacySetupProgressRequiresAuthorityCustodyBeforeIdentity() throws {
        let installation = try IncompleteSiteRootInstallation(
            authorityHost: "monas.example.test",
            redactedReference: "abc123…def4",
            recordedAt: Date(timeIntervalSince1970: 1_000)
        )
        let projection = EnrollmentProjection(
            retainedHistory: [],
            incompleteSiteRootInstallations: [installation]
        )

        XCTAssertEqual(
            InstallationDetailAction(installation: try XCTUnwrap(projection.installations.first)),
            .continueAuthorityCustody
        )
    }

    func testCompletedAuthorityCustodyOffersIdentityContinuation() throws {
        let installation = try IncompleteSiteRootInstallation(
            authorityHost: "monas.example.test", redactedReference: "abc123…def4",
            setupPhase: .identityEnrolmentRequired
        )
        let projection = EnrollmentProjection(
            retainedHistory: [], incompleteSiteRootInstallations: [installation]
        )
        XCTAssertEqual(
            InstallationDetailAction(installation: try XCTUnwrap(projection.installations.first)),
            .continueIdentitySetup
        )
    }

    func testTrustedInstallationDoesNotOfferIdentitySetupContinuation() throws {
        let projection = EnrollmentProjection(enrollment: try fixtureEnrollment())

        XCTAssertEqual(
            InstallationDetailAction(installation: try XCTUnwrap(projection.installations.first)),
            .none
        )
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

    private func fixtureLegacyEnrollment() throws
        -> LegacyAuthenticatedEnrollmentOutput
    {
        try LegacyAuthenticatedEnrollmentOutput(
            trust: LegacyInstallationTrustRecord(
                installationID: Data(repeating: 0x11, count: 16),
                displayName: "Legacy laboratory",
                audience: "prosopikon:pistis:enrolment",
                userID: Data(repeating: 0x12, count: 16),
                externalIdentityID: Data(repeating: 0x13, count: 16),
                fingerprint: Data(repeating: 0x14, count: 32),
                installationKeyID: Data(repeating: 0x15, count: 32),
                installationPublicKey: Data([0x02])
                    + Data(repeating: 0x16, count: 32),
                authorityKeyID: Data(repeating: 0x17, count: 32),
                authorityReceipt: Data(repeating: 0x18, count: 64),
                policyGeneration: 1,
                revocationGeneration: 1,
                expiresAt: Date(timeIntervalSince1970: 2_000_000_000),
                active: true
            ),
            responseContext: DeviceResponseContext(
                deviceID: Data(repeating: 0x19, count: 16),
                deviceKeyID: Data(repeating: 0x1a, count: 32),
                userID: Data(repeating: 0x12, count: 16),
                externalIdentityID: Data(repeating: 0x13, count: 16)
            ),
            allowedHosts: ["legacy.example.test"]
        )
    }
}

private enum ProjectionTestFailure: Error {
    case unavailable
}
