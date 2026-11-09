import Foundation
import XCTest
import PistisCore
@testable import Pistis

final class ScopedAppAttestStoreTests: XCTestCase {
    private let key = Data(repeating: 0x11, count: 32).base64EncodedString()

    private func pending(_ id: UUID, site: String = "site-b") -> ScopedAppAttestPending {
        ScopedAppAttestPending(attemptID: id, correlation: Data(repeating: 0x44, count: 32),
                               registrationReference: "reference-b", siteClaim: site,
                               appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
                               environmentClaim: "Production", keyID: key,
                               preparedRegistration: Data([1, 2, 3]))
    }
    private func binding(_ id: UUID, installation: UInt8 = 2) -> ScopedAppAttestBinding {
        ScopedAppAttestBinding(attemptID: id, installationID: Data(repeating: installation, count: 16),
                               site: "site-b", appIdentifier: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
                               environment: "Production", keyID: key, policyGeneration: 1, revocationGeneration: 1)
    }

    func testRetryRestartConflictAndDistinctInstallation() throws {
        let persistence = ScopedMemoryPersistence()
        let first = ScopedAppAttestStore(persistence: persistence)
        defer { try? first.resetAll() }
        let attempt = UUID()
        try first.stage(pending(attempt))
        try first.stage(pending(attempt))
        XCTAssertThrowsError(try first.stage(pending(attempt, site: "site-other")))
        let restarted = ScopedAppAttestStore(persistence: persistence)
        XCTAssertEqual(try restarted.pending(attemptID: attempt), pending(attempt))
        XCTAssertNil(try restarted.binding(installationID: Data(repeating: 1, count: 16)))
        try restarted.markSubmitted(attemptID: attempt)
        try restarted.commit(binding(attempt))
        try first.commit(binding(attempt))
        XCTAssertEqual(try first.binding(installationID: Data(repeating: 2, count: 16)), binding(attempt))
        XCTAssertNil(try first.pending(attemptID: attempt))
        XCTAssertThrowsError(try first.cancel(attemptID: attempt))
        XCTAssertThrowsError(try first.commit(binding(attempt, installation: 3)))
        XCTAssertNil(try first.binding(installationID: Data(repeating: 3, count: 16)))
        let other = UUID()
        try first.stage(pending(other))
        try first.markSubmitted(attemptID: other)
        XCTAssertThrowsError(try first.commit(binding(other)))
        XCTAssertEqual(try first.binding(installationID: Data(repeating: 2, count: 16)), binding(attempt))
    }

    func testCancellationIsAttemptScopedAndSurvivesRestart() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        defer { try? store.resetAll() }
        let cancelled = UUID(), retained = UUID()
        try store.stage(pending(cancelled)); try store.stage(pending(retained))
        try store.cancel(attemptID: cancelled)
        try store.cancel(attemptID: cancelled)
        let restarted = ScopedAppAttestStore(persistence: persistence)
        XCTAssertNil(try restarted.pending(attemptID: cancelled))
        XCTAssertEqual(try restarted.pending(attemptID: retained), pending(retained))
        XCTAssertThrowsError(try restarted.stage(pending(cancelled)))
        XCTAssertThrowsError(try restarted.commit(binding(cancelled)))
        try restarted.markSubmitted(attemptID: retained)
        try restarted.commit(binding(retained))
        try restarted.resetAll()
        XCTAssertNil(try store.binding(installationID: Data(repeating: 2, count: 16)))
        XCTAssertNil(try store.pending(attemptID: retained))
    }

    func testInterruptedCommitReconcilesAndCannotBeCancelled() throws {
        let persistence = ScopedMemoryPersistence()
        let first = ScopedAppAttestStore(persistence: persistence)
        let attempt = UUID()
        try first.stage(pending(attempt))
        try first.markSubmitted(attemptID: attempt)
        persistence.failNextCompletion = true
        XCTAssertThrowsError(try first.commit(binding(attempt)))
        let restarted = ScopedAppAttestStore(persistence: persistence)
        XCTAssertNil(try restarted.binding(installationID: Data(repeating: 2, count: 16)))
        XCTAssertThrowsError(try restarted.cancel(attemptID: attempt))
        XCTAssertThrowsError(try restarted.commit(binding(attempt, installation: 3)))
        try restarted.commit(binding(attempt))
        XCTAssertEqual(try restarted.binding(installationID: Data(repeating: 2, count: 16)), binding(attempt))
    }

    func testConcurrentAttemptsForSameInstallationDoNotOverwrite() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        let first = UUID(), second = UUID()
        try store.stage(pending(first)); try store.stage(pending(second))
        try store.markSubmitted(attemptID: first); try store.markSubmitted(attemptID: second)
        let choices = [binding(first), binding(second)]
        let results = ConcurrentResults()
        DispatchQueue.concurrentPerform(iterations: 2) { index in
            do { try store.commit(choices[index]); results.record(success: true) }
            catch { results.record(success: false) }
        }
        XCTAssertEqual(results.successes, 1)
        let stored = try XCTUnwrap(store.binding(installationID: choices[0].installationID))
        XCTAssertTrue(choices.contains(stored))
    }

    func testIndependentBindingsAndConflictingRetry() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        let b = UUID(), c = UUID()
        let cKey = Data(repeating: 0x22, count: 32).base64EncodedString()
        let cPending = ScopedAppAttestPending(
            attemptID: c, correlation: Data(repeating: 0x55, count: 32),
            registrationReference: "reference-c", siteClaim: "site-c",
            appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environmentClaim: "Production", keyID: cKey, preparedRegistration: Data([4])
        )
        let cBinding = ScopedAppAttestBinding(
            attemptID: c, installationID: Data(repeating: 3, count: 16), site: "site-c",
            appIdentifier: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environment: "Production", keyID: cKey, policyGeneration: 2, revocationGeneration: 3
        )
        try store.stage(pending(b)); try store.markSubmitted(attemptID: b); try store.commit(binding(b))
        try store.stage(cPending); try store.markSubmitted(attemptID: c); try store.commit(cBinding)
        XCTAssertEqual(try store.binding(installationID: binding(b).installationID), binding(b))
        XCTAssertEqual(try store.binding(installationID: cBinding.installationID), cBinding)
        var legacyReads = 0
        let bReference = try store.reference(for: .installation(binding(b).installationID)) {
            legacyReads += 1; return "legacy-a"
        }
        let cReference = try store.reference(for: .installation(cBinding.installationID)) {
            legacyReads += 1; return "legacy-a"
        }
        XCTAssertEqual(bReference, key); XCTAssertEqual(cReference, cKey); XCTAssertEqual(legacyReads, 0)
        XCTAssertThrowsError(try store.commit(binding(c)))
        XCTAssertEqual(try store.binding(installationID: cBinding.installationID), cBinding)
    }

    func testInterruptedCleanupAfterCommitIsSafeAndRetryable() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        let attempt = UUID()
        try store.stage(pending(attempt)); try store.markSubmitted(attemptID: attempt)
        persistence.failNextRemoval = true
        XCTAssertThrowsError(try store.commit(binding(attempt)))
        let restarted = ScopedAppAttestStore(persistence: persistence)
        XCTAssertEqual(try restarted.binding(installationID: binding(attempt).installationID), binding(attempt))
        try restarted.commit(binding(attempt))
        XCTAssertNil(try persistence.read(account: "pending." + attempt.uuidString))
        XCTAssertThrowsError(try restarted.cancel(attemptID: attempt))
    }

    func testSubmittedAttemptCannotBeLocallyCancelled() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        let attempt = UUID()
        try store.stage(pending(attempt))
        try store.markSubmitted(attemptID: attempt)
        try store.markSubmitted(attemptID: attempt)
        XCTAssertThrowsError(try store.cancel(attemptID: attempt))
        XCTAssertEqual(try store.pending(attemptID: attempt), pending(attempt))
        let restarted = ScopedAppAttestStore(persistence: persistence)
        XCTAssertThrowsError(try restarted.cancel(attemptID: attempt))
        XCTAssertEqual(try restarted.pending(attemptID: attempt), pending(attempt))
    }

    func testInterruptedCancellationRemovesOnlyExactPendingOnRetry() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        let cancelled = UUID(), retained = UUID()
        try store.stage(pending(cancelled)); try store.stage(pending(retained))
        persistence.failNextRemoval = true
        XCTAssertThrowsError(try store.cancel(attemptID: cancelled))
        let restarted = ScopedAppAttestStore(persistence: persistence)
        XCTAssertNil(try restarted.pending(attemptID: cancelled))
        XCTAssertThrowsError(try restarted.commit(binding(cancelled)))
        try restarted.cancel(attemptID: cancelled)
        XCTAssertEqual(try restarted.pending(attemptID: retained), pending(retained))
        XCTAssertNil(try persistence.read(account: "pending." + cancelled.uuidString))
    }

    func testReceiptStagingDoesNotPromoteOrSelectInstallation() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        let attempt = UUID()
        let receipt = ScopedStagedEnrollment(attemptID: attempt, output: try stagedOutput(marker: 2))
        XCTAssertThrowsError(try store.stageEnrollment(receipt))
        try store.stage(pending(attempt)); try store.markSubmitted(attemptID: attempt)
        try store.stageEnrollment(receipt); try store.stageEnrollment(receipt)
        XCTAssertEqual(try store.stagedEnrollment(attemptID: attempt), receipt)
        XCTAssertNil(try store.binding(installationID: receipt.output.trust.installationID))
        XCTAssertEqual(try store.reference(for: .legacy) { "legacy-a" }, "legacy-a")
        let conflict = ScopedStagedEnrollment(attemptID: attempt, output: try stagedOutput(marker: 3))
        XCTAssertThrowsError(try store.stageEnrollment(conflict))
        XCTAssertEqual(try store.stagedEnrollment(attemptID: attempt), receipt)
        let restarted = ScopedAppAttestStore(persistence: persistence)
        XCTAssertEqual(try restarted.stagedEnrollment(attemptID: attempt), receipt)
        try restarted.resetAll()
        XCTAssertNil(try restarted.stagedEnrollment(attemptID: attempt))
    }

    private func stagedOutput(marker: UInt8) throws -> AuthenticatedEnrollmentOutput {
        let user = Data(repeating: marker + 1, count: 16)
        let identity = Data(repeating: marker + 2, count: 16)
        let trust = try InstallationTrustRecord(
            installationID: Data(repeating: marker, count: 16), displayName: "Fixture",
            audience: "prosopikon:pistis:enrolment", authorisedProductAudiences: ["jenkins"],
            userID: user, externalIdentityID: identity, fingerprint: Data(repeating: 4, count: 32),
            installationKeyID: Data(repeating: 5, count: 32),
            installationPublicKey: Data([2]) + Data(repeating: 6, count: 32),
            authorityKeyID: Data(repeating: 7, count: 32), authorityReceipt: Data([8]),
            policyGeneration: 2, revocationGeneration: 3,
            expiresAt: Date(timeIntervalSince1970: 2_000_000_000), active: true)
        return try AuthenticatedEnrollmentOutput(
            trust: trust, responseContext: DeviceResponseContext(
                deviceID: Data(repeating: 9, count: 16), deviceKeyID: Data(repeating: 10, count: 32),
                userID: user, externalIdentityID: identity),
            allowedHosts: ["pistis.example.test"], httpsOrigin: "https://pistis.example.test",
            tlsSPKISHA256: Data(repeating: 11, count: 32))
    }

    func testScopedLookupNeverFallsBackToLegacy() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        defer { try? store.resetAll() }
        var legacyReads = 0
        func legacy() -> String? { legacyReads += 1; return "legacy-a" }
        XCTAssertEqual(try store.reference(for: .legacy, legacy: legacy), "legacy-a")
        XCTAssertNil(try store.reference(for: .installation(Data(repeating: 2, count: 16)), legacy: legacy))
        XCTAssertEqual(legacyReads, 1)
        let attempt = UUID()
        try store.stage(pending(attempt)); try store.markSubmitted(attemptID: attempt)
        try store.commit(binding(attempt))
        XCTAssertEqual(try store.reference(for: .installation(Data(repeating: 2, count: 16)), legacy: legacy), key)
        XCTAssertEqual(legacyReads, 1)
        XCTAssertEqual(try store.reference(for: .legacy, legacy: legacy), "legacy-a")
    }

    func testRejectsUnboundAndMalformedRecords() throws {
        let persistence = ScopedMemoryPersistence()
        let store = ScopedAppAttestStore(persistence: persistence)
        defer { try? store.resetAll() }
        let attempt = UUID()
        XCTAssertThrowsError(try store.commit(binding(attempt)))
        try store.stage(pending(attempt))
        try store.markSubmitted(attemptID: attempt)
        let wrong = ScopedAppAttestBinding(attemptID: attempt, installationID: Data(repeating: 2, count: 16),
                                           site: "other-site", appIdentifier: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
                                           environment: "Production", keyID: key, policyGeneration: 1, revocationGeneration: 1)
        XCTAssertThrowsError(try store.commit(wrong))
        XCTAssertEqual(try store.pending(attemptID: attempt), pending(attempt))
    }
}

final class ScopedMemoryPersistence: ScopedAppAttestPersistence {
    private var values: [String: Data] = [:]
    var failNextCompletion = false
    var failNextRemoval = false
    func read(account: String) throws -> Data? { values[account] }
    func add(account: String, data: Data) throws -> Bool {
        if account.hasPrefix("completed."), failNextCompletion {
            failNextCompletion = false
            throw PlatformFailure.appAttestKeyCreationFailed
        }
        guard values[account] == nil else { return false }
        values[account] = data
        return true
    }
    func entries() throws -> [(String, Data)] { values.map { ($0.key, $0.value) } }
    func remove(account: String) throws {
        if failNextRemoval { failNextRemoval = false; throw PlatformFailure.appAttestKeyCreationFailed }
        values.removeValue(forKey: account)
    }
    func removeAll() throws { values.removeAll() }
}

private final class ConcurrentResults: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func record(success: Bool) { lock.lock(); defer { lock.unlock() }; if success { count += 1 } }
    var successes: Int { lock.lock(); defer { lock.unlock() }; return count }
}
