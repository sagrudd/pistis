import CryptoKit
import Foundation
import PistisCore
import XCTest

@testable import Pistis

/// A deterministic, test-target-only model of the attended iPhone participant.
///
/// This simulator deliberately does not claim Secure Enclave, Face ID, or
/// Apple App Attest evidence. It drives the production QR parsers and routing
/// rules while modelling those hardware results as explicit test inputs. The
/// physical-device gate remains mandatory for release qualification.
struct MonasFirstWebLoginIPhoneSimulator {
    enum Stage: String, Equatable {
        case reset
        case hostAttached
        case browserIdentityAccepted
        case siteRootReviewed
        case siteRootBiometricAccepted
        case appAttestAccepted
        case siteRootCommitted
        case siteX509Reviewed
        case siteX509BiometricAccepted
        case siteX509Committed
        case authorityCustodyStatusChecked
        case authorityCustodyAppAttestAccepted
        case authorityCustodyReviewed
        case authorityCustodyBiometricAccepted
        case authorityCustodyCommitted
        case firstDeviceReviewed
        case providerIdentityVerified
        case providerIdentityConfirmed
        case deviceBiometricAccepted
        case identityReceiptInstalled
        case authorityActivated
        case monasLoginReviewed
        case monasLoginBiometricAccepted
        case monasSessionEstablished
        case productLoginReviewed
        case productLoginBiometricAccepted
        case productSessionEstablished
    }

    enum Failure: Error, Equatable {
        case outOfOrder
        case cancelled
        case biometricDenied
        case appAttestDenied
        case replay
        case wrongInstallation
        case wrongAudience
        case providerIdentityNotConfirmed
        case unsupportedQR
    }

    var stage: Stage = .reset
    var evidence: [String] = []
    private(set) var terminalFailure: Failure?
    private(set) var numericProviderSubject: UInt64?
    private var installationID: Data?
    private var seenQRDigests = Set<Data>()
    private var providerGate = AttendedEnrolmentGate()
    var authorityCustodyStatus: MonasSiteRootDelegationTransport.AuthorityCustodyStatusV2?
    var authorityCustodyCorrelation: Data?
    var authorityCustodyAcceptedSchema: String?

    mutating func attachHost() throws {
        try transition(from: .reset, to: .hostAttached, evidence: "host-attached")
    }

    mutating func acceptBrowserIdentity(numericSubject: UInt64) throws {
        guard numericSubject > 0 else { throw fail(.wrongInstallation) }
        self.numericProviderSubject = numericSubject
        try transition(
            from: .hostAttached,
            to: .browserIdentityAccepted,
            evidence: "browser-numeric-provider-subject-accepted"
        )
    }

    mutating func reviewSiteRoot(qrText: String, nowMilliseconds: UInt64) throws {
        try require(.browserIdentityAccepted)
        try consume(qrText)
        do {
            let presentation = try SiteRootGenesisRegistrationPresentationV1(
                qrText: qrText,
                authorityOrigins: [
                    URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin)!
                ],
                nowUnixMillis: nowMilliseconds,
                requireCorrelation: true
            )
            guard presentation.correlation != nil else { throw Failure.unsupportedQR }
        } catch let failure as Failure {
            throw fail(failure)
        } catch {
            throw fail(.unsupportedQR)
        }
        stage = .siteRootReviewed
        evidence.append("production-site-root-genesis-presentation-verified")
    }

    mutating func acceptSiteRootBiometric(_ accepted: Bool) throws {
        try simulatedBiometric(
            accepted,
            from: .siteRootReviewed,
            to: .siteRootBiometricAccepted,
            evidence: "simulated-site-root-biometric-accepted"
        )
    }

    mutating func acceptAppAttest(_ accepted: Bool) throws {
        try require(.siteRootBiometricAccepted)
        guard accepted else { throw fail(.appAttestDenied) }
        stage = .appAttestAccepted
        evidence.append("simulated-app-attest-registration-accepted")
    }

    mutating func commitSiteRoot() throws {
        try transition(
            from: .appAttestAccepted,
            to: .siteRootCommitted,
            evidence: "site-root-proof-and-delegation-accepted"
        )
    }

    mutating func reviewSiteX509(qrText: String, nowSeconds: UInt64) throws {
        try require(.siteRootCommitted)
        try consume(qrText)
        do {
            _ = try SiteX509FirstProvisionBrokerPresentationV1(
                qrText: qrText,
                nowUnixSeconds: nowSeconds
            )
        } catch {
            throw fail(.unsupportedQR)
        }
        stage = .siteX509Reviewed
        evidence.append("production-site-x509-broker-presentation-verified")
    }

    mutating func acceptSiteX509Biometric(_ accepted: Bool) throws {
        try simulatedBiometric(
            accepted,
            from: .siteX509Reviewed,
            to: .siteX509BiometricAccepted,
            evidence: "simulated-site-x509-biometric-accepted"
        )
    }

    mutating func commitSiteX509() throws {
        try transition(
            from: .siteX509BiometricAccepted,
            to: .siteX509Committed,
            evidence: "site-x509-custody-and-paired-leaf-accepted"
        )
    }

    mutating func reviewFirstDevice(qrText: String, now: Date) throws {
        try require(.authorityCustodyCommitted)
        try consume(qrText)
        guard GenericScanRoute.classify(qrText, now: now) == .firstDeviceEnrolment else {
            throw fail(.unsupportedQR)
        }
        do {
            let presentation = try FirstDevicePresentationV4.verify(
                qrText: qrText,
                expectedAppConfigurationDigest:
                    GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest,
                now: now
            )
            installationID = presentation.installationID
        } catch {
            throw fail(.unsupportedQR)
        }
        stage = .firstDeviceReviewed
        evidence.append("production-first-device-presentation-verified")
    }

    mutating func verifyProviderIdentity(
        numericSubject: UInt64,
        challengeExpiry: UInt64
    ) throws {
        try require(.firstDeviceReviewed)
        guard numericSubject == numericProviderSubject else {
            throw fail(.wrongInstallation)
        }
        let approval = VerifiedProviderApproval(
            subject: numericSubject,
            login: "display-data-is-not-authority",
            policyGeneration: 1,
            authorityChallenge: Data(repeating: 0x66, count: 32),
            challengeExpiry: challengeExpiry
        )
        providerGate.recordProviderVerification(approval)
        stage = .providerIdentityVerified
        evidence.append("numeric-provider-subject-verified")
    }

    mutating func confirmProviderIdentity() throws {
        try require(.providerIdentityVerified)
        _ = try providerGate.takeForExplicitConfirmation()
        stage = .providerIdentityConfirmed
        evidence.append("explicit-provider-account-confirmation")
    }

    mutating func acceptDeviceBiometric(_ accepted: Bool) throws {
        try simulatedBiometric(
            accepted,
            from: .providerIdentityConfirmed,
            to: .deviceBiometricAccepted,
            evidence: "simulated-device-binding-biometric-accepted"
        )
    }

    mutating func installIdentityReceipt(for installationID: Data) throws {
        try require(.deviceBiometricAccepted)
        guard installationID == self.installationID else {
            throw fail(.wrongInstallation)
        }
        providerGate.markInstalled()
        guard providerGate.state == .installed else {
            throw fail(.providerIdentityNotConfirmed)
        }
        stage = .identityReceiptInstalled
        evidence.append("signed-first-device-receipt-installed")
    }

    mutating func activateAuthority() throws {
        try transition(
            from: .identityReceiptInstalled,
            to: .authorityActivated,
            evidence: "bootstrap-retired-and-production-authority-activated"
        )
    }

    mutating func reviewMonasLogin(
        qrText: String,
        trust: InstallationTrustRecord,
        expectedExternalIdentityID: Data,
        now: Date
    ) async throws {
        try require(.authorityActivated)
        try consume(qrText)
        guard GenericScanRoute.classify(qrText) == .ordinaryAuthentication else {
            throw fail(.unsupportedQR)
        }
        let verified: VerifiedAuthenticationChallenge
        do {
            verified = try await ProductionChallengeVerifier.verify(
                qrText: qrText,
                trustRepository: SimulatorTrust(record: trust),
                expectedExternalIdentityID: expectedExternalIdentityID,
                now: now
            )
        } catch ProductionCeremonyError.wrongAudience {
            throw fail(.wrongAudience)
        } catch ProductionCeremonyError.unknownInstallation {
            throw fail(.wrongInstallation)
        } catch {
            throw fail(.unsupportedQR)
        }
        guard verified.installationID == installationID else {
            throw fail(.wrongInstallation)
        }
        guard verified.audience == "propylaion" else { throw fail(.wrongAudience) }
        stage = .monasLoginReviewed
        evidence.append("production-signed-propylaion-home-challenge-verified")
    }

    mutating func acceptMonasLoginBiometric(_ accepted: Bool) throws {
        try simulatedBiometric(
            accepted,
            from: .monasLoginReviewed,
            to: .monasLoginBiometricAccepted,
            evidence: "simulated-monas-login-biometric-accepted"
        )
    }

    mutating func establishMonasSession(
        installationID: Data,
        audience: String,
        redirectedPath: String
    ) throws {
        try require(.monasLoginBiometricAccepted)
        guard installationID == self.installationID else {
            throw fail(.wrongInstallation)
        }
        guard audience == "propylaion", redirectedPath == "/home" else {
            throw fail(.wrongAudience)
        }
        stage = .monasSessionEstablished
        evidence.append("verified-monas-session-established-at-home")
    }

    mutating func reviewProductLogin(
        qrText: String,
        trust: InstallationTrustRecord,
        expectedExternalIdentityID: Data,
        now: Date
    ) async throws {
        try require(.monasSessionEstablished)
        try consume(qrText)
        guard GenericScanRoute.classify(qrText) == .ordinaryAuthentication else {
            throw fail(.unsupportedQR)
        }
        let verified: VerifiedAuthenticationChallenge
        do {
            verified = try await ProductionChallengeVerifier.verify(
                qrText: qrText,
                trustRepository: SimulatorTrust(record: trust),
                expectedExternalIdentityID: expectedExternalIdentityID,
                now: now
            )
        } catch ProductionCeremonyError.wrongAudience {
            throw fail(.wrongAudience)
        } catch ProductionCeremonyError.unknownInstallation {
            throw fail(.wrongInstallation)
        } catch {
            throw fail(.unsupportedQR)
        }
        guard verified.installationID == installationID else {
            throw fail(.wrongInstallation)
        }
        guard verified.audience == "dasobjectstore" else {
            throw fail(.wrongAudience)
        }
        stage = .productLoginReviewed
        evidence.append("production-signed-dasobjectstore-challenge-verified")
    }

    mutating func acceptProductLoginBiometric(_ accepted: Bool) throws {
        try simulatedBiometric(
            accepted,
            from: .productLoginReviewed,
            to: .productLoginBiometricAccepted,
            evidence: "simulated-dasobjectstore-login-biometric-accepted"
        )
    }

    mutating func establishProductSession(
        installationID: Data,
        audience: String
    ) throws {
        try require(.productLoginBiometricAccepted)
        guard installationID == self.installationID else {
            throw fail(.wrongInstallation)
        }
        guard audience == "dasobjectstore" else { throw fail(.wrongAudience) }
        stage = .productSessionEstablished
        evidence.append("exact-audience-dasobjectstore-session-established")
    }

    mutating func cancel() {
        terminalFailure = .cancelled
    }

    mutating func simulatedBiometric(
        _ accepted: Bool,
        from expected: Stage,
        to next: Stage,
        evidence value: String
    ) throws {
        try require(expected)
        guard accepted else { throw fail(.biometricDenied) }
        stage = next
        evidence.append(value)
    }

    private mutating func transition(
        from expected: Stage,
        to next: Stage,
        evidence value: String
    ) throws {
        try require(expected)
        stage = next
        evidence.append(value)
    }

    private mutating func consume(_ qrText: String) throws {
        let digest = Data(SHA256.hash(data: Data(qrText.utf8)))
        guard seenQRDigests.insert(digest).inserted else { throw fail(.replay) }
    }

    mutating func require(_ expected: Stage) throws {
        guard terminalFailure == nil else { throw terminalFailure! }
        guard stage == expected else { throw fail(.outOfOrder) }
    }

    mutating func fail(_ failure: Failure) -> Failure {
        terminalFailure = failure
        return failure
    }
}

final class MonasFirstWebLoginIPhoneSimulatorTests: XCTestCase {
    private let nowMilliseconds: UInt64 = 1_700_000_060_000
    private var nowSeconds: UInt64 { nowMilliseconds / 1_000 }
    private var now: Date { Date(timeIntervalSince1970: Double(nowMilliseconds) / 1_000) }
    private let numericSubject: UInt64 = 3_848_500
    private let installationID = Data(repeating: 0x22, count: 16)

    func testCompleteFirstInstallMonasLoginAndDASObjectStoreAudienceFlow() async throws {
        var simulator = MonasFirstWebLoginIPhoneSimulator()
        let monasLogin = try SimulatorAuthenticationFixture(
            installationID: installationID,
            audience: "propylaion",
            authorisedAudiences: ["propylaion", "dasobjectstore"]
        )
        let productLogin = try SimulatorAuthenticationFixture(
            installationID: installationID,
            audience: "dasobjectstore",
            authorisedAudiences: ["propylaion", "dasobjectstore"]
        )

        try simulator.attachHost()
        try simulator.acceptBrowserIdentity(numericSubject: numericSubject)
        try simulator.reviewSiteRoot(qrText: siteRootQR(), nowMilliseconds: nowMilliseconds)
        try simulator.acceptSiteRootBiometric(true)
        try simulator.acceptAppAttest(true)
        try simulator.commitSiteRoot()
        try simulator.reviewSiteX509(qrText: siteX509QR(), nowSeconds: nowSeconds)
        try simulator.acceptSiteX509Biometric(true)
        try simulator.commitSiteX509()
        let custody = try MonasFirstWebLoginCustodySimulatorFixture(
            mode: .rotation,
            expiresAtUnixSeconds: nowSeconds + 120
        )
        try simulator.observeAuthorityCustodyStatus(.appAttestAssertionRequired)
        try simulator.acceptAuthorityCustodyAppAttest(
            true,
            observedLifecycle: .initialRotationRequired
        )
        try simulator.reviewAuthorityCustody(
            fixture: custody,
            nowUnixSeconds: nowSeconds
        )
        try simulator.acceptAuthorityCustodyBiometric(true)
        try simulator.commitAuthorityCustody(acceptedData: custody.accepted)
        try simulator.reviewFirstDevice(qrText: try firstDeviceQR(), now: now)
        try simulator.verifyProviderIdentity(
            numericSubject: numericSubject,
            challengeExpiry: nowMilliseconds + 120_000
        )
        try simulator.confirmProviderIdentity()
        try simulator.acceptDeviceBiometric(true)
        try simulator.installIdentityReceipt(for: installationID)
        try simulator.activateAuthority()
        try await simulator.reviewMonasLogin(
            qrText: monasLogin.qr,
            trust: monasLogin.trust,
            expectedExternalIdentityID: monasLogin.externalIdentityID,
            now: now
        )
        try simulator.acceptMonasLoginBiometric(true)
        try simulator.establishMonasSession(
            installationID: installationID,
            audience: "propylaion",
            redirectedPath: "/home"
        )
        try await simulator.reviewProductLogin(
            qrText: productLogin.qr,
            trust: productLogin.trust,
            expectedExternalIdentityID: productLogin.externalIdentityID,
            now: now
        )
        try simulator.acceptProductLoginBiometric(true)
        try simulator.establishProductSession(
            installationID: installationID,
            audience: "dasobjectstore"
        )

        XCTAssertEqual(simulator.stage, .productSessionEstablished)
        XCTAssertNil(simulator.terminalFailure)
        XCTAssertEqual(
            simulator.evidence,
            [
                "host-attached",
                "browser-numeric-provider-subject-accepted",
                "production-site-root-genesis-presentation-verified",
                "simulated-site-root-biometric-accepted",
                "simulated-app-attest-registration-accepted",
                "site-root-proof-and-delegation-accepted",
                "production-site-x509-broker-presentation-verified",
                "simulated-site-x509-biometric-accepted",
                "site-x509-custody-and-paired-leaf-accepted",
                "production-authority-custody-status-checked",
                "simulated-authority-custody-app-attest-assertion-accepted",
                "production-authority-custody-v2-presentation-verified",
                "simulated-authority-custody-biometric-accepted",
                "durable-thesaurophylax-authority-signer-ready",
                "production-first-device-presentation-verified",
                "numeric-provider-subject-verified",
                "explicit-provider-account-confirmation",
                "simulated-device-binding-biometric-accepted",
                "signed-first-device-receipt-installed",
                "bootstrap-retired-and-production-authority-activated",
                "production-signed-propylaion-home-challenge-verified",
                "simulated-monas-login-biometric-accepted",
                "verified-monas-session-established-at-home",
                "production-signed-dasobjectstore-challenge-verified",
                "simulated-dasobjectstore-login-biometric-accepted",
                "exact-audience-dasobjectstore-session-established",
            ])
    }

    func testCancellationIsTerminalAndCannotAdvance() throws {
        var simulator = MonasFirstWebLoginIPhoneSimulator()
        try simulator.attachHost()
        simulator.cancel()
        XCTAssertThrowsError(
            try simulator.acceptBrowserIdentity(numericSubject: numericSubject)
        ) { XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .cancelled) }
    }

    func testBiometricAndAppAttestDenialsAreTerminal() throws {
        var biometric = MonasFirstWebLoginIPhoneSimulator()
        try biometric.attachHost()
        try biometric.acceptBrowserIdentity(numericSubject: numericSubject)
        try biometric.reviewSiteRoot(qrText: siteRootQR(), nowMilliseconds: nowMilliseconds)
        XCTAssertThrowsError(try biometric.acceptSiteRootBiometric(false)) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .biometricDenied)
        }

        var attest = MonasFirstWebLoginIPhoneSimulator()
        try attest.attachHost()
        try attest.acceptBrowserIdentity(numericSubject: numericSubject)
        try attest.reviewSiteRoot(qrText: siteRootQR(), nowMilliseconds: nowMilliseconds)
        try attest.acceptSiteRootBiometric(true)
        XCTAssertThrowsError(try attest.acceptAppAttest(false)) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .appAttestDenied)
        }
    }

    func testExpiredAndSubstitutedAuthorityPresentationsFailClosed() throws {
        var expiredRoot = MonasFirstWebLoginIPhoneSimulator()
        try expiredRoot.attachHost()
        try expiredRoot.acceptBrowserIdentity(numericSubject: numericSubject)
        XCTAssertThrowsError(
            try expiredRoot.reviewSiteRoot(
                qrText: siteRootQR(expiry: nowMilliseconds - 1),
                nowMilliseconds: nowMilliseconds
            )
        ) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .unsupportedQR)
        }

        var substitutedX509 = try throughSiteRoot()
        XCTAssertThrowsError(
            try substitutedX509.reviewSiteX509(
                qrText: siteX509QR(submissionOrigin: "https://attacker.example.test"),
                nowSeconds: nowSeconds
            )
        ) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .unsupportedQR)
        }
    }

    func testReplayAndSkippedStageFailClosed() throws {
        var skipped = MonasFirstWebLoginIPhoneSimulator()
        XCTAssertThrowsError(try skipped.commitSiteRoot()) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .outOfOrder)
        }

        var replay = try throughAuthorityCustody()
        let qr = siteX509QR()
        XCTAssertThrowsError(try replay.reviewFirstDevice(qrText: qr, now: now)) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .replay)
        }
    }

    func testFirstDeviceIsBlockedUntilAuthorityCustodyIsDurable() throws {
        var simulator = try throughSiteX509()
        XCTAssertThrowsError(
            try simulator.reviewFirstDevice(qrText: try firstDeviceQR(), now: now)
        ) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .outOfOrder)
        }
    }

    func testAuthorityCustodyAppAttestAndBiometricDenialsAreTerminal() throws {
        var attest = try throughSiteX509()
        try attest.observeAuthorityCustodyStatus(.appAttestAssertionRequired)
        XCTAssertThrowsError(
            try attest.acceptAuthorityCustodyAppAttest(
                false,
                observedLifecycle: .initialRotationRequired
            )
        ) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .appAttestDenied)
        }

        var biometric = try throughSiteX509()
        let fixture = try MonasFirstWebLoginCustodySimulatorFixture(
            mode: .rotation,
            expiresAtUnixSeconds: nowSeconds + 120
        )
        try biometric.observeAuthorityCustodyStatus(.initialRotationRequired)
        try biometric.reviewAuthorityCustody(fixture: fixture, nowUnixSeconds: nowSeconds)
        XCTAssertThrowsError(try biometric.acceptAuthorityCustodyBiometric(false)) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .biometricDenied)
        }
    }

    func testRetainedAuthorityCustodyRecoveryUsesRecoveryWireBeforeIdentity() throws {
        var simulator = try throughSiteX509()
        let recovery = try MonasFirstWebLoginCustodySimulatorFixture(
            mode: .recovery,
            expiresAtUnixSeconds: nowSeconds + 120
        )
        try simulator.observeAuthorityCustodyStatus(.recoveryRequired)
        try simulator.reviewAuthorityCustody(
            fixture: recovery,
            nowUnixSeconds: nowSeconds
        )
        try simulator.acceptAuthorityCustodyBiometric(true)
        try simulator.commitAuthorityCustody(acceptedData: recovery.accepted)
        try simulator.reviewFirstDevice(qrText: try firstDeviceQR(), now: now)
        XCTAssertEqual(simulator.stage, .firstDeviceReviewed)
    }

    func testAuthorityCustodyAcceptedResponseCannotBeReplayed() throws {
        var simulator = try throughSiteX509()
        let custody = try MonasFirstWebLoginCustodySimulatorFixture(
            mode: .rotation,
            expiresAtUnixSeconds: nowSeconds + 120
        )
        try simulator.observeAuthorityCustodyStatus(.initialRotationRequired)
        try simulator.reviewAuthorityCustody(fixture: custody, nowUnixSeconds: nowSeconds)
        try simulator.acceptAuthorityCustodyBiometric(true)
        try simulator.commitAuthorityCustody(acceptedData: custody.accepted)
        XCTAssertThrowsError(
            try simulator.commitAuthorityCustody(acceptedData: custody.accepted)
        ) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .outOfOrder)
        }
    }

    func testProviderIdentityInstallationAndAudienceSeparationFailClosed() async throws {
        var wrongProvider = try throughFirstDevice()
        XCTAssertThrowsError(
            try wrongProvider.verifyProviderIdentity(
                numericSubject: numericSubject + 1,
                challengeExpiry: nowMilliseconds + 120_000
            )
        ) {
            XCTAssertEqual($0 as? MonasFirstWebLoginIPhoneSimulator.Failure, .wrongInstallation)
        }

        var wrongInstallation = try throughAuthorityActivation()
        let otherInstallation = try SimulatorAuthenticationFixture(
            installationID: Data(repeating: 0x99, count: 16),
            audience: "propylaion",
            authorisedAudiences: ["propylaion"]
        )
        do {
            try await wrongInstallation.reviewMonasLogin(
                qrText: otherInstallation.qr,
                trust: otherInstallation.trust,
                expectedExternalIdentityID: otherInstallation.externalIdentityID,
                now: now
            )
            XCTFail("wrong installation unexpectedly authenticated")
        } catch {
            XCTAssertEqual(error as? MonasFirstWebLoginIPhoneSimulator.Failure, .wrongInstallation)
        }

        var wrongAudience = try throughAuthorityActivation()
        let productOnly = try SimulatorAuthenticationFixture(
            installationID: installationID,
            audience: "dasobjectstore",
            authorisedAudiences: ["dasobjectstore"]
        )
        do {
            try await wrongAudience.reviewMonasLogin(
                qrText: productOnly.qr,
                trust: productOnly.trust,
                expectedExternalIdentityID: productOnly.externalIdentityID,
                now: now
            )
            XCTFail("product audience unexpectedly authenticated as Monas")
        } catch {
            XCTAssertEqual(error as? MonasFirstWebLoginIPhoneSimulator.Failure, .wrongAudience)
        }
    }

    private func throughSiteRoot() throws -> MonasFirstWebLoginIPhoneSimulator {
        var simulator = MonasFirstWebLoginIPhoneSimulator()
        try simulator.attachHost()
        try simulator.acceptBrowserIdentity(numericSubject: numericSubject)
        try simulator.reviewSiteRoot(qrText: siteRootQR(), nowMilliseconds: nowMilliseconds)
        try simulator.acceptSiteRootBiometric(true)
        try simulator.acceptAppAttest(true)
        try simulator.commitSiteRoot()
        return simulator
    }

    private func throughFirstDevice() throws -> MonasFirstWebLoginIPhoneSimulator {
        var simulator = try throughAuthorityCustody()
        try simulator.reviewFirstDevice(qrText: try firstDeviceQR(), now: now)
        return simulator
    }

    private func throughAuthorityCustody() throws -> MonasFirstWebLoginIPhoneSimulator {
        var simulator = try throughSiteX509()
        let custody = try MonasFirstWebLoginCustodySimulatorFixture(
            mode: .rotation,
            expiresAtUnixSeconds: nowSeconds + 120
        )
        try simulator.observeAuthorityCustodyStatus(.initialRotationRequired)
        try simulator.reviewAuthorityCustody(fixture: custody, nowUnixSeconds: nowSeconds)
        try simulator.acceptAuthorityCustodyBiometric(true)
        try simulator.commitAuthorityCustody(acceptedData: custody.accepted)
        return simulator
    }

    private func throughSiteX509() throws -> MonasFirstWebLoginIPhoneSimulator {
        var simulator = try throughSiteRoot()
        try simulator.reviewSiteX509(qrText: siteX509QR(), nowSeconds: nowSeconds)
        try simulator.acceptSiteX509Biometric(true)
        try simulator.commitSiteX509()
        return simulator
    }

    private func throughAuthorityActivation() throws -> MonasFirstWebLoginIPhoneSimulator {
        var simulator = try throughFirstDevice()
        try simulator.verifyProviderIdentity(
            numericSubject: numericSubject,
            challengeExpiry: nowMilliseconds + 120_000
        )
        try simulator.confirmProviderIdentity()
        try simulator.acceptDeviceBiometric(true)
        try simulator.installIdentityReceipt(for: installationID)
        try simulator.activateAuthority()
        return simulator
    }

    private func firstDeviceQR() throws -> String {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent(
                "../../../../fixtures/protocol-v4/first-device/presentation-positive.json"
            )
            .standardizedFileURL
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
        return try XCTUnwrap(object["qr_text"] as? String)
    }

    private func siteRootQR(expiry: UInt64? = nil) -> String {
        let origin = MonasSiteRootGenesisBrokerEndpointV1.origin
        let registration = origin + MonasSiteRootGenesisBrokerEndpointV1.registrationPath
        return json([
            "schema": SiteRootGenesisRegistrationPresentationV1.schema,
            "reference": "candidate-genesis-reference",
            "site_trust_domain": "candidate-site",
            "registration_url": registration,
            "app_attest_ceremony_id_b64url": b64(Data(repeating: 0x11, count: 16)),
            "app_attest_challenge_digest_b64url": b64(Data(repeating: 0x22, count: 32)),
            "correlation_b64url": b64(Data(repeating: 0x44, count: 32)),
            "expires_at_unix_millis": expiry ?? nowMilliseconds + 120_000,
        ])
    }

    private func siteX509QR(
        submissionOrigin: String = SiteRootConvergenceProfileV2.x509BrokerOrigin
    ) -> String {
        let site = Data(repeating: 0x22, count: 16)
        let transaction = Data(repeating: 0x33, count: 16)
        return json([
            "schema": SiteRootConvergenceProfileV2.x509BrokerProvisionSchema,
            "purpose": SiteRootConvergenceProfileV2.x509BrokerPurpose,
            "site_uuid": "22222222-2222-2222-2222-222222222222",
            "transaction_uuid": "33333333-3333-3333-3333-333333333333",
            "generation": 4,
            "canonical_challenge_b64url": b64(
                siteX509Challenge(site: site, transaction: transaction)
            ),
            "correlation_b64url": b64(Data(repeating: 0x44, count: 32)),
            "roles": SiteX509FirstProvisionBrokerPresentationV1.roles,
            "expires_at_unix_seconds": nowSeconds + 120,
            "submission_url": submissionOrigin
                + SiteRootConvergenceProfileV2.x509BrokerSubmitPath,
            "enrolled_site_root_public_key_id_b64url": b64(
                Data(repeating: 0x55, count: 32)
            ),
        ])
    }

    private func siteX509Challenge(site: Data, transaction: Data) -> Data {
        var result = Data("PXFP/v1\u{1}".utf8)
        result += field(1, Data(SiteRootConvergenceProfileV2.x509Purpose.utf8))
        result += field(2, site)
        result += field(3, transaction)
        result += field(4, u64(4))
        result += field(5, Data(SiteRootConvergenceProfileV2.x509RootPurpose.utf8))
        result += field(6, Data([2]) + Data(repeating: 0x66, count: 32))
        result += field(7, Data(repeating: 0x77, count: 32))
        result += field(8, Data(repeating: 0x88, count: 32))
        result += field(9, Data(SiteRootConvergenceProfileV2.x509IssuerPurpose.utf8))
        result += field(10, Data([3]) + Data(repeating: 0x99, count: 32))
        result += field(11, Data(repeating: 0xaa, count: 32))
        result += field(12, Data(repeating: 0xbb, count: 32))
        result += field(13, u64(nowSeconds + 120))
        result += field(14, Data(repeating: 0xcc, count: 32))
        return result
    }

    private func field(_ tag: UInt8, _ value: Data) -> Data {
        Data([tag, UInt8(value.count >> 8), UInt8(truncatingIfNeeded: value.count)]) + value
    }

    private func u64(_ value: UInt64) -> Data {
        withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }

    private func b64(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func json(_ object: [String: Any]) -> String {
        String(
            data: try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
            encoding: .utf8
        )!
    }
}

private actor SimulatorTrust: InstallationTrustReading {
    private let stored: InstallationTrustRecord

    init(record: InstallationTrustRecord) {
        stored = record
    }

    func record(installationID: Data) -> InstallationTrustRecord? {
        stored.installationID == installationID ? stored : nil
    }
}

private struct SimulatorAuthenticationFixture {
    let qr: String
    let trust: InstallationTrustRecord
    let externalIdentityID = Data(repeating: 0x44, count: 16)

    init(
        installationID: Data,
        audience: String,
        authorisedAudiences: Set<String>
    ) throws {
        let key = P256.Signing.PrivateKey()
        let keyID = Data(repeating: 0x21, count: 32)
        let fingerprint = Data(repeating: 0x31, count: 32)
        let payload = Self.challenge(
            installationID: installationID,
            keyID: keyID,
            fingerprint: fingerprint,
            audience: audience
        )
        let signingInput = try CoseSign1.signatureStructure(keyID: keyID, payload: payload)
        let signature = Self.lowS(try key.signature(for: signingInput).rawRepresentation)
        let cose = try CoseSign1(
            keyID: keyID,
            payload: payload,
            signature: signature
        ).encoded()
        qr = Self.qr(cose)
        trust = try InstallationTrustRecord(
            installationID: installationID,
            displayName: "Candidate Monas installation",
            audience: "prosopikon:pistis:enrolment",
            authorisedProductAudiences: authorisedAudiences,
            userID: Data(repeating: 0x88, count: 16),
            externalIdentityID: externalIdentityID,
            fingerprint: fingerprint,
            installationKeyID: keyID,
            installationPublicKey: key.publicKey.compressedRepresentation,
            authorityKeyID: Data(repeating: 0x55, count: 32),
            authorityReceipt: Data([0x01]),
            policyGeneration: 1,
            revocationGeneration: 1,
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            active: true
        )
    }

    private static func challenge(
        installationID: Data,
        keyID: Data,
        fingerprint: Data,
        audience: String
    ) -> Data {
        var result = Data([0xb1])
        result += uint(0) + uint(1)
        result += uint(1) + text("pistis.authentication-challenge.v1")
        result += uint(2) + uint(1_700_000_000_000)
        result += uint(3) + uint(1_700_000_120_000)
        result += uint(4) + bytes(installationID)
        result += uint(5) + bytes(keyID)
        result += uint(6) + bytes(Data(repeating: 0x66, count: 16))
        result += uint(7) + bytes(Data(repeating: 0x77, count: 32))
        result += uint(8) + bytes(Data(repeating: 0x88, count: 16))
        result += uint(9) + bytes(Data(repeating: 0x44, count: 16))
        result += uint(10) + text("authenticate-session")
        result += uint(11) + text(audience)
        result += uint(12) + text("Candidate Monas installation")
        result += uint(13) + text("candidate-operator")
        result += uint(14) + bytes(Data(repeating: 0x99, count: 32))
        result += uint(15) + bytes(fingerprint)
        result +=
            uint(16) + Data([0x81])
            + text("https://monas.example.test/auth/pistis")
        return result
    }

    private static func qr(_ cose: Data) -> String {
        let frame = Data([0xa3, 0x00, 0x02, 0x01, 0x01, 0x02]) + bytes(cose)
        let body = frame.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let checksum = SHA256.hash(data: Data("PISTIS1:\(body)".utf8)).prefix(8)
            .map { String(format: "%02x", $0) }.joined()
        return "PISTIS1:\(body).\(checksum)"
    }

    private static func lowS(_ signature: Data) -> Data {
        let halfOrder = Data([
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
            0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
        ])
        let scalar = signature.suffix(32)
        guard sGreaterThanHalfOrder(scalar, halfOrder: halfOrder) else { return signature }
        let order: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ]
        let input = Array(scalar)
        var output = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var value = Int(order[index]) - Int(input[index]) - borrow
            if value < 0 {
                value += 256
                borrow = 1
            } else {
                borrow = 0
            }
            output[index] = UInt8(value)
        }
        return signature.prefix(32) + Data(output)
    }

    private static func sGreaterThanHalfOrder(
        _ scalar: Data.SubSequence,
        halfOrder: Data
    ) -> Bool {
        !scalar.lexicographicallyPrecedes(halfOrder) && scalar != halfOrder
    }

    private static func bytes(_ value: Data) -> Data {
        argument(major: 2, UInt64(value.count)) + value
    }

    private static func text(_ value: String) -> Data {
        argument(major: 3, UInt64(value.utf8.count)) + Data(value.utf8)
    }

    private static func uint(_ value: UInt64) -> Data { argument(major: 0, value) }

    private static func argument(major: UInt8, _ value: UInt64) -> Data {
        if value < 24 { return Data([major << 5 | UInt8(value)]) }
        if value <= UInt8.max { return Data([major << 5 | 24, UInt8(value)]) }
        if value <= UInt16.max {
            let result = UInt16(value).bigEndian
            return Data([major << 5 | 25]) + withUnsafeBytes(of: result) { Data($0) }
        }
        if value <= UInt32.max {
            let result = UInt32(value).bigEndian
            return Data([major << 5 | 26]) + withUnsafeBytes(of: result) { Data($0) }
        }
        let result = value.bigEndian
        return Data([major << 5 | 27]) + withUnsafeBytes(of: result) { Data($0) }
    }
}
