import Foundation

protocol BaseCampVaultSiteRootRegistrationReadingV1: Sendable {
    func existingRegistration() throws -> SiteRootKeyRegistrationV1?
}

extension SecureEnclaveSiteRootProofProducer:
    BaseCampVaultSiteRootRegistrationReadingV1 {}

protocol BaseCampVaultMigrationTransportingV1: Sendable {
    func fetchBaseCampVaultMigrationV1(
        expectedDeviceKeyID: String,
        expectedRevocationGeneration: UInt64,
        nowUnixSeconds: UInt64
    ) async throws -> BaseCampVaultMigrationPresentationV1

    func submitBaseCampVaultMigrationV1(
        _ submission: IphoneMediatedCustodyRewrapSubmissionV1
    ) async throws
}

extension MonasAppAttestTransport: BaseCampVaultMigrationTransportingV1 {}

protocol BaseCampVaultMigrationApprovalExecutingV1: Sendable {
    func approve(
        _ presentation: BaseCampVaultMigrationPresentationV1
    ) async throws -> IphoneMediatedCustodyRewrapSubmissionV1
}

extension SecureEnclaveBaseCampVaultMigrationProducerV1:
    BaseCampVaultMigrationApprovalExecutingV1
{
    func approve(
        _ presentation: BaseCampVaultMigrationPresentationV1
    ) async throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Approve this exact Base Camp vault custody migration"
        )
        return try produce(presentation, using: ceremony)
    }
}

struct BaseCampVaultMigrationPresentedReviewV1: Identifiable, Equatable, Sendable {
    let id: Data
    let evidence: BaseCampVaultMigrationReviewV1
}

/// Owns one explicit, purpose-separated Base Camp migration decision.
/// Scanning only fetches and validates public/ciphertext evidence. It never
/// approves automatically and it is not reachable from ordinary login.
@MainActor
final class BaseCampVaultMigrationCoordinatorV1: ObservableObject {
    enum Phase: Equatable {
        case idle
        case fetching
        case review
        case approving
        case completed
        case cancelled
        case failed
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var presentedReview: BaseCampVaultMigrationPresentedReviewV1?
    private let transport: (any BaseCampVaultMigrationTransportingV1)?
    private let trustStore: any InstallationTrustStoring
    private let approval: (any BaseCampVaultMigrationApprovalExecutingV1)?
    private let siteRootRegistration: (any BaseCampVaultSiteRootRegistrationReadingV1)?
    private let now: @Sendable () -> Date
    private var pending: BaseCampVaultMigrationPresentationV1?

    init(
        transport: (any BaseCampVaultMigrationTransportingV1)?,
        trustStore: any InstallationTrustStoring = InstallationTrustKeychain.shared,
        approval: (any BaseCampVaultMigrationApprovalExecutingV1)? = nil,
        siteRootRegistration: (any BaseCampVaultSiteRootRegistrationReadingV1)? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.transport = transport
        self.trustStore = trustStore
        self.now = now
        if let approval {
            self.approval = approval
        } else {
            self.approval = try? SecureEnclaveBaseCampVaultMigrationProducerV1()
        }
        self.siteRootRegistration = siteRootRegistration
            ?? (try? SecureEnclaveSiteRootProofProducer(
                authenticationReason: "Verify the retained Site Root device"
            ))
    }

    func accept(qrText: String) async {
        reset()
        do {
            _ = try BaseCampVaultMigrationQRV1(qrText: qrText)
            guard let transport,
                  let enrollment = try await trustStore.activeEnrollment(),
                  enrollment.trust.active,
                  enrollment.trust.expiresAt > now()
            else { throw PlatformFailure.enrolmentRequired }
            let registration = try siteRootRegistration?.existingRegistration()
            guard let registration else { throw PlatformFailure.keyNotFound }
            phase = .fetching
            let presentation = try await transport.fetchBaseCampVaultMigrationV1(
                expectedDeviceKeyID: registration.deviceKeyID,
                expectedRevocationGeneration: enrollment.trust.revocationGeneration,
                nowUnixSeconds: UInt64(now().timeIntervalSince1970)
            )
            pending = presentation
            presentedReview = BaseCampVaultMigrationPresentedReviewV1(
                id: presentation.correlation,
                evidence: presentation.review
            )
            phase = .review
        } catch {
            pending = nil
            presentedReview = nil
            phase = .failed
        }
    }

    func approve() async {
        guard phase == .review, let pending, let transport, let approval else {
            phase = .failed
            return
        }
        do {
            phase = .approving
            let submission = try await approval.approve(pending)
            try await transport.submitBaseCampVaultMigrationV1(submission)
            self.pending = nil
            phase = .completed
            presentedReview = nil
        } catch {
            self.pending = nil
            phase = .failed
        }
    }

    func cancel() {
        pending = nil
        phase = .cancelled
        presentedReview = nil
    }

    func reset() {
        pending = nil
        presentedReview = nil
        phase = .idle
    }
}

protocol BaseCampVaultSuccessorTransportingV1: Sendable {
    func fetchBaseCampVaultSuccessorRotationV1(
        expectedDeviceKeyID: String,
        expectedRevocationGeneration: UInt64,
        nowUnixSeconds: UInt64
    ) async throws -> BaseCampVaultSuccessorRotationPresentationV1

    func submitBaseCampVaultSuccessorRotationV1(
        _ submission: IphoneMediatedCustodyRewrapSubmissionV1
    ) async throws
}

extension MonasAppAttestTransport: BaseCampVaultSuccessorTransportingV1 {}

protocol BaseCampVaultSuccessorApprovalExecutingV1: Sendable {
    func approve(
        _ presentation: BaseCampVaultSuccessorRotationPresentationV1
    ) async throws -> IphoneMediatedCustodyRewrapSubmissionV1
}

extension SecureEnclaveBaseCampVaultSuccessorRotationProducerV1:
    BaseCampVaultSuccessorApprovalExecutingV1
{
    func approve(
        _ presentation: BaseCampVaultSuccessorRotationPresentationV1
    ) async throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Approve this exact Base Camp vault successor rotation"
        )
        return try produce(presentation, using: ceremony)
    }
}

struct BaseCampVaultSuccessorPresentedReviewV1: Identifiable, Equatable, Sendable {
    let id: Data
    let evidence: BaseCampVaultSuccessorRotationReviewV1
}

@MainActor
final class BaseCampVaultSuccessorCoordinatorV1: ObservableObject {
    enum Phase: Equatable {
        case idle, fetching, review, approving, completed, cancelled, failed
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var presentedReview: BaseCampVaultSuccessorPresentedReviewV1?
    private let transport: (any BaseCampVaultSuccessorTransportingV1)?
    private let trustStore: any InstallationTrustStoring
    private let approval: (any BaseCampVaultSuccessorApprovalExecutingV1)?
    private let siteRootRegistration: (any BaseCampVaultSiteRootRegistrationReadingV1)?
    private let now: @Sendable () -> Date
    private var pending: BaseCampVaultSuccessorRotationPresentationV1?

    init(
        transport: (any BaseCampVaultSuccessorTransportingV1)?,
        trustStore: any InstallationTrustStoring = InstallationTrustKeychain.shared,
        approval: (any BaseCampVaultSuccessorApprovalExecutingV1)? = nil,
        siteRootRegistration: (any BaseCampVaultSiteRootRegistrationReadingV1)? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.transport = transport
        self.trustStore = trustStore
        self.now = now
        self.approval = approval ?? (try? SecureEnclaveBaseCampVaultSuccessorRotationProducerV1())
        self.siteRootRegistration = siteRootRegistration
            ?? (try? SecureEnclaveSiteRootProofProducer(
                authenticationReason: "Verify the retained Site Root device"
            ))
    }

    func accept(qrText: String) async {
        reset()
        do {
            _ = try BaseCampVaultSuccessorRotationQRV1(qrText: qrText)
            guard let transport,
                  let enrollment = try await trustStore.activeEnrollment(),
                  enrollment.trust.active,
                  enrollment.trust.expiresAt > now()
            else { throw PlatformFailure.enrolmentRequired }
            let registration = try siteRootRegistration?.existingRegistration()
            guard let registration else { throw PlatformFailure.keyNotFound }
            phase = .fetching
            let value = try await transport.fetchBaseCampVaultSuccessorRotationV1(
                expectedDeviceKeyID: registration.deviceKeyID,
                expectedRevocationGeneration: enrollment.trust.revocationGeneration,
                nowUnixSeconds: UInt64(now().timeIntervalSince1970)
            )
            pending = value
            presentedReview = BaseCampVaultSuccessorPresentedReviewV1(
                id: value.correlation, evidence: value.review
            )
            phase = .review
        } catch {
            pending = nil
            presentedReview = nil
            phase = .failed
        }
    }

    func approve() async {
        guard phase == .review, let pending, let transport, let approval else {
            phase = .failed
            return
        }
        do {
            phase = .approving
            let submission = try await approval.approve(pending)
            try await transport.submitBaseCampVaultSuccessorRotationV1(submission)
            self.pending = nil
            phase = .completed
            presentedReview = nil
        } catch {
            self.pending = nil
            phase = .failed
        }
    }

    func cancel() {
        pending = nil
        phase = .cancelled
        presentedReview = nil
    }

    func reset() {
        pending = nil
        presentedReview = nil
        phase = .idle
    }
}
