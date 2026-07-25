import Foundation

public enum ChallengeRoute: String, Codable, Sendable {
    case qr
    case directLocal = "direct_local"
}

public enum ApprovalPurpose: String, Codable, Sendable {
    case login = "auth.login"
    case reportReviewed = "report.reviewed"
    case reportApproved = "report.approved"
    case datasetReleased = "dataset.released"
    case workflowApproved = "workflow.approved"
    case softwareReleaseApproved = "software.release-approved"
    case artefactAttested = "artefact.attested"
}

public struct ApprovalChallenge: Codable, Equatable, Sendable {
    public let id: ChallengeID
    public let installationID: InstallationID
    public let installationName: String
    public let installationFingerprint: SHA256Fingerprint
    public let identityID: IdentityID
    public let localUsername: String
    public let purpose: ApprovalPurpose
    public let requestedStatement: String
    public let issuedAt: Date
    public let expiresAt: Date
    public let route: ChallengeRoute

    public init(
        id: ChallengeID,
        installationID: InstallationID,
        installationName: String,
        installationFingerprint: SHA256Fingerprint,
        identityID: IdentityID,
        localUsername: String,
        purpose: ApprovalPurpose,
        requestedStatement: String,
        issuedAt: Date,
        expiresAt: Date,
        route: ChallengeRoute
    ) throws {
        guard !installationName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !localUsername.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !requestedStatement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              installationName.utf8.count <= 256,
              localUsername.utf8.count <= 256,
              requestedStatement.utf8.count <= 2_048
        else {
            throw ChallengeValidationError.invalidDisplayContext
        }
        guard issuedAt < expiresAt,
              expiresAt.timeIntervalSince(issuedAt) <= 300
        else {
            throw ChallengeValidationError.invalidValidityWindow
        }
        self.id = id
        self.installationID = installationID
        self.installationName = installationName
        self.installationFingerprint = installationFingerprint
        self.identityID = identityID
        self.localUsername = localUsername
        self.purpose = purpose
        self.requestedStatement = requestedStatement
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.route = route
    }

    public func validateForPresentation(
        now: Date,
        identity: ExternalIdentity?,
        installation: Installation?
    ) throws {
        guard now >= issuedAt, now < expiresAt else {
            throw ChallengeValidationError.expiredOrNotYetValid
        }
        guard let identity, identity.id == identityID, identity.bindingState == .bound else {
            throw ChallengeValidationError.wrongOrUnboundIdentity
        }
        guard let installation, installation.id == installationID else {
            throw ChallengeValidationError.unknownInstallation
        }
        guard installation.observedFingerprint == installationFingerprint else {
            throw ChallengeValidationError.installationFingerprintMismatch
        }
        guard installation.mayApprove else {
            throw ChallengeValidationError.installationNotTrusted(installation.trustState)
        }
    }
}

public enum ChallengeValidationError: Error, Equatable, Sendable {
    case invalidDisplayContext
    case invalidValidityWindow
    case expiredOrNotYetValid
    case wrongOrUnboundIdentity
    case unknownInstallation
    case installationFingerprintMismatch
    case installationNotTrusted(InstallationTrustState)
}
