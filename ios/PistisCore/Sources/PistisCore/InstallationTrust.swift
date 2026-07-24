import Foundation

public enum InstallationTrustState: String, Codable, Sendable {
    case new
    case trusted
    case trustChanged = "trust_changed"
    case revoked
}

public struct Installation: Codable, Equatable, Sendable {
    public let id: InstallationID
    public var displayName: String
    public var alias: String?
    public private(set) var trustedFingerprint: SHA256Fingerprint?
    public private(set) var observedFingerprint: SHA256Fingerprint
    public private(set) var trustState: InstallationTrustState
    public private(set) var lastUsedAt: Date?

    public init(
        id: InstallationID,
        displayName: String,
        observedFingerprint: SHA256Fingerprint,
        alias: String? = nil
    ) throws {
        guard !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw DomainValidationError.missingDisplayName
        }
        self.id = id
        self.displayName = displayName
        self.alias = alias
        trustedFingerprint = nil
        self.observedFingerprint = observedFingerprint
        trustState = .new
        lastUsedAt = nil
    }

    public mutating func pair(observedAt: Date) throws {
        guard trustState != .revoked else { throw InstallationTrustError.revoked }
        trustedFingerprint = observedFingerprint
        trustState = .trusted
        lastUsedAt = observedAt
    }

    public mutating func observe(
        fingerprint: SHA256Fingerprint,
        observedAt: Date
    ) throws {
        guard trustState != .revoked else { throw InstallationTrustError.revoked }
        observedFingerprint = fingerprint
        if let trustedFingerprint, trustedFingerprint != fingerprint {
            trustState = .trustChanged
        } else if trustedFingerprint == fingerprint {
            trustState = .trusted
            lastUsedAt = observedAt
        }
    }

    public mutating func repair(confirmedFingerprint: SHA256Fingerprint, at: Date) throws {
        guard trustState == .trustChanged else {
            throw InstallationTrustError.repairNotRequired
        }
        guard confirmedFingerprint == observedFingerprint else {
            throw InstallationTrustError.fingerprintMismatch
        }
        trustedFingerprint = confirmedFingerprint
        trustState = .trusted
        lastUsedAt = at
    }

    public mutating func revoke() {
        trustState = .revoked
    }

    public var mayApprove: Bool {
        trustState == .trusted
    }
}

public enum InstallationTrustError: Error, Equatable, Sendable {
    case revoked
    case repairNotRequired
    case fingerprintMismatch
}
