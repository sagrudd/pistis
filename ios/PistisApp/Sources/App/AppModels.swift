import Foundation

struct IdentitySummary: Identifiable, Hashable {
    let id: UUID
    let provider: String
    let displayName: String
    let stableSubject: String
    let githubAccountID: UInt64?
    let installationID: UUID
    let installationName: String
    let installationHost: String
    let expiresAt: Date
    let status: String
    let allowsLocalForget: Bool
}

struct IdentityAccountGroup: Identifiable {
    enum Key: Hashable {
        case github(UInt64)
        case unlabelled(UUID)
    }

    let id: Key
    let installations: [IdentitySummary]

    var githubAccountID: UInt64? {
        if case let .github(id) = id { return id }
        return nil
    }

    var title: String {
        installations.first { $0.displayName != "GitHub account" }?.displayName ?? "GitHub account"
    }

    static func group(_ identities: [IdentitySummary]) -> [Self] {
        func key(_ identity: IdentitySummary) -> Key {
            identity.githubAccountID.map(Key.github) ?? .unlabelled(identity.installationID)
        }
        let groups = Dictionary(grouping: identities, by: key)
        var seen = Set<Key>()
        return identities.compactMap { identity in
            let id = key(identity)
            guard seen.insert(id).inserted, let installations = groups[id] else { return nil }
            return Self(id: id, installations: installations)
        }
    }
}

struct InstallationSummary: Identifiable, Hashable {
    let id: UUID
    let name: String
    let localAlias: String
    let fingerprint: String
    let status: String
    let lastUsed: String
    let allowsLocalForget: Bool
    /// The label for the non-secret fact shown in the installation detail.
    /// Authenticated installations expose a public fingerprint; an incomplete
    /// Site Root installation instead exposes its redacted ceremony reference.
    let evidenceLabel: String
    let setupPhase: SiteRootSetupPhase?

    init(
        id: UUID,
        name: String,
        localAlias: String,
        fingerprint: String,
        status: String,
        lastUsed: String,
        allowsLocalForget: Bool,
        evidenceLabel: String = "Public fingerprint",
        setupPhase: SiteRootSetupPhase? = nil
    ) {
        self.id = id
        self.name = name
        self.localAlias = localAlias
        self.fingerprint = fingerprint
        self.status = status
        self.lastUsed = lastUsed
        self.allowsLocalForget = allowsLocalForget
        self.evidenceLabel = evidenceLabel
        self.setupPhase = setupPhase
    }
}

struct ApprovalRequest: Identifiable, Hashable {
    let id: UUID
    let action: String
    let subject: String
    let installation: String
    let localUser: String
    let externalIdentity: String
    let fingerprint: String
    let expiry: String
    let route: String
    let trustState: String
}

struct HistoryEvent: Identifiable, Hashable, Codable {
    let id: UUID
    let action: String
    let installation: String
    let occurredAt: String
    let decision: String
    let signature: String
    let transfer: String
    let verification: String
}
