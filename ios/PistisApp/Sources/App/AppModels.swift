import Foundation

struct IdentitySummary: Identifiable, Hashable {
    let id: UUID
    let provider: String
    let displayName: String
    let stableSubject: String
    let status: String
    let allowsLocalForget: Bool
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

enum DemonstrationData {
    static let identities = [
        IdentitySummary(
            id: UUID(),
            provider: "GitHub",
            displayName: "stephen",
            stableSubject: "Provider user 184203",
            status: "Enrolled",
            allowsLocalForget: false
        ),
        IdentitySummary(
            id: UUID(),
            provider: "Google",
            displayName: "Research account",
            stableSubject: "Subject …72f1",
            status: "Enrolled",
            allowsLocalForget: false
        ),
    ]

    static let installations = [
        InstallationSummary(
            id: UUID(),
            name: "Synoptikon Berlin",
            localAlias: "Primary laboratory",
            fingerprint: "7A31 9C42 0F88 1B6D",
            status: "Trusted",
            lastUsed: "Today, 14:21",
            allowsLocalForget: false
        ),
        InstallationSummary(
            id: UUID(),
            name: "Monas workstation",
            localAlias: "Analysis desk",
            fingerprint: "E810 6AF2 93C4 772A",
            status: "Needs review",
            lastUsed: "18 July 2026",
            allowsLocalForget: false
        ),
    ]

    static let approval = ApprovalRequest(
        id: UUID(),
        action: "Sign in",
        subject: "Synoptikon account stephen",
        installation: "Synoptikon Berlin",
        localUser: "stephen",
        externalIdentity: "GitHub · stephen",
        fingerprint: "7A31 9C42 0F88 1B6D",
        expiry: "2 minutes",
        route: "Scanned QR code",
        trustState: "Previously trusted"
    )

    static let history = [
        HistoryEvent(
            id: UUID(),
            action: "Sign in",
            installation: "Synoptikon Berlin",
            occurredAt: "Today, 14:21",
            decision: "Approved",
            signature: "Produced",
            transfer: "Delivered locally",
            verification: "Accepted by installation"
        ),
        HistoryEvent(
            id: UUID(),
            action: "Sign report",
            installation: "Monas workstation",
            occurredAt: "Yesterday, 09:04",
            decision: "Denied",
            signature: "Not produced",
            transfer: "Not attempted",
            verification: "Not applicable"
        ),
    ]
}
