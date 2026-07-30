import Foundation

struct EnrollmentProjection: Equatable {
    let identities: [IdentitySummary]
    let installations: [InstallationSummary]
    let history: [HistoryEvent]

    static let empty = EnrollmentProjection(
        identities: [],
        installations: [],
        history: []
    )

    private init(
        identities: [IdentitySummary],
        installations: [InstallationSummary],
        history: [HistoryEvent]
    ) {
        self.identities = identities
        self.installations = installations
        self.history = history
    }

    init(
        enrollment: AuthenticatedEnrollmentOutput,
        retainedHistory: [HistoryEvent] = [],
        now: Date = Date()
    ) {
        let trust = enrollment.trust
        let isCurrent = trust.active && now < trust.expiresAt
        let externalIdentityID = Self.uuid(trust.externalIdentityID)
        let installationID = Self.uuid(trust.installationID)
        let stableSubject = "Identity \(Self.shortIdentifier(trust.externalIdentityID))"
        let host = enrollment.allowedHosts.sorted().first ?? trust.audience

        identities = [
            IdentitySummary(
                id: externalIdentityID,
                provider: "GitHub",
                displayName: "GitHub account",
                stableSubject: stableSubject,
                status: isCurrent ? "Enrolled" : "Expired",
                allowsLocalForget: !isCurrent
            ),
        ]
        installations = [
            InstallationSummary(
                id: installationID,
                name: trust.displayName,
                localAlias: host,
                fingerprint: Self.fingerprint(trust.fingerprint),
                status: isCurrent ? "Trusted" : "Expired",
                lastUsed: "Not used yet",
                allowsLocalForget: !isCurrent
            ),
        ]
        let enrolmentEvent = HistoryEvent(
            id: Self.uuid(enrollment.responseContext.deviceID),
            action: "Device enrolled",
            installation: trust.displayName,
            occurredAt: "Exact time not retained locally",
            decision: "Verified",
            signature: "Secure Enclave registration verified",
            transfer: "Authority receipt installed locally",
            verification: "Authority receipt verified"
        )
        history = Self.mergeHistory(retainedHistory + [enrolmentEvent])
    }

    init(retainedHistory: [HistoryEvent]) {
        identities = []
        installations = []
        history = Self.mergeHistory(retainedHistory)
    }

    private static func uuid(_ data: Data) -> UUID {
        precondition(data.count == 16)
        let hex = data.map { String(format: "%02x", $0) }.joined()
        let part1 = String(hex.prefix(8))
        let part2 = String(hex.dropFirst(8).prefix(4))
        let part3 = String(hex.dropFirst(12).prefix(4))
        let part4 = String(hex.dropFirst(16).prefix(4))
        let part5 = String(hex.dropFirst(20))
        let formatted = "\(part1)-\(part2)-\(part3)-\(part4)-\(part5)"
        return UUID(uuidString: formatted)!
    }

    private static func shortIdentifier(_ data: Data) -> String {
        data.prefix(8)
            .map { String(format: "%02X", $0) }
            .joined()
    }

    private static func fingerprint(_ data: Data) -> String {
        let hex = data.prefix(16)
            .map { String(format: "%02X", $0) }
            .joined()
        return stride(from: 0, to: hex.count, by: 4).map {
            String(hex.dropFirst($0).prefix(4))
        }.joined(separator: " ")
    }

    private static func mergeHistory(_ events: [HistoryEvent]) -> [HistoryEvent] {
        var seen = Set<UUID>()
        return events.reversed().filter { seen.insert($0.id).inserted }
    }
}

@MainActor
final class EnrollmentProjectionStore: ObservableObject {
    enum State: Equatable {
        case loading
        case loaded(EnrollmentProjection)
        case failed
    }

    @Published private(set) var state: State = .loading
    private let loadEnrollment: () async throws -> AuthenticatedEnrollmentOutput?
    private let loadHistory: () async throws -> [HistoryEvent]
    private let recordHistory: (HistoryEvent) async throws -> Void

    init(
        loadEnrollment: @escaping () async throws -> AuthenticatedEnrollmentOutput?,
        loadHistory: @escaping () async throws -> [HistoryEvent] = { [] },
        recordHistory: @escaping (HistoryEvent) async throws -> Void = { _ in }
    ) {
        self.loadEnrollment = loadEnrollment
        self.loadHistory = loadHistory
        self.recordHistory = recordHistory
    }

    convenience init() {
        self.init {
            try await InstallationTrustKeychain.shared.enrollmentInventoryRecord()
        } loadHistory: {
            try LocalHistoryRepository.shared.records()
        } recordHistory: {
            try LocalHistoryRepository.shared.record($0)
        }
    }

    func refresh() async {
        do {
            let stored = try await loadEnrollment()
            if let stored,
               let event = EnrollmentProjection(enrollment: stored).history.first
            {
                try await recordHistory(event)
            }
            let history = try await loadHistory()
            let projection = stored.map {
                EnrollmentProjection(enrollment: $0, retainedHistory: history)
            } ?? EnrollmentProjection(retainedHistory: history)
            state = .loaded(projection)
        } catch {
            state = .failed
        }
    }
}
