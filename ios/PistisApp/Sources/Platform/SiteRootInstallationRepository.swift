import Foundation

enum SiteRootSetupPhase: String, Codable, Equatable {
    case authorityCustodyRequired = "authority-custody-required"
    case identityEnrolmentRequired = "identity-enrolment-required"
}

/// A non-authorising local lifecycle observation created after a completed
/// first Site Root ceremony. It contains only redacted public presentation
/// facts and must never be consumed as session, identity, or trust authority.
struct IncompleteSiteRootInstallation: Codable, Equatable, Identifiable {
    static let storageProfile = 1

    let storageProfile: Int
    let id: UUID
    let authorityHost: String
    let redactedReference: String
    let recordedAt: Date
    let setupPhase: SiteRootSetupPhase

    init(
        id: UUID = UUID(),
        authorityHost: String,
        redactedReference: String,
        recordedAt: Date = Date(),
        setupPhase: SiteRootSetupPhase = .authorityCustodyRequired
    ) throws {
        guard Self.isSafeHost(authorityHost),
              Self.isSafeReference(redactedReference)
        else {
            throw PlatformFailure.invalidConfiguration
        }
        self.storageProfile = Self.storageProfile
        self.id = id
        self.authorityHost = authorityHost
        self.redactedReference = redactedReference
        self.recordedAt = recordedAt
        self.setupPhase = setupPhase
    }

    private enum CodingKeys: String, CodingKey {
        case storageProfile, id, authorityHost, redactedReference, recordedAt, setupPhase
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: values.decode(UUID.self, forKey: .id),
            authorityHost: values.decode(String.self, forKey: .authorityHost),
            redactedReference: values.decode(String.self, forKey: .redactedReference),
            recordedAt: values.decode(Date.self, forKey: .recordedAt),
            setupPhase: values.decodeIfPresent(SiteRootSetupPhase.self, forKey: .setupPhase)
                ?? .authorityCustodyRequired
        )
        guard try values.decode(Int.self, forKey: .storageProfile) == Self.storageProfile else {
            throw PlatformFailure.invalidConfiguration
        }
    }

    private static func isSafeHost(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 253 else { return false }
        return value.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }
    }

    private static func isSafeReference(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 64 else { return false }
        return value.allSatisfy {
            $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "…"
        }
    }
}

/// Persists only the iPhone's redacted setup progress. Monas remains the
/// authoritative source for Site Trust, custody, sessions, and enrolment.
@MainActor
final class SiteRootInstallationRepository {
    static let shared = SiteRootInstallationRepository()
    static let installationsDidChangeNotification = Notification.Name(
        "org.mnemosynebiosciences.pistis.site-root-installations-changed"
    )

    private let defaults: UserDefaults
    private let key = "org.mnemosynebiosciences.pistis.site-root-installations.v1"
    private let maximumRecords = 16
    private let maximumEncodedBytes = 8_192

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func records() throws -> [IncompleteSiteRootInstallation] {
        guard let data = defaults.data(forKey: key) else { return [] }
        guard data.count <= maximumEncodedBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        let decoded = try JSONDecoder().decode([IncompleteSiteRootInstallation].self, from: data)
        guard decoded.count <= maximumRecords,
              decoded.allSatisfy({ $0.storageProfile == IncompleteSiteRootInstallation.storageProfile })
        else {
            throw PlatformFailure.invalidConfiguration
        }
        return decoded
    }

    func recordCompletedFirstCeremony(_ review: SiteRootDelegationReview) throws {
        guard review.isFirstDevice else { return }
        try record(
            IncompleteSiteRootInstallation(
            authorityHost: review.destination,
            redactedReference: review.reference
            )
        )
    }

    func recordRecoveredFirstCeremony(
        authorityHost: String,
        redactedReference: String,
        registeredAt: Date
    ) throws {
        try record(
            IncompleteSiteRootInstallation(
                authorityHost: authorityHost,
                redactedReference: redactedReference,
                recordedAt: registeredAt
            )
        )
    }

    func recordAuthorityCustodyCompleted(authorityHost: String) throws {
        var retained = try records()
        guard let index = retained.lastIndex(where: {
            $0.authorityHost == authorityHost
                && $0.setupPhase == .authorityCustodyRequired
        }) else { throw PlatformFailure.invalidConfiguration }
        let current = retained[index]
        retained[index] = try IncompleteSiteRootInstallation(
            id: current.id, authorityHost: current.authorityHost,
            redactedReference: current.redactedReference, recordedAt: current.recordedAt,
            setupPhase: .identityEnrolmentRequired
        )
        try persist(retained)
    }

    private func record(_ record: IncompleteSiteRootInstallation) throws {
        var retained = try records()
        if let index = retained.firstIndex(where: {
            $0.authorityHost == record.authorityHost &&
                $0.redactedReference == record.redactedReference
        }) {
            retained[index] = record
        } else {
            retained.append(record)
        }
        try persist(Array(retained.suffix(maximumRecords)))
    }

    private func persist(_ retained: [IncompleteSiteRootInstallation]) throws {
        let encoded = try JSONEncoder().encode(retained)
        guard encoded.count <= maximumEncodedBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        defaults.set(encoded, forKey: key)
        NotificationCenter.default.post(name: Self.installationsDidChangeNotification, object: nil)
    }
}
