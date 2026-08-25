import Foundation

enum SiteRootSetupPhase: String, Codable, Equatable {
    case authorityCustodyRequired = "authority-custody-required"
    case identityEnrolmentRequired = "identity-enrolment-required"
}

/// A non-authorising local lifecycle observation created after a completed
/// first Site Root ceremony. It contains only redacted public presentation
/// facts and must never be consumed as session, identity, or trust authority.
struct IncompleteSiteRootInstallation: Codable, Equatable, Identifiable {
  static let storageProfile = 2

  struct Evidence: Codable, Equatable {
    let id: UUID
    let redactedReference: String
    let recordedAt: Date
    let setupPhase: SiteRootSetupPhase
  }

    let storageProfile: Int
    let id: UUID
    let authorityHost: String
    let redactedReference: String
    let recordedAt: Date
    let setupPhase: SiteRootSetupPhase
  let evidence: [Evidence]

    init(
        id: UUID = UUID(),
        authorityHost: String,
        redactedReference: String,
        recordedAt: Date = Date(),
    setupPhase: SiteRootSetupPhase = .authorityCustodyRequired,
    evidence: [Evidence]? = nil
    ) throws {
    let retainedEvidence =
      evidence ?? [
        Evidence(
          id: id, redactedReference: redactedReference,
          recordedAt: recordedAt, setupPhase: setupPhase
        )
      ]
        guard Self.isSafeHost(authorityHost),
      Self.isSafeReference(redactedReference),
      !retainedEvidence.isEmpty, retainedEvidence.count <= 16,
      retainedEvidence.allSatisfy({ Self.isSafeReference($0.redactedReference) })
        else {
            throw PlatformFailure.invalidConfiguration
        }
        self.storageProfile = Self.storageProfile
        self.id = id
    self.authorityHost = try Self.canonicalHost(authorityHost)
        self.redactedReference = redactedReference
        self.recordedAt = recordedAt
        self.setupPhase = setupPhase
    self.evidence = retainedEvidence
    }

    private enum CodingKeys: String, CodingKey {
    case storageProfile, id, authorityHost, redactedReference, recordedAt, setupPhase, evidence
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
    let profile = try values.decode(Int.self, forKey: .storageProfile)
    guard profile == 1 || profile == Self.storageProfile else {
      throw PlatformFailure.invalidConfiguration
    }
        try self.init(
            id: values.decode(UUID.self, forKey: .id),
            authorityHost: values.decode(String.self, forKey: .authorityHost),
            redactedReference: values.decode(String.self, forKey: .redactedReference),
            recordedAt: values.decode(Date.self, forKey: .recordedAt),
            setupPhase: values.decodeIfPresent(SiteRootSetupPhase.self, forKey: .setupPhase)
        ?? .authorityCustodyRequired,
      evidence: values.decodeIfPresent([Evidence].self, forKey: .evidence)
        )
  }

  static func canonicalHost(_ value: String) throws -> String {
    guard isSafeHost(value) else { throw PlatformFailure.invalidConfiguration }
    guard !value.hasPrefix("."), !value.hasSuffix("..") else {
      throw PlatformFailure.invalidConfiguration
    }
    var canonical = value.lowercased()
    if canonical.hasSuffix(".") { canonical.removeLast() }
    let octets = canonical.split(separator: ".", omittingEmptySubsequences: false)
    if octets.count == 4, octets.allSatisfy({ UInt8($0) != nil }) {
      canonical = octets.map { String(UInt8($0)!) }.joined(separator: ".")
    }
    guard isSafeHost(canonical), !canonical.contains("..") else {
            throw PlatformFailure.invalidConfiguration
        }
    return canonical
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
    guard decoded.count <= maximumRecords else {
            throw PlatformFailure.invalidConfiguration
        }
    let reconciled = try reconcile(decoded)
    if reconciled != decoded { try persist(reconciled, notify: false) }
    return reconciled
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
        let canonicalHost = try IncompleteSiteRootInstallation.canonicalHost(authorityHost)
        guard let index = retained.firstIndex(where: {
            $0.authorityHost == canonicalHost
                && $0.setupPhase == .authorityCustodyRequired
        }) else { throw PlatformFailure.invalidConfiguration }
        let current = retained[index]
        retained[index] = try IncompleteSiteRootInstallation(
            id: current.id, authorityHost: current.authorityHost,
            redactedReference: current.redactedReference, recordedAt: current.recordedAt,
            setupPhase: .identityEnrolmentRequired,
            evidence: current.evidence
        )
        try persist(retained)
    }

    /// Retires only the matching non-authorising setup projection after the
    /// authority receipt has been verified and authenticated installation
    /// trust has already been committed to Keychain.
    func recordIdentityEnrolmentCompleted(authorityHost: String) throws {
        var retained = try records()
        let canonicalHost = try IncompleteSiteRootInstallation.canonicalHost(authorityHost)
        guard let index = retained.firstIndex(where: {
            $0.authorityHost == canonicalHost
                && $0.setupPhase == .identityEnrolmentRequired
        }) else { return }
        retained.remove(at: index)
        try persist(retained)
    }

    /// Records no authority progress merely because the brokered Site X.509
    /// transaction completed. The signed replacement profile must first bind
    /// this broker record to the native authority; v2 authority custody is the
    /// next protected phase and identity enrolment remains unavailable.
    func recordBrokeredSiteX509Completed() throws {
        guard let brokerHost = URL(
            string: SiteRootConvergenceProfileV2.x509BrokerOrigin
        )?.host else { throw PlatformFailure.invalidConfiguration }
        let canonicalHost = try IncompleteSiteRootInstallation.canonicalHost(brokerHost)
        let retained = try records()
        guard let index = retained.firstIndex(where: {
            $0.authorityHost == canonicalHost
        }) else { throw PlatformFailure.invalidConfiguration }
        guard retained[index].setupPhase == .authorityCustodyRequired else { return }
    }

    /// Rebinds only a broker-created, non-authorising setup projection to the
    /// exact native authority in a verified or code-signed deployment profile.
    /// The migration deliberately returns to the custody-required phase: an
    /// earlier UI projection may have skipped custody, but local state is not
    /// proof that the protected host signer is ready.
    func bindBrokeredSetup(toNativeAuthorityHost authorityHost: String) throws {
        guard let brokerHost = URL(
            string: SiteRootConvergenceProfileV2.x509BrokerOrigin
        )?.host else { throw PlatformFailure.invalidConfiguration }
        let canonicalBroker = try IncompleteSiteRootInstallation.canonicalHost(brokerHost)
        let canonicalAuthority = try IncompleteSiteRootInstallation.canonicalHost(authorityHost)
        guard canonicalAuthority != canonicalBroker else {
            throw PlatformFailure.invalidConfiguration
        }
        var retained = try records()
        let brokerRecords = retained.filter { $0.authorityHost == canonicalBroker }
        guard !brokerRecords.isEmpty else { return }
        retained.removeAll { $0.authorityHost == canonicalBroker }
        retained.append(contentsOf: try brokerRecords.map { current in
            try IncompleteSiteRootInstallation(
                id: current.id, authorityHost: canonicalAuthority,
                redactedReference: current.redactedReference,
                recordedAt: current.recordedAt,
                setupPhase: .authorityCustodyRequired,
                evidence: current.evidence
            )
        })
        try persist(Array(try reconcile(retained).suffix(maximumRecords)))
    }

    /// Erase every non-authorising Site Root setup projection on this phone.
    /// Server-side Site Root, custody and transaction records are unchanged.
    func resetAllLocalInstallations() {
        defaults.removeObject(forKey: key)
        NotificationCenter.default.post(
            name: Self.installationsDidChangeNotification,
            object: nil
        )
    }

    private func record(_ record: IncompleteSiteRootInstallation) throws {
        var retained = try records()
        retained.append(record)
        try persist(Array(try reconcile(retained).suffix(maximumRecords)))
    }

    private func reconcile(
        _ records: [IncompleteSiteRootInstallation]
    ) throws -> [IncompleteSiteRootInstallation] {
        let groups = Dictionary(grouping: records, by: \.authorityHost)
        return try groups.keys.sorted().map { host in
            let records = groups[host]!
            let allEvidence = records.flatMap(\.evidence).sorted {
                if $0.recordedAt != $1.recordedAt { return $0.recordedAt < $1.recordedAt }
                return $0.id.uuidString < $1.id.uuidString
            }
            let strongest: SiteRootSetupPhase = records.contains {
                $0.setupPhase == .identityEnrolmentRequired
            } ? .identityEnrolmentRequired : .authorityCustodyRequired
            let boundedEvidence = Array(allEvidence.suffix(16))
            let latest = boundedEvidence.last!
            let stableID = records.map(\.id).min { $0.uuidString < $1.uuidString }!
            return try IncompleteSiteRootInstallation(
                id: stableID, authorityHost: host,
                redactedReference: latest.redactedReference,
                recordedAt: latest.recordedAt, setupPhase: strongest,
                evidence: boundedEvidence
            )
        }
    }

    private func persist(
        _ retained: [IncompleteSiteRootInstallation], notify: Bool = true
    ) throws {
        let encoded = try JSONEncoder().encode(retained)
        guard encoded.count <= maximumEncodedBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        defaults.set(encoded, forKey: key)
        if notify {
            NotificationCenter.default.post(name: Self.installationsDidChangeNotification, object: nil)
        }
    }
}
