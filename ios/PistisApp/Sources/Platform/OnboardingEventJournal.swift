import CryptoKit
import Foundation

/// The onboarding routes for which the iPhone may retain a diagnostic event.
/// These are closed values so caller input cannot become an event category.
enum OnboardingEventFlow: String, Codable, CaseIterable, Sendable {
    case firstDeviceSiteRoot = "site_root_first_device"
    case siteRootDelegation = "site_root_delegation"
    case providerEnrolment = "provider_enrolment"
}

enum OnboardingEventKind: String, Codable, CaseIterable, Sendable {
    case qrValidated = "qr_validated"
    case stageEntered = "stage_entered"
    case completed
    case failed
    case cancelled
}

enum OnboardingEventStage: String, Codable, CaseIterable, Sendable {
    case qrValidation = "qr_validation"
    case siteRootKey = "site_root_key"
    case appAttest = "app_attest"
    case monasDelegation = "monas_delegation"
    case delegationPoll = "delegation_poll"
    case siteRootProof = "site_root_proof"
    case proofResponse = "proof_response"
    case faceID = "face_id"
    case providerVerification = "provider_verification"
    case deviceRegistration = "device_registration"
}

enum OnboardingEventOutcome: String, Codable, CaseIterable, Sendable {
    case accepted
    case started
    case succeeded
    case rejected
    case failed
    case cancelled
}

/// An authority label, never the QR or runtime URL itself.
enum OnboardingEventAuthority: String, Codable, CaseIterable, Sendable {
    case fixedInstallBroker = "fixed_install_broker"
    case configuredSiteRoot = "configured_site_root"
}

/// Coarse failure categories safe for a diagnostic outbox.
enum OnboardingEventFailureCode: String, Codable, CaseIterable, Sendable {
    case configuration
    case qrValidation = "qr_validation"
    case camera
    case secureHardware = "secure_hardware"
    case appAttest = "app_attest"
    case authorityUnavailable = "authority_unavailable"
    case authorityRejected = "authority_rejected"
    case timeout
    case provider
    case storage
    case cancelled
    case unknown
}

/// A single bounded, redacted observation of an onboarding transition.
///
/// This value intentionally has no free-form diagnostic text. References are
/// represented only by a SHA-256 digest encoded as canonical base64url, and
/// authority URLs are reduced to a closed label. It is not an authentication
/// input, a local authority record, or a replacement for the installation's
/// authoritative audit.
struct OnboardingEvent: Codable, Hashable, Identifiable, Sendable {
    static let schema = "pistis.ios.onboarding-event.v1"

    let schema: String
    let id: UUID
    let attemptID: UUID
    let flow: OnboardingEventFlow
    let kind: OnboardingEventKind
    let stage: OnboardingEventStage
    let outcome: OnboardingEventOutcome
    let sequence: UInt32
    let elapsedMs: UInt32
    let httpStatus: UInt16
    let referenceDigestB64URL: String?
    let authority: OnboardingEventAuthority
    let failure: OnboardingEventFailureCode?
    let occurredAtUnixMillis: UInt64

    init(
        id: UUID,
        attemptID: UUID,
        flow: OnboardingEventFlow,
        kind: OnboardingEventKind,
        stage: OnboardingEventStage,
        outcome: OnboardingEventOutcome,
        sequence: UInt32 = 1,
        elapsedMs: UInt32 = 0,
        httpStatus: UInt16 = 0,
        referenceDigest: Data? = nil,
        authority: OnboardingEventAuthority,
        failure: OnboardingEventFailureCode? = nil,
        occurredAtUnixMillis: UInt64
    ) throws {
        guard occurredAtUnixMillis > 0,
              referenceDigest.map({ $0.count == 32 && !$0.allSatisfy({ $0 == 0 }) }) ?? true,
              (1 ... 512).contains(sequence),
              elapsedMs <= 600_000,
              httpStatus == 0 || (100 ... 599).contains(httpStatus),
              Self.valid(kind: kind, outcome: outcome, failure: failure)
        else { throw PlatformFailure.invalidConfiguration }

        schema = Self.schema
        self.id = id
        self.attemptID = attemptID
        self.flow = flow
        self.kind = kind
        self.stage = stage
        self.outcome = outcome
        self.sequence = sequence
        self.elapsedMs = elapsedMs
        self.httpStatus = httpStatus
        referenceDigestB64URL = referenceDigest.map(Self.base64URL)
        self.authority = authority
        self.failure = failure
        self.occurredAtUnixMillis = occurredAtUnixMillis
    }

    /// Hash a protocol reference before it reaches any retained event.
    static func redactedDigestData(for reference: String) -> Data {
        Data(SHA256.hash(data: Data(reference.utf8)))
    }

    static func redactedDigest(for reference: String) -> String {
        base64URL(redactedDigestData(for: reference))
    }

    private static func valid(
        kind: OnboardingEventKind,
        outcome: OnboardingEventOutcome,
        failure: OnboardingEventFailureCode?
    ) -> Bool {
        switch kind {
        case .qrValidated:
            return (outcome == .accepted && failure == nil)
                || (outcome == .rejected && failure != nil)
        case .stageEntered:
            return outcome == .started || outcome == .accepted
                ? failure == nil
                : false
        case .completed:
            return outcome == .succeeded && failure == nil
        case .failed:
            return outcome == .failed && failure != nil
        case .cancelled:
            return outcome == .cancelled && failure == nil
        }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema, id
        case attemptID = "attempt_id"
        case flow, kind, stage, outcome, sequence
        case elapsedMs = "elapsed_ms"
        case httpStatus = "http_status"
        case referenceDigestB64URL = "reference_digest_b64url"
        case authority, failure
        case occurredAtUnixMillis = "occurred_at_unix_millis"
    }

    func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(schema, forKey: .schema)
        try values.encode(id, forKey: .id)
        try values.encode(attemptID, forKey: .attemptID)
        try values.encode(flow, forKey: .flow)
        try values.encode(kind, forKey: .kind)
        try values.encode(stage, forKey: .stage)
        try values.encode(outcome, forKey: .outcome)
        try values.encode(sequence, forKey: .sequence)
        try values.encode(elapsedMs, forKey: .elapsedMs)
        try values.encode(httpStatus, forKey: .httpStatus)
        try values.encode(referenceDigestB64URL, forKey: .referenceDigestB64URL)
        try values.encode(authority, forKey: .authority)
        try values.encode(failure, forKey: .failure)
        try values.encode(occurredAtUnixMillis, forKey: .occurredAtUnixMillis)
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: OnboardingEventDynamicKey.self)
        guard Set(untyped.allKeys.map(\.stringValue))
            == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw DecodingError.dataCorruptedError(
                forKey: .schema,
                in: try decoder.container(keyedBy: CodingKeys.self),
                debugDescription: "unexpected onboarding event fields: \(untyped.allKeys.map(\.stringValue).sorted())"
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let schema = try values.decode(String.self, forKey: .schema)
        let id = try values.decode(UUID.self, forKey: .id)
        let attemptID = try values.decode(UUID.self, forKey: .attemptID)
        let flow = try values.decode(OnboardingEventFlow.self, forKey: .flow)
        let kind = try values.decode(OnboardingEventKind.self, forKey: .kind)
        let stage = try values.decode(OnboardingEventStage.self, forKey: .stage)
        let outcome = try values.decode(OnboardingEventOutcome.self, forKey: .outcome)
        let sequence = try values.decode(UInt32.self, forKey: .sequence)
        let elapsedMs = try values.decode(UInt32.self, forKey: .elapsedMs)
        let httpStatus = try values.decode(UInt16.self, forKey: .httpStatus)
        let referenceDigestB64URL = try values.decodeIfPresent(
            String.self,
            forKey: .referenceDigestB64URL
        )
        let authority = try values.decode(OnboardingEventAuthority.self, forKey: .authority)
        let failure = try values.decodeIfPresent(
            OnboardingEventFailureCode.self,
            forKey: .failure
        )
        let occurredAtUnixMillis = try values.decode(UInt64.self, forKey: .occurredAtUnixMillis)

        guard schema == Self.schema,
              Self.validDigest(referenceDigestB64URL)
        else {
            throw PlatformFailure.invalidConfiguration
        }
        let referenceDigest = referenceDigestB64URL.flatMap(Self.decodeBase64URL)
        self = try Self(
            id: id,
            attemptID: attemptID,
            flow: flow,
            kind: kind,
            stage: stage,
            outcome: outcome,
            sequence: sequence,
            elapsedMs: elapsedMs,
            httpStatus: httpStatus,
            referenceDigest: referenceDigest,
            authority: authority,
            failure: failure,
            occurredAtUnixMillis: occurredAtUnixMillis
        )
    }

    private static func validDigest(_ value: String?) -> Bool {
        guard let value else { return true }
        guard let data = decodeBase64URL(value), data.count == 32,
              !data.allSatisfy({ $0 == 0 })
        else { return false }
        return base64URL(data) == value
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty,
              value.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }),
              value.count % 4 != 1
        else { return nil }
        let padding = String(repeating: "=", count: (4 - value.count % 4) % 4)
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + padding
        return Data(base64Encoded: standard)
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// A typed diagnostic batch. The upload port accepts this value rather than a
/// URL request so the eventual authority adapter owns authentication, TLS,
/// redirect, cookie and logging policy.
struct OnboardingEventUploadBatch: Codable, Sendable {
    static let schema = "pistis.ios.onboarding-event-batch.v1"
    static let maximumEvents = 16
    static let maximumEncodedBytes = 16_384

    let schema: String
    let events: [OnboardingEvent]

    init(events: [OnboardingEvent]) throws {
        guard (1 ... Self.maximumEvents).contains(events.count),
              Set(events.map(\.id)).count == events.count
        else { throw PlatformFailure.invalidConfiguration }
        schema = Self.schema
        self.events = events
    }

    func encodedBody() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        guard data.count <= Self.maximumEncodedBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        return data
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema, events
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: OnboardingEventDynamicKey.self)
        guard Set(untyped.allKeys.map(\.stringValue))
            == Set(CodingKeys.allCases.map(\.rawValue))
        else { throw PlatformFailure.invalidConfiguration }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let schema = try values.decode(String.self, forKey: .schema)
        guard schema == Self.schema else { throw PlatformFailure.invalidConfiguration }
        self = try Self(events: values.decode([OnboardingEvent].self, forKey: .events))
    }
}

struct OnboardingEventUploadReceipt: Codable, Sendable {
    static let schema = "pistis.ios.onboarding-event-upload-receipt.v1"

    let schema: String
    let acceptedEventIDs: [UUID]

    init(acceptedEventIDs: [UUID]) throws {
        guard acceptedEventIDs.count <= OnboardingEventUploadBatch.maximumEvents,
              Set(acceptedEventIDs).count == acceptedEventIDs.count
        else { throw PlatformFailure.onboardingEventUploadRejected }
        schema = Self.schema
        self.acceptedEventIDs = acceptedEventIDs
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case acceptedEventIDs = "accepted_event_ids"
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: OnboardingEventDynamicKey.self)
        guard Set(untyped.allKeys.map(\.stringValue))
            == Set(CodingKeys.allCases.map(\.rawValue))
        else { throw PlatformFailure.onboardingEventUploadRejected }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard try values.decode(String.self, forKey: .schema) == Self.schema else {
            throw PlatformFailure.onboardingEventUploadRejected
        }
        self = try Self(
            acceptedEventIDs: values.decode([UUID].self, forKey: .acceptedEventIDs)
        )
    }
}

/// The only upload dependency exposed to the iOS app. A future Monas adapter
/// must supply the authenticated, pinned HTTPS implementation; no URL or
/// bearer value is accepted by the journal and no default network route is
/// enabled by this contract.
protocol OnboardingEventUploadTransport: Sendable {
    func upload(
        _ batch: OnboardingEventUploadBatch
    ) async throws -> OnboardingEventUploadReceipt
}

struct UnavailableOnboardingEventUploadTransport: OnboardingEventUploadTransport {
    func upload(
        _: OnboardingEventUploadBatch
    ) async throws -> OnboardingEventUploadReceipt {
        throw PlatformFailure.onboardingEventUploadUnavailable
    }
}

/// Main-actor outbox coordinator. A successful receipt may acknowledge only
/// IDs present in the sent batch; everything else remains queued for retry.
@MainActor
final class OnboardingEventUploadClient {
    private let journal: OnboardingEventJournal
    private let transport: any OnboardingEventUploadTransport

    init(
        journal: OnboardingEventJournal,
        transport: any OnboardingEventUploadTransport
    ) {
        self.journal = journal
        self.transport = transport
    }

    func uploadPending() async throws -> Int {
        let pending = try journal.pendingEvents(limit: OnboardingEventUploadBatch.maximumEvents)
        guard !pending.isEmpty else { return 0 }
        let batch = try OnboardingEventUploadBatch(events: pending)
        let receipt = try await transport.upload(batch)
        let sentIDs = Set(pending.map(\.id))
        let acceptedIDs = Set(receipt.acceptedEventIDs)
        guard acceptedIDs.isSubset(of: sentIDs) else {
            throw PlatformFailure.onboardingEventUploadRejected
        }
        try journal.acknowledge(receipt.acceptedEventIDs)
        return acceptedIDs.count
    }
}

@MainActor
protocol OnboardingEventRecording: AnyObject {
    func append(_ event: OnboardingEvent) throws
}

/// Redacted, bounded local outbox. This is intentionally separate from the
/// user-facing `LocalHistoryRepository`: history is a display projection,
/// while this store is an ephemeral diagnostic queue and is never
/// authoritative. Unacknowledged rows remain available for the bounded retry
/// path until the 48-hour retention boundary.
@MainActor
final class OnboardingEventJournal: OnboardingEventRecording {
    static let shared = OnboardingEventJournal()
    static let journalDidChangeNotification = Notification.Name(
        "org.mnemosynebiosciences.pistis.onboarding-event-journal-changed"
    )
    static let maximumRecords = 64
    static let maximumEncodedBytes = 32_768
    static let retentionMillis: UInt64 = 48 * 60 * 60 * 1_000

    private let defaults: UserDefaults
    private let key = "org.mnemosynebiosciences.pistis.onboarding-event-journal.v1"
    private let nowUnixMillis: @Sendable () -> UInt64

    init(
        defaults: UserDefaults = .standard,
        nowUnixMillis: @escaping @Sendable () -> UInt64 = {
            UInt64(max(0, Date().timeIntervalSince1970 * 1_000))
        }
    ) {
        self.defaults = defaults
        self.nowUnixMillis = nowUnixMillis
        // Remove expired material as soon as the app constructs the journal;
        // `events()` also repeats this check before every read or append.
        try? _ = events()
    }

    func events() throws -> [OnboardingEvent] {
        guard let data = defaults.data(forKey: key) else { return [] }
        guard data.count <= Self.maximumEncodedBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        let decoded = try JSONDecoder().decode([OnboardingEvent].self, from: data)
        let now = nowUnixMillis()
        let retained = decoded.filter { event in
            event.occurredAtUnixMillis <= now
                && now - event.occurredAtUnixMillis <= Self.retentionMillis
        }
        if retained.count != decoded.count {
            try persist(retained)
        }
        return retained
    }

    func pendingEvents(limit: Int = OnboardingEventUploadBatch.maximumEvents) throws
        -> [OnboardingEvent]
    {
        guard (1 ... OnboardingEventUploadBatch.maximumEvents).contains(limit) else {
            throw PlatformFailure.invalidConfiguration
        }
        return Array(try events().prefix(limit))
    }

    func append(_ event: OnboardingEvent) throws {
        var retained = try events()
        if let existing = retained.first(where: { $0.id == event.id }) {
            guard existing == event else { throw PlatformFailure.invalidConfiguration }
            return
        }
        retained.append(event)
        retained = Array(retained.suffix(Self.maximumRecords))
        try persist(retained)
    }

    func acknowledge(_ ids: [UUID]) throws {
        guard Set(ids).count == ids.count else {
            throw PlatformFailure.onboardingEventUploadRejected
        }
        guard !ids.isEmpty else { return }
        let acknowledged = Set(ids)
        try persist(try events().filter { !acknowledged.contains($0.id) })
    }

    private func persist(_ events: [OnboardingEvent]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(events)
        guard encoded.count <= Self.maximumEncodedBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        defaults.set(encoded, forKey: key)
        NotificationCenter.default.post(
            name: Self.journalDidChangeNotification,
            object: nil
        )
    }
}

private struct OnboardingEventDynamicKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

extension PlatformFailure {
    /// The fixed install broker uses a coarse 503 for rejected requests and
    /// a 200 state response for an expired or consumed delegation. Preserve
    /// that bounded fact without retaining response bodies or free-form text.
    var onboardingEventHTTPStatus: UInt16 {
        switch self {
        case .siteRootGenesisRegistrationRejected,
             .siteRootGenesisDelegationUnavailable,
             .siteRootGenesisCompletionRejected:
            503
        case .siteRootGenesisDelegationExpired,
             .siteRootGenesisDelegationConsumed:
            200
        default:
            0
        }
    }

    var onboardingEventFailureCode: OnboardingEventFailureCode {
        switch self {
        case .invalidConfiguration, .randomnessUnavailable:
            .configuration
        case .cameraPermissionDenied, .cameraUnavailable:
            .camera
        case .qrPayloadTooLarge, .qrPayloadUnsupported,
             .invalidFirstDevicePresentation:
            .qrValidation
        case .secureHardwareUnavailable, .keyCreationFailed, .keyNotFound,
             .keyInvalidated, .siteRootAuthorityKeyMissing,
             .siteRootAuthorityKeyMismatch, .siteRootAuthorityKeyInvalidated,
             .publicKeyExtractionFailed, .userVerificationUnavailable,
             .userVerificationNotEnrolled, .userVerificationLockedOut,
             .userVerificationCancelled, .signingFailed, .malformedSignature:
            .secureHardware
        case .appAttestUnavailable, .appAttestInvalidInput,
             .appAttestKeyCreationFailed, .appAttestAttestationFailed,
             .appAttestAssertionFailed:
            .appAttest
        case .siteRootGenesisDelegationTimedOut:
            .timeout
        case .siteRootGenesisRegistrationRejected,
             .siteRootGenesisDelegationExpired,
             .siteRootGenesisDelegationConsumed,
             .siteRootGenesisCompletionRejected:
            .authorityRejected
        case .siteRootAuthorityUnavailable, .siteRootGenesisDelegationUnavailable,
             .siteRootGenesisTransportUnavailable, .custodyRewrapUnavailable:
            .authorityUnavailable
        case .invalidOAuthCallback, .oauthStateMismatch, .oauthDenied,
             .enrolmentBeginRetryRequired, .enrolmentRequired,
             .existingEnrolmentMustBeRemoved, .enrolmentReceiptInvalid:
            .provider
        case .enrolmentStorageFailed:
            .storage
        case .operationCancelled:
            .cancelled
        case .productionEnvelopeUnavailable, .siteX509PresentationAlreadyAttempted:
            .unknown
        case .onboardingEventUploadUnavailable, .onboardingEventUploadRejected:
            .unknown
        }
    }
}
