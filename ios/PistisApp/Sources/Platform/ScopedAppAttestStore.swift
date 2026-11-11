import Foundation
import CryptoKit
import Security

/// Local staging only. A committed record is not authority evidence and must
/// not activate an installation without the separately verified handoff.
struct ScopedAppAttestPending: Codable, Equatable, Sendable {
    let attemptID: UUID
    let correlation: Data
    let registrationReference: String
    let siteClaim: String
    let appClaim: String
    let environmentClaim: String
    let keyID: String
    /// Exact prepared registration bytes; retry must not create a new key.
    let preparedRegistration: Data

    func validate() throws {
        guard attemptID.uuidString != "00000000-0000-0000-0000-000000000000",
              correlation.count == 32, !correlation.allSatisfy({ $0 == 0 }),
              !registrationReference.isEmpty, registrationReference.utf8.count <= 128,
              registrationReference.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                      || [45, 46, 58, 95].contains($0)
              }),
              !siteClaim.isEmpty, siteClaim.utf8.count <= 255,
              appClaim == AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
              ["Production", "Development"].contains(environmentClaim),
              !preparedRegistration.isEmpty, preparedRegistration.count <= 300_000,
              PendingAppAttestReplacementKeyV1.canonicalKeyID(keyID) != nil
        else { throw PlatformFailure.appAttestInvalidInput }
    }
}

struct ScopedAppAttestBinding: Codable, Equatable, Sendable {
    let attemptID: UUID
    let installationID: Data
    let site: String
    let appIdentifier: String
    let environment: String
    let keyID: String
    let policyGeneration: UInt64
    let revocationGeneration: UInt64

    func validate() throws {
        guard installationID.count == 16, !installationID.allSatisfy({ $0 == 0 }),
              !site.isEmpty, site.utf8.count <= 255,
              appIdentifier == AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
              ["Production", "Development"].contains(environment),
              PendingAppAttestReplacementKeyV1.canonicalKeyID(keyID) != nil
        else { throw PlatformFailure.appAttestInvalidInput }
    }
}

protocol ScopedAppAttestPersistence: AnyObject {
    func read(account: String) throws -> Data?
    /// Returns false for an existing item without changing it.
    func add(account: String, data: Data) throws -> Bool
    func entries() throws -> [(String, Data)]
    func remove(account: String) throws
    func removeAll() throws
}

private final class ScopedAppAttestKeychainPersistence: ScopedAppAttestPersistence {
    private let service: String
    init(service: String) { self.service = service }
    private func base() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
    }
    private func query(_ account: String) -> [String: Any] {
        base().merging([kSecAttrAccount as String: account]) { _, new in new }
    }
    func read(account: String) throws -> Data? {
        var request = query(account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
        return data
    }
    func add(account: String, data: Data) throws -> Bool {
        let attributes: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemAdd(query(account).merging(attributes) { _, new in new } as CFDictionary, nil)
        if status == errSecDuplicateItem { return false }
        guard status == errSecSuccess else { throw PlatformFailure.appAttestKeyCreationFailed }
        return true
    }
    func entries() throws -> [(String, Data)] {
        var request = base()
        request[kSecReturnAttributes as String] = true
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitAll
        var item: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &item)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = item as? [[String: Any]] else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
        return try items.map { entry in
            guard let account = entry[kSecAttrAccount as String] as? String,
                  let data = entry[kSecValueData as String] as? Data
            else { throw PlatformFailure.invalidConfiguration }
            return (account, data)
        }
    }
    func remove(account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
    }
    func removeAll() throws {
        let status = SecItemDelete(base() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
    }
}

/// A staged receipt is not in the active installation inventory. Its
/// association with the broker attempt remains unverified until the separate
/// authority handoff succeeds.
struct ScopedStagedEnrollment: Codable, Equatable, Sendable {
    let attemptID: UUID
    let output: AuthenticatedEnrollmentOutput
}

/// The marker proves only local pre-send staging, never server acceptance.
/// Unauthorising recovery material. Exact bytes are retained for reconciliation.
struct ScopedAttendedRecoveryProof: Codable, Equatable, Sendable {
    let attemptID: UUID
    let correlation: Data
    let transcriptDigest: Data
    let nonce: Data
    let expiresAt: UInt64
    let relaySecret: Data
    let proof: Data

    func validate() throws {
        guard correlation.count == 32, !correlation.allSatisfy({ $0 == 0 }),
              transcriptDigest.count == 32, !transcriptDigest.allSatisfy({ $0 == 0 }),
              nonce.count == 32, !nonce.allSatisfy({ $0 == 0 }), expiresAt > 0,
              relaySecret.count == 32, !relaySecret.allSatisfy({ $0 == 0 }),
              !proof.isEmpty, proof.count <= 16_384 else { throw PlatformFailure.invalidConfiguration }
    }
}

struct ScopedSubmittedAttempt: Sendable {
    fileprivate let pending: ScopedAppAttestPending
    var keyID: String { pending.keyID }
    var siteClaim: String { pending.siteClaim }
    var appClaim: String { pending.appClaim }
    var environmentClaim: String { pending.environmentClaim }
    func matchesRecovery(_ transcript: AttendedRecoveryTranscriptV1) -> Bool {
        var operation = pending.attemptID.uuid
        let operationBytes = withUnsafeBytes(of: &operation) { Data($0) }
        return transcript.operation == operationBytes && transcript.correlation == pending.correlation
            && transcript.reference == pending.registrationReference && transcript.site == pending.siteClaim
    }
    func matchesStatus(_ transcript: FirstDeviceStatusTranscriptV2) -> Bool {
        let digest = Data(SHA256.hash(
            data: Data("mnemosyne.monas.first-device.correlation.v2\0".utf8) + pending.correlation
        ))
        return transcript.reference == pending.registrationReference && transcript.correlationDigest == digest
    }
    fileprivate init(_ pending: ScopedAppAttestPending) { self.pending = pending }
}

enum AppAttestReferenceScope {
    /// Only for the separately verified, unambiguous legacy installation.
    case legacy
    case installation(Data)
}

private struct BrokerAttemptReservation: Codable, Equatable {
    let attemptID: UUID
    let presentationDigest: Data
}

struct ProvisionalBrokerPresentation: Codable, Equatable {
    let attemptID: UUID
    let installationID: Data
    let presentationDigest: Data
    let qrText: String
    let verifiedAtMillis: UInt64
}

struct ProvisionalLeafHandoff: Codable, Equatable {
    let attemptID: UUID
    let wrapper: Data
    let verifiedAtSeconds: UInt64
}

/// Create-once keychain records. All operations in the Pistis process share
/// one lock; no app extension or other process may write this private service.
/// Cancellation markers remain until explicit reset, so a crash cannot turn a
/// cancelled attempt into a fresh one. Once marked, pending secrets are erased. The caller must
/// authenticate the eventual Monas handoff before recording a binding.
// All persistence access is serialized by the process-wide lock below.
final class ScopedAppAttestStore: @unchecked Sendable {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var activeDispatches = 0 // Protected by lock.
    private nonisolated(unsafe) static var resetInProgress = false // Protected by lock.
    private nonisolated(unsafe) static var legacyWriteInProgress = false // Protected by lock.
    private static let productionService = "org.mnemosynebiosciences.pistis.app-attest-scoped.v1"
    private let persistence: any ScopedAppAttestPersistence

    init() {
        persistence = ScopedAppAttestKeychainPersistence(service: Self.productionService)
    }
    init(persistence: any ScopedAppAttestPersistence) { self.persistence = persistence }
#if DEBUG
    /// Isolated simulator test service; cannot address the production service.
    init(testService: String) throws {
        guard testService.hasPrefix("org.mnemosynebiosciences.pistis.test.scoped."),
              UUID(uuidString: String(testService.dropFirst("org.mnemosynebiosciences.pistis.test.scoped.".count))) != nil
        else { throw PlatformFailure.invalidConfiguration }
        persistence = ScopedAppAttestKeychainPersistence(service: testService)
    }
#endif

    func stage(_ pending: ScopedAppAttestPending) throws {
        try pending.validate()
        try withLock {
            guard try readData(account: cancelled(pending.attemptID)) == nil,
                  try readData(account: completed(pending.attemptID)) == nil
            else { throw PlatformFailure.invalidConfiguration }
            try createOnce(pending, account: staged(pending.attemptID))
        }
    }

    /// A protected create-once correlation reservation lets a rescan recover
    /// the original operation even if key generation was interrupted.
    func reserveBrokerAttempt(_ presentation: SiteRootBrokerPresentationV2) throws -> UUID {
        try withLock {
            guard !Self.resetInProgress, !Self.legacyWriteInProgress else { throw PlatformFailure.enrolmentBeginRetryRequired }
            let digest = SHA256.hash(data: Data("pistis:broker-attempt:v2\0".utf8) + presentation.correlation)
            let account = "broker." + digest.map { String(format: "%02x", $0) }.joined()
            if let existing = try read(BrokerAttemptReservation.self, account: account) {
                guard existing.presentationDigest == presentation.presentationDigest,
                      existing.attemptID.uuidString != "00000000-0000-0000-0000-000000000000"
                else { throw PlatformFailure.invalidConfiguration }
                return existing.attemptID
            }
            let value = BrokerAttemptReservation(attemptID: UUID(), presentationDigest: presentation.presentationDigest)
            try createOnce(value, account: account)
            return value.attemptID
        }
    }

    /// A reset or cancellation during Apple key generation invalidates the
    /// marker, preventing the returning asynchronous operation from staging.
    func stagePrepared(_ pending: ScopedAppAttestPending) throws {
        try pending.validate()
        try withLock {
            guard !Self.resetInProgress,
                  try read(UUID.self, account: preparing(pending.attemptID)) == pending.attemptID,
                  try readData(account: cancelled(pending.attemptID)) == nil,
                  try readData(account: completed(pending.attemptID)) == nil,
                  try readData(account: submitted(pending.attemptID)) == nil
            else { throw PlatformFailure.invalidConfiguration }
            try createOnce(pending, account: staged(pending.attemptID))
        }
    }

    /// Atomically records intent before generating an Apple key. An orphaned
    /// marker is ambiguous and blocks automatic generation on restart.
    func markPreparing(_ attemptID: UUID) throws {
        try withLock {
            guard !Self.resetInProgress,
                  try readData(account: staged(attemptID)) == nil,
                  try readData(account: submitted(attemptID)) == nil,
                  try readData(account: cancelled(attemptID)) == nil,
                  try readData(account: completed(attemptID)) == nil,
                  try readData(account: preparing(attemptID)) == nil
            else { throw PlatformFailure.invalidConfiguration }
            try createOnce(attemptID, account: preparing(attemptID))
        }
    }

    /// An orphaned pre-send attempt may be abandoned by exact ID. The Apple
    /// key may remain OS-managed; no other local credential is deleted.
    func abandonPreparing(_ attemptID: UUID) throws {
        try withLock {
            guard try read(UUID.self, account: preparing(attemptID)) == attemptID,
                  try readData(account: staged(attemptID)) == nil,
                  try readData(account: submitted(attemptID)) == nil,
                  try readData(account: completed(attemptID)) == nil
            else { throw PlatformFailure.invalidConfiguration }
            try createOnce(attemptID, account: cancelled(attemptID))
        }
    }

    /// Persist this marker before any network submission. A submitted attempt
    /// remains pending until authenticated reconciliation, never local cancel.
    func markSubmitted(attemptID: UUID) throws {
        try withLock {
            guard try readData(account: cancelled(attemptID)) == nil,
                  try readData(account: completed(attemptID)) == nil,
                  let value = try read(ScopedAppAttestPending.self, account: staged(attemptID)),
                  value.attemptID == attemptID else { throw PlatformFailure.invalidConfiguration }
            try value.validate()
            try createOnce(attemptID, account: submitted(attemptID))
        }
    }

    /// Holds a process-wide lifetime claim until the network operation ends.
    /// Reset is refused while a claim exists, including cancellation cleanup.
    func beginDispatch(attemptID: UUID, expected: ScopedAppAttestPending) throws -> ScopedAppAttestPending {
        try withLock {
            guard !Task.isCancelled, !Self.resetInProgress,
                  try readData(account: cancelled(attemptID)) == nil,
                  try readData(account: completed(attemptID)) == nil,
                  try readData(account: submitted(attemptID)) == nil,
                  let pending = try read(ScopedAppAttestPending.self, account: staged(attemptID)),
                  pending.attemptID == attemptID, pending == expected else { throw PlatformFailure.invalidConfiguration }
            try pending.validate()
            try createOnce(attemptID, account: submitted(attemptID))
            Self.activeDispatches += 1
            return pending
        }
    }

    func endDispatch() {
        withLock {
            precondition(Self.activeDispatches > 0)
            Self.activeDispatches -= 1
        }
    }

    func beginSubmittedPoll(attemptID: UUID, expected: ScopedAppAttestPending) throws {
        try withLock {
            guard !Task.isCancelled, !Self.resetInProgress,
                  try read(UUID.self, account: submitted(attemptID)) == attemptID,
                  try readData(account: cancelled(attemptID)) == nil,
                  try read(ScopedAppAttestPending.self, account: staged(attemptID)) == expected,
                  expected.attemptID == attemptID else { throw PlatformFailure.invalidConfiguration }
            try expected.validate()
            if let binding = try read(ScopedAppAttestBinding.self, account: completed(attemptID)) {
                guard binding.attemptID == attemptID, binding.keyID == expected.keyID,
                      try read(ScopedAppAttestBinding.self, account: installed(binding.installationID)) == binding
                else { throw PlatformFailure.invalidConfiguration }
            }
            Self.activeDispatches += 1
        }
    }

    /// Retains submitted capability during a partially completed promotion so
    /// the authority can be checked freshly before retrying inventory writes.
    func statusPending(attemptID: UUID) throws -> ScopedAppAttestPending? {
        try withLock {
            guard try read(UUID.self, account: submitted(attemptID)) == attemptID,
                  try readData(account: cancelled(attemptID)) == nil,
                  let pending = try read(ScopedAppAttestPending.self, account: staged(attemptID)),
                  pending.attemptID == attemptID else { return nil }
            try pending.validate()
            if let binding = try read(ScopedAppAttestBinding.self, account: completed(attemptID)) {
                guard binding.attemptID == attemptID, binding.keyID == pending.keyID,
                      try read(ScopedAppAttestBinding.self, account: installed(binding.installationID)) == binding
                else { throw PlatformFailure.invalidConfiguration }
            }
            return pending
        }
    }

    func submittedBrokerAttempt(correlation: Data, siteUUID: String) throws -> ScopedAppAttestPending? {
        guard let uuid = UUID(uuidString: siteUUID), uuid.uuidString.lowercased() == siteUUID,
              correlation.count == 32 else { throw PlatformFailure.invalidConfiguration }
        return try withLock {
            var found: [ScopedAppAttestPending] = []
            for (account, data) in try persistence.entries() where account.hasPrefix("pending.") {
                let pending = try JSONDecoder().decode(ScopedAppAttestPending.self, from: data)
                try pending.validate()
                guard account == staged(pending.attemptID) else { throw PlatformFailure.invalidConfiguration }
                if pending.siteClaim == "site-" + siteUUID,
                   try read(UUID.self, account: submitted(pending.attemptID)) == pending.attemptID,
                   try readData(account: cancelled(pending.attemptID)) == nil,
                   try readData(account: completed(pending.attemptID)) == nil {
                    guard pending.correlation == correlation else { throw PlatformFailure.siteRootBindingUnavailable }
                    found.append(pending)
                }
            }
            guard found.count <= 1 else { throw PlatformFailure.siteRootBindingUnavailable }
            return found.first
        }
    }

    func hasSubmittedBrokerAttempt() throws -> Bool {
        try withLock {
            for (account, data) in try persistence.entries() where account.hasPrefix("pending.") {
                let pending = try JSONDecoder().decode(ScopedAppAttestPending.self, from: data)
                try pending.validate()
                guard account == staged(pending.attemptID) else { throw PlatformFailure.invalidConfiguration }
                if try read(UUID.self, account: submitted(pending.attemptID)) == pending.attemptID,
                   try readData(account: cancelled(pending.attemptID)) == nil,
                   try readData(account: completed(pending.attemptID)) == nil { return true }
            }
            return false
        }
    }

    func hasAnyScopedBinding() throws -> Bool { try withLock { try !allBindings().isEmpty } }

    func stageProvisionalLeaf(_ value: ProvisionalLeafHandoff, pending: ScopedAppAttestPending) throws {
        guard value.attemptID == pending.attemptID, value.wrapper.count <= 8_192,
              value.verifiedAtSeconds > 0 else { throw PlatformFailure.invalidConfiguration }
        try withLock {
            guard !Self.resetInProgress,
                  try read(UUID.self, account: submitted(value.attemptID)) == value.attemptID,
                  try read(ScopedAppAttestPending.self, account: staged(value.attemptID)) == pending,
                  try readData(account: completed(value.attemptID)) == nil
            else { throw PlatformFailure.invalidConfiguration }
            let account = "leaf." + value.attemptID.uuidString
            if let existing = try read(ProvisionalLeafHandoff.self, account: account) {
                guard existing.attemptID == value.attemptID, existing.wrapper == value.wrapper else {
                    throw PlatformFailure.invalidConfiguration
                }
            } else { try createOnce(value, account: account) }
        }
    }

    func provisionalLeaf(attemptID: UUID) throws -> ProvisionalLeafHandoff? {
        try withLock { try read(ProvisionalLeafHandoff.self, account: "leaf." + attemptID.uuidString) }
    }

    func requireFreshCustodyStep(_ step: String, pending: ScopedAppAttestPending) throws {
        guard ["assertion", "begin", "complete"].contains(step) else { throw PlatformFailure.invalidConfiguration }
        try withLock {
            guard try read(ScopedAppAttestPending.self, account: staged(pending.attemptID)) == pending,
                  try read(UUID.self, account: submitted(pending.attemptID)) == pending.attemptID,
                  try readData(account: "custody." + step + "." + pending.attemptID.uuidString) == nil
            else { throw PlatformFailure.enrolmentBeginRetryRequired }
        }
    }

    func markCustodyStep(_ step: String, pending: ScopedAppAttestPending) throws {
        guard ["assertion", "begin", "complete"].contains(step) else { throw PlatformFailure.invalidConfiguration }
        try withLock {
            let account = "custody." + step + "." + pending.attemptID.uuidString
            guard !Self.resetInProgress,
                  try read(ScopedAppAttestPending.self, account: staged(pending.attemptID)) == pending,
                  try read(UUID.self, account: submitted(pending.attemptID)) == pending.attemptID,
                  try readData(account: account) == nil else { throw PlatformFailure.enrolmentBeginRetryRequired }
            if step == "begin" || step == "complete" {
                let previous = step == "begin" ? "assertion" : "begin"
                guard try read(UUID.self, account: "custody." + previous + "." + pending.attemptID.uuidString) == pending.attemptID
                else { throw PlatformFailure.enrolmentBeginRetryRequired }
            }
            try createOnce(pending.attemptID, account: account)
        }
    }

    func markInitialProofSubmitted(attemptID: UUID, expected: ScopedAppAttestPending) throws {
        try withLock {
            guard !Self.resetInProgress,
                  try read(UUID.self, account: submitted(attemptID)) == attemptID,
                  try read(ScopedAppAttestPending.self, account: staged(attemptID)) == expected,
                  try readData(account: "proof-submitted." + attemptID.uuidString) == nil
            else { throw PlatformFailure.invalidConfiguration }
            try createOnce(attemptID, account: "proof-submitted." + attemptID.uuidString)
        }
    }

    static func beginLocalReset() throws {
        lock.lock(); defer { lock.unlock() }
        guard activeDispatches == 0, !resetInProgress, !legacyWriteInProgress else {
            throw PlatformFailure.enrolmentBeginRetryRequired
        }
        resetInProgress = true
    }

    func beginLegacyGlobalWrite() throws {
        try withLock {
            guard !Self.resetInProgress, !Self.legacyWriteInProgress, Self.activeDispatches == 0,
                  try allBindings().isEmpty,
                  try !persistence.entries().contains(where: { $0.0.hasPrefix("broker.") || $0.0.hasPrefix("pending.") })
            else { throw PlatformFailure.siteRootBindingUnavailable }
            Self.legacyWriteInProgress = true
        }
    }

    func endLegacyGlobalWrite() {
        withLock { precondition(Self.legacyWriteInProgress); Self.legacyWriteInProgress = false }
    }

    static func endLocalReset() {
        lock.lock(); defer { lock.unlock() }
        precondition(resetInProgress)
        resetInProgress = false
    }

    func pending(attemptID: UUID) throws -> ScopedAppAttestPending? {
        try withLock {
            if let cancellation = try read(UUID.self, account: cancelled(attemptID)) {
                guard cancellation == attemptID else { throw PlatformFailure.invalidConfiguration }
                try persistence.remove(account: staged(attemptID))
                return nil
            }
            if let completion = try read(ScopedAppAttestBinding.self, account: completed(attemptID)) {
                try completion.validate()
                guard completion.attemptID == attemptID,
                      try read(ScopedAppAttestBinding.self, account: installed(completion.installationID)) == completion
                else { throw PlatformFailure.invalidConfiguration }
                return nil
            }
            guard let value = try read(ScopedAppAttestPending.self, account: staged(attemptID)) else { return nil }
            try value.validate()
            guard value.attemptID == attemptID else { throw PlatformFailure.invalidConfiguration }
            return value
        }
    }

    /// Returns pending context only after the durable pre-send marker exists.
    func submittedAttempt(attemptID: UUID) throws -> ScopedSubmittedAttempt? {
        try withLock {
            guard try read(UUID.self, account: submitted(attemptID)) == attemptID,
                  try readData(account: cancelled(attemptID)) == nil,
                  try readData(account: completed(attemptID)) == nil,
                  let value = try read(ScopedAppAttestPending.self, account: staged(attemptID))
            else { return nil }
            try value.validate()
            guard value.attemptID == attemptID else { throw PlatformFailure.invalidConfiguration }
            return ScopedSubmittedAttempt(value)
        }
    }

    /// Associates an attended, independently verified V4 scan with the only
    /// pending operation for receipt staging. This is not authority evidence.
    func stageProvisionalPresentation(installationID: Data, digest: Data,
                                      qrText: String, verifiedAtMillis: UInt64) throws -> UUID {
        guard installationID.count == 16, !installationID.allSatisfy({ $0 == 0 }),
              digest.count == 32, !digest.allSatisfy({ $0 == 0 }),
              qrText.hasPrefix("PISTIS1:"), qrText.utf8.count <= 8_192, verifiedAtMillis > 0
        else { throw PlatformFailure.invalidConfiguration }
        return try withLock {
            guard !Self.resetInProgress else { throw PlatformFailure.enrolmentBeginRetryRequired }
            var candidates: [ScopedAppAttestPending] = []
            for (account, data) in try persistence.entries() where account.hasPrefix("pending.") {
                let value = try JSONDecoder().decode(ScopedAppAttestPending.self, from: data)
                try value.validate()
                guard account == staged(value.attemptID) else { throw PlatformFailure.invalidConfiguration }
                if try read(UUID.self, account: submitted(value.attemptID)) == value.attemptID,
                   try readData(account: cancelled(value.attemptID)) == nil,
                   try readData(account: completed(value.attemptID)) == nil {
                    candidates.append(value)
                }
            }
            guard candidates.count == 1, let pending = candidates.first else {
                throw PlatformFailure.siteRootBindingUnavailable
            }
            let account = "provisional." + pending.attemptID.uuidString
            if let existing = try read(ProvisionalBrokerPresentation.self, account: account) {
                guard existing.attemptID == pending.attemptID, existing.installationID == installationID,
                      existing.presentationDigest == digest, existing.qrText == qrText else {
                    throw PlatformFailure.invalidConfiguration
                }
                return existing.attemptID
            }
            let value = ProvisionalBrokerPresentation(attemptID: pending.attemptID,
                installationID: installationID, presentationDigest: digest,
                qrText: qrText, verifiedAtMillis: verifiedAtMillis)
            try createOnce(value, account: account)
            return pending.attemptID
        }
    }

    func provisionalPresentation(attemptID: UUID) throws -> ProvisionalBrokerPresentation? {
        try withLock { try read(ProvisionalBrokerPresentation.self, account: "provisional." + attemptID.uuidString) }
    }

    func soleRecoverablePresentation() throws -> ProvisionalBrokerPresentation? {
        try withLock {
            var matches: [ProvisionalBrokerPresentation] = []
            for (account, data) in try persistence.entries() where account.hasPrefix("provisional.") {
                let value = try JSONDecoder().decode(ProvisionalBrokerPresentation.self, from: data)
                guard account == "provisional." + value.attemptID.uuidString else { throw PlatformFailure.invalidConfiguration }
                if try read(UUID.self, account: submitted(value.attemptID)) == value.attemptID,
                   try readData(account: staged(value.attemptID)) != nil,
                   try read(ScopedStagedEnrollment.self, account: enrollment(value.attemptID)) != nil {
                    matches.append(value)
                }
            }
            guard matches.count <= 1 else { throw PlatformFailure.siteRootBindingUnavailable }
            return matches.first
        }
    }

    /// Retains a separately verified enrolment output without selecting it or
    /// adding it to InstallationTrustKeychain. It does not establish a link
    /// from the broker operation to the receipt's installation.
    func stageEnrollment(_ value: ScopedStagedEnrollment) throws {
        try withLock {
            guard try read(UUID.self, account: submitted(value.attemptID)) == value.attemptID,
                  try readData(account: cancelled(value.attemptID)) == nil,
                  try readData(account: completed(value.attemptID)) == nil,
                  let pending = try read(ScopedAppAttestPending.self, account: staged(value.attemptID)),
                  pending.attemptID == value.attemptID else { throw PlatformFailure.invalidConfiguration }
            try pending.validate()
            try createOnce(value, account: enrollment(value.attemptID))
        }
    }

    func stagedEnrollment(attemptID: UUID) throws -> ScopedStagedEnrollment? {
        try withLock {
            guard let value = try read(ScopedStagedEnrollment.self, account: enrollment(attemptID)) else { return nil }
            guard value.attemptID == attemptID else { throw PlatformFailure.invalidConfiguration }
            return value
        }
    }

    /// Persistence primitive only; call only after exact authority acceptance.
    func commit(_ binding: ScopedAppAttestBinding, retainPending: Bool = false) throws {
        try binding.validate()
        try withLock {
            guard try readData(account: cancelled(binding.attemptID)) == nil else {
                throw PlatformFailure.invalidConfiguration
            }
            if let marker = try read(ScopedAppAttestBinding.self, account: completed(binding.attemptID)) {
                guard marker == binding,
                      try read(ScopedAppAttestBinding.self, account: installed(binding.installationID)) == binding
                else { throw PlatformFailure.invalidConfiguration }
                if !retainPending { try persistence.remove(account: staged(binding.attemptID)) }
                return
            }
            guard try read(UUID.self, account: submitted(binding.attemptID)) == binding.attemptID,
                  let pending = try read(ScopedAppAttestPending.self, account: staged(binding.attemptID)),
                  pending.siteClaim == binding.site, pending.appClaim == binding.appIdentifier,
                  pending.environmentClaim == binding.environment, pending.keyID == binding.keyID
            else { throw PlatformFailure.invalidConfiguration }
            try pending.validate()
            guard pending.attemptID == binding.attemptID else { throw PlatformFailure.invalidConfiguration }
            let existingForAttempt = try allBindings().filter { $0.attemptID == binding.attemptID }
            guard existingForAttempt.allSatisfy({ $0 == binding }) else {
                throw PlatformFailure.invalidConfiguration
            }
            try createOnce(binding, account: installed(binding.installationID))
            try createOnce(binding, account: completed(binding.attemptID))
            if !retainPending { try persistence.remove(account: staged(binding.attemptID)) }
        }
    }

    func binding(installationID: Data) throws -> ScopedAppAttestBinding? {
        guard installationID.count == 16 else { throw PlatformFailure.invalidConfiguration }
        return try withLock {
            guard let value = try read(ScopedAppAttestBinding.self, account: installed(installationID)),
                  let marker = try read(ScopedAppAttestBinding.self, account: completed(value.attemptID)),
                  value == marker else { return nil }
            try value.validate()
            guard value.installationID == installationID else { throw PlatformFailure.invalidConfiguration }
            return value
        }
    }

    /// Inactive create-once staging only; this does not authenticate or dispatch a proof.
    func stageAttendedRecoveryProof(_ value: ScopedAttendedRecoveryProof) throws {
        try value.validate()
        try withLock {
            guard !Self.resetInProgress,
                  try read(UUID.self, account: submitted(value.attemptID)) == value.attemptID,
                  try readData(account: cancelled(value.attemptID)) == nil,
                  try readData(account: completed(value.attemptID)) == nil,
                  let pending = try read(ScopedAppAttestPending.self, account: staged(value.attemptID)),
                  pending.attemptID == value.attemptID, pending.correlation == value.correlation
            else { throw PlatformFailure.invalidConfiguration }
            try pending.validate()
            try createOnce(value, account: "attended-proof." + value.attemptID.uuidString)
        }
    }

    /// Reopening returns only the identical stored material; expiry does not erase evidence.
    func attendedRecoveryProof(attemptID: UUID) throws -> ScopedAttendedRecoveryProof? {
        try withLock {
            guard let value = try read(ScopedAttendedRecoveryProof.self, account: "attended-proof." + attemptID.uuidString)
            else { return nil }
            try value.validate()
            guard value.attemptID == attemptID,
                  try read(UUID.self, account: submitted(attemptID)) == attemptID,
                  try readData(account: cancelled(attemptID)) == nil,
                  let pending = try read(ScopedAppAttestPending.self, account: staged(attemptID)),
                  pending.correlation == value.correlation else { throw PlatformFailure.invalidConfiguration }
            try pending.validate()
            return value
        }
    }

    /// A scoped lookup never reads or falls back to the legacy primary item.
    /// The caller must establish that a legacy lookup is unambiguous.
    func reference(
        for scope: AppAttestReferenceScope, legacy: () throws -> String?
    ) throws -> String? {
        switch scope {
        case .legacy: return try legacy()
        case let .installation(id): return try binding(installationID: id)?.keyID
        }
    }

    /// Cancels only this exact attempt and never deletes a committed reference.
    func cancel(attemptID: UUID) throws {
        try withLock {
            if let marker = try read(UUID.self, account: cancelled(attemptID)) {
                guard marker == attemptID else { throw PlatformFailure.invalidConfiguration }
                try persistence.remove(account: staged(attemptID))
                return
            }
            guard let pending = try read(ScopedAppAttestPending.self, account: staged(attemptID)),
                  try readData(account: completed(attemptID)) == nil,
                  try readData(account: submitted(attemptID)) == nil
            else { throw PlatformFailure.invalidConfiguration }
            // A crash between the two commit writes may already have stored an
            // installation binding. Never cancel an attempt in that state.
            if try allBindings().contains(where: { $0.attemptID == attemptID }) {
                throw PlatformFailure.invalidConfiguration
            }
            try pending.validate()
            guard pending.attemptID == attemptID else { throw PlatformFailure.invalidConfiguration }
            try createOnce(attemptID, account: cancelled(attemptID))
            try persistence.remove(account: staged(attemptID))
        }
    }

    func resetAll() throws {
        try withLock {
            guard Self.activeDispatches == 0 else { throw PlatformFailure.enrolmentBeginRetryRequired }
            try persistence.removeAll()
        }
    }

    private func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        Self.lock.lock(); defer { Self.lock.unlock() }
        return try operation()
    }
    private func staged(_ id: UUID) -> String { "pending." + id.uuidString }
    private func preparing(_ id: UUID) -> String { "preparing." + id.uuidString }
    private func enrollment(_ id: UUID) -> String { "enrollment." + id.uuidString }
    private func cancelled(_ id: UUID) -> String { "cancelled." + id.uuidString }
    private func completed(_ id: UUID) -> String { "completed." + id.uuidString }
    private func submitted(_ id: UUID) -> String { "submitted." + id.uuidString }
    private func installed(_ id: Data) -> String { "installation." + id.map { String(format: "%02x", $0) }.joined() }
    private func readData(account: String) throws -> Data? {
        try persistence.read(account: account)
    }
    private func read<T: Decodable>(_ type: T.Type, account: String) throws -> T? {
        guard let data = try readData(account: account) else { return nil }
        guard data.count <= 1_048_576 else { throw PlatformFailure.invalidConfiguration }
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw PlatformFailure.invalidConfiguration }
    }
    private func createOnce<T: Codable & Equatable>(_ value: T, account: String) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard data.count <= 1_048_576 else { throw PlatformFailure.invalidConfiguration }
        if try !persistence.add(account: account, data: data) {
            guard try read(T.self, account: account) == value else { throw PlatformFailure.invalidConfiguration }
        }
    }
    private func allBindings() throws -> [ScopedAppAttestBinding] {
        try persistence.entries().compactMap { account, data in
            guard account.hasPrefix("installation.") else { return nil }
            do {
                let value = try JSONDecoder().decode(ScopedAppAttestBinding.self, from: data)
                try value.validate()
                guard account == installed(value.installationID) else { throw PlatformFailure.invalidConfiguration }
                return value
            } catch { throw PlatformFailure.invalidConfiguration }
        }
    }
}
