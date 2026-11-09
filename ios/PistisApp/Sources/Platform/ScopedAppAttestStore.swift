import Foundation
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

/// The marker proves only local pre-send staging, never server acceptance.
struct ScopedSubmittedAttempt: Sendable {
    fileprivate let pending: ScopedAppAttestPending
    var keyID: String { pending.keyID }
    var siteClaim: String { pending.siteClaim }
    var appClaim: String { pending.appClaim }
    fileprivate init(_ pending: ScopedAppAttestPending) { self.pending = pending }
}

enum AppAttestReferenceScope {
    /// Only for the separately verified, unambiguous legacy installation.
    case legacy
    case installation(Data)
}

/// Create-once keychain records. All operations in the Pistis process share
/// one lock; no app extension or other process may write this private service.
/// Cancellation markers remain until explicit reset, so a crash cannot turn a
/// cancelled attempt into a fresh one. Once marked, pending secrets are erased. The caller must
/// authenticate the eventual Monas handoff before recording a binding.
// All persistence access is serialized by the process-wide lock below.
final class ScopedAppAttestStore: @unchecked Sendable {
    private static let lock = NSLock()
    private static let productionService = "org.mnemosynebiosciences.pistis.app-attest-scoped.v1"
    private let persistence: any ScopedAppAttestPersistence

    init() {
        persistence = ScopedAppAttestKeychainPersistence(service: Self.productionService)
    }
    init(persistence: any ScopedAppAttestPersistence) { self.persistence = persistence }

    func stage(_ pending: ScopedAppAttestPending) throws {
        try pending.validate()
        try withLock {
            guard try readData(account: cancelled(pending.attemptID)) == nil,
                  try readData(account: completed(pending.attemptID)) == nil
            else { throw PlatformFailure.invalidConfiguration }
            try createOnce(pending, account: staged(pending.attemptID))
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
                try persistence.remove(account: staged(attemptID))
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

    /// Persistence primitive only; call only after exact authority acceptance.
    func commit(_ binding: ScopedAppAttestBinding) throws {
        try binding.validate()
        try withLock {
            guard try readData(account: cancelled(binding.attemptID)) == nil else {
                throw PlatformFailure.invalidConfiguration
            }
            if let marker = try read(ScopedAppAttestBinding.self, account: completed(binding.attemptID)) {
                guard marker == binding,
                      try read(ScopedAppAttestBinding.self, account: installed(binding.installationID)) == binding
                else { throw PlatformFailure.invalidConfiguration }
                try persistence.remove(account: staged(binding.attemptID))
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
            try persistence.remove(account: staged(binding.attemptID))
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

    func resetAll() throws { try withLock { try persistence.removeAll() } }

    private func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        Self.lock.lock(); defer { Self.lock.unlock() }
        return try operation()
    }
    private func staged(_ id: UUID) -> String { "pending." + id.uuidString }
    private func cancelled(_ id: UUID) -> String { "cancelled." + id.uuidString }
    private func completed(_ id: UUID) -> String { "completed." + id.uuidString }
    private func submitted(_ id: UUID) -> String { "submitted." + id.uuidString }
    private func installed(_ id: Data) -> String { "installation." + id.map { String(format: "%02x", $0) }.joined() }
    private func readData(account: String) throws -> Data? {
        try persistence.read(account: account)
    }
    private func read<T: Decodable>(_ type: T.Type, account: String) throws -> T? {
        guard let data = try readData(account: account) else { return nil }
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw PlatformFailure.invalidConfiguration }
    }
    private func createOnce<T: Codable & Equatable>(_ value: T, account: String) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
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
