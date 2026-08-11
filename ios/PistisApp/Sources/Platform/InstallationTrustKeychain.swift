import Foundation
import PistisCore

#if canImport(Security)
import Security
#endif

/// Complete mobile-side output from an authenticated Prosopikon enrolment.
///
/// Only the system-browser enrolment broker may construct and install this
/// value. QR acquisition never reaches this API.
struct AuthenticatedEnrollmentOutput: Codable, Equatable, Sendable {
    let storageProfile: UInt64
    let trust: InstallationTrustRecord
    let responseContext: DeviceResponseContext
    let allowedHosts: Set<String>

    init(
        trust: InstallationTrustRecord,
        responseContext: DeviceResponseContext,
        allowedHosts: Set<String>
    ) throws {
        guard trust.userID == responseContext.userID,
              trust.externalIdentityID == responseContext.externalIdentityID,
              !allowedHosts.isEmpty,
              allowedHosts.allSatisfy({ CanonicalHTTPSHost.parse($0) != nil })
        else { throw PlatformFailure.invalidConfiguration }
        storageProfile = 2
        self.trust = trust
        self.responseContext = responseContext
        self.allowedHosts = allowedHosts
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case storageProfile
        case trust
        case responseContext
        case allowedHosts
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: TrustCodingKey.self)
        guard Set(untyped.allKeys.map(\.stringValue))
            == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "invalid trust fields")
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(UInt64.self, forKey: .storageProfile) == 2 else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "invalid storage profile")
            )
        }
        try self.init(
            trust: container.decode(InstallationTrustRecord.self, forKey: .trust),
            responseContext: container.decode(
                DeviceResponseContext.self,
                forKey: .responseContext
            ),
            allowedHosts: container.decode(Set<String>.self, forKey: .allowedHosts)
        )
    }
}

/// The exact trust profile stored before ADR 0031 added signed product
/// audiences. This type is inventory-only and can never authorise.
struct LegacyInstallationTrustRecord: Codable, Equatable, Sendable {
    let installationID: Data
    let displayName: String
    let audience: String
    let userID: Data
    let externalIdentityID: Data
    let fingerprint: Data
    let installationKeyID: Data
    let installationPublicKey: Data
    let authorityKeyID: Data
    let authorityReceipt: Data
    let policyGeneration: UInt64
    let revocationGeneration: UInt64
    let expiresAt: Date
    let active: Bool

    init(
        installationID: Data,
        displayName: String,
        audience: String,
        userID: Data,
        externalIdentityID: Data,
        fingerprint: Data,
        installationKeyID: Data,
        installationPublicKey: Data,
        authorityKeyID: Data,
        authorityReceipt: Data,
        policyGeneration: UInt64,
        revocationGeneration: UInt64,
        expiresAt: Date,
        active: Bool
    ) throws {
        guard installationID.count == 16,
              userID.count == 16,
              externalIdentityID.count == 16,
              fingerprint.count == 32,
              installationKeyID.count == 32,
              installationPublicKey.count == 33,
              authorityKeyID.count == 32,
              !authorityReceipt.isEmpty,
              Self.bounded(displayName, maximum: 128),
              Self.bounded(audience, maximum: 128)
        else { throw PlatformFailure.invalidConfiguration }
        self.installationID = installationID
        self.displayName = displayName
        self.audience = audience
        self.userID = userID
        self.externalIdentityID = externalIdentityID
        self.fingerprint = fingerprint
        self.installationKeyID = installationKeyID
        self.installationPublicKey = installationPublicKey
        self.authorityKeyID = authorityKeyID
        self.authorityReceipt = authorityReceipt
        self.policyGeneration = policyGeneration
        self.revocationGeneration = revocationGeneration
        self.expiresAt = expiresAt
        self.active = active
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case installationID
        case displayName
        case audience
        case userID
        case externalIdentityID
        case fingerprint
        case installationKeyID
        case installationPublicKey
        case authorityKeyID
        case authorityReceipt
        case policyGeneration
        case revocationGeneration
        case expiresAt
        case active
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: TrustCodingKey.self)
        guard Set(untyped.allKeys.map(\.stringValue))
            == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "invalid legacy trust fields")
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            installationID: container.decode(Data.self, forKey: .installationID),
            displayName: container.decode(String.self, forKey: .displayName),
            audience: container.decode(String.self, forKey: .audience),
            userID: container.decode(Data.self, forKey: .userID),
            externalIdentityID: container.decode(Data.self, forKey: .externalIdentityID),
            fingerprint: container.decode(Data.self, forKey: .fingerprint),
            installationKeyID: container.decode(Data.self, forKey: .installationKeyID),
            installationPublicKey: container.decode(Data.self, forKey: .installationPublicKey),
            authorityKeyID: container.decode(Data.self, forKey: .authorityKeyID),
            authorityReceipt: container.decode(Data.self, forKey: .authorityReceipt),
            policyGeneration: container.decode(UInt64.self, forKey: .policyGeneration),
            revocationGeneration: container.decode(UInt64.self, forKey: .revocationGeneration),
            expiresAt: container.decode(Date.self, forKey: .expiresAt),
            active: container.decode(Bool.self, forKey: .active)
        )
    }

    private static func bounded(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
    }
}

struct LegacyAuthenticatedEnrollmentOutput: Codable, Equatable, Sendable {
    let trust: LegacyInstallationTrustRecord
    let responseContext: DeviceResponseContext
    let allowedHosts: Set<String>

    init(
        trust: LegacyInstallationTrustRecord,
        responseContext: DeviceResponseContext,
        allowedHosts: Set<String>
    ) throws {
        guard trust.userID == responseContext.userID,
              trust.externalIdentityID == responseContext.externalIdentityID,
              !allowedHosts.isEmpty,
              allowedHosts.allSatisfy({ CanonicalHTTPSHost.parse($0) != nil })
        else { throw PlatformFailure.invalidConfiguration }
        self.trust = trust
        self.responseContext = responseContext
        self.allowedHosts = allowedHosts
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case trust
        case responseContext
        case allowedHosts
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: TrustCodingKey.self)
        guard Set(untyped.allKeys.map(\.stringValue))
            == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "invalid legacy output fields")
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            trust: container.decode(LegacyInstallationTrustRecord.self, forKey: .trust),
            responseContext: container.decode(
                DeviceResponseContext.self,
                forKey: .responseContext
            ),
            allowedHosts: container.decode(Set<String>.self, forKey: .allowedHosts)
        )
    }
}

enum EnrollmentInventoryRecord: Equatable, Sendable {
    case current(AuthenticatedEnrollmentOutput)
    case legacy(LegacyAuthenticatedEnrollmentOutput)
}

private struct TrustCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

protocol InstallationTrustStoring: InstallationTrustReading {
    func activeEnrollment() async throws -> AuthenticatedEnrollmentOutput?
    func installAuthenticated(_ output: AuthenticatedEnrollmentOutput) async throws
    func revoke(installationID: Data) async throws
}

/// Keychain-backed single-device MVP trust repository.
actor InstallationTrustKeychain: InstallationTrustStoring {
    static let shared = InstallationTrustKeychain()
    nonisolated static let enrollmentDidChangeNotification = Notification.Name(
        "org.mnemosynebiosciences.pistis.enrollment-did-change"
    )

    private let service = "org.mnemosynebiosciences.pistis.installation-trust.v1"
    private let account = "primary"

    func record(installationID: Data) throws -> InstallationTrustRecord? {
        guard let output = try loadCurrent(),
              output.trust.installationID == installationID
        else {
            return nil
        }
        return output.trust
    }

    func activeEnrollment() throws -> AuthenticatedEnrollmentOutput? {
        guard let output = try loadCurrent(), output.trust.active,
              Date() < output.trust.expiresAt
        else { return nil }
        return output
    }

    /// Return the durable record for inventory presentation, including an
    /// expired or inactive record that must no longer authorize requests.
    func enrollmentInventoryRecord() throws -> EnrollmentInventoryRecord? {
        try loadInventory()
    }

    /// Whether the create-once slot is occupied, including by expired trust.
    func hasStoredEnrollment() throws -> Bool {
        try loadInventory() != nil
    }

    func installAuthenticated(_ output: AuthenticatedEnrollmentOutput) throws {
        let disposition = try Self.firstInstallDisposition(
            existing: existingCurrentForInstall(),
            proposed: output
        )
        if disposition == .idempotent {
            NotificationCenter.default.post(
                name: Self.enrollmentDidChangeNotification,
                object: nil
            )
            return
        }
        let data = try JSONEncoder().encode(output)
        guard data.count <= 16_384 else { throw PlatformFailure.invalidConfiguration }
        #if canImport(Security)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status: OSStatus
        switch disposition {
        case .create:
            var insertion = baseQuery()
            attributes.forEach { insertion[$0.key] = $0.value }
            status = SecItemAdd(insertion as CFDictionary, nil)
        case .replace:
            status = SecItemUpdate(
                baseQuery() as CFDictionary,
                attributes as CFDictionary
            )
        case .idempotent:
            return
        }
        guard status == errSecSuccess else {
            throw PlatformFailure.invalidConfiguration
        }
        NotificationCenter.default.post(
            name: Self.enrollmentDidChangeNotification,
            object: nil
        )
        #else
        throw PlatformFailure.invalidConfiguration
        #endif
    }

    enum FirstInstallDisposition: Equatable {
        case create
        case idempotent
        case replace
    }

    static func firstInstallDisposition(
        existing: AuthenticatedEnrollmentOutput?,
        proposed: AuthenticatedEnrollmentOutput
    ) throws -> FirstInstallDisposition {
        guard let existing else { return .create }
        if existing == proposed { return .idempotent }
        guard Self.isAuthorisedReplacement(existing: existing, proposed: proposed) else {
            throw PlatformFailure.invalidConfiguration
        }
        return .replace
    }

    /// Accept only the narrow, authority-signed replacement transition. The
    /// installation and human authority remain fixed while the server advances
    /// revocation state and binds a fresh physical-device key.
    static func isAuthorisedReplacement(
        existing: AuthenticatedEnrollmentOutput,
        proposed: AuthenticatedEnrollmentOutput
    ) -> Bool {
        let old = existing.trust
        let new = proposed.trust
        guard old.installationID == new.installationID,
              old.displayName == new.displayName,
              old.audience == new.audience,
              old.authorisedProductAudiences == new.authorisedProductAudiences,
              old.userID == new.userID,
              old.externalIdentityID == new.externalIdentityID,
              old.fingerprint == new.fingerprint,
              old.installationKeyID == new.installationKeyID,
              old.installationPublicKey == new.installationPublicKey,
              old.authorityKeyID == new.authorityKeyID,
              old.policyGeneration == new.policyGeneration,
              old.revocationGeneration < UInt64.max,
              new.revocationGeneration == old.revocationGeneration + 1,
              new.expiresAt >= old.expiresAt,
              new.active,
              existing.allowedHosts == proposed.allowedHosts,
              existing.responseContext.userID == proposed.responseContext.userID,
              existing.responseContext.externalIdentityID
                  == proposed.responseContext.externalIdentityID,
              existing.responseContext.deviceID != proposed.responseContext.deviceID,
              existing.responseContext.deviceKeyID != proposed.responseContext.deviceKeyID,
              old.authorityReceipt != new.authorityReceipt
        else { return false }
        return true
    }

    func revoke(installationID: Data) throws {
        guard let current = try loadInventory() else { return }
        let storedID: Data
        switch current {
        case let .current(output):
            storedID = output.trust.installationID
        case let .legacy(output):
            storedID = output.trust.installationID
        }
        guard storedID == installationID else {
            throw PlatformFailure.invalidConfiguration
        }
        try deleteStoredEnrollment()
    }

    /// Forget local material only when it cannot authorize. This does not
    /// represent or perform authority-side revocation.
    func forgetExpired(installationID: Data, now: Date = Date()) throws {
        guard let current = try loadCurrent(),
              current.trust.installationID == installationID,
              Self.allowsLocalForget(
                  active: current.trust.active,
                  expiresAt: current.trust.expiresAt,
                  now: now
              )
        else { throw PlatformFailure.invalidConfiguration }
        try deleteStoredEnrollment()
    }

    /// Retire the exact preceding profile. It is structurally incapable of
    /// authorising in current software and this does not represent server
    /// revocation.
    func forgetIncompatible(
        installationID: Data,
        externalIdentityID: Data
    ) throws {
        guard case let .legacy(current)? = try loadInventory(),
              Self.matchesLegacyRemoval(
                  current,
                  installationID: installationID,
                  externalIdentityID: externalIdentityID
              )
        else { throw PlatformFailure.invalidConfiguration }
        try deleteStoredEnrollment()
    }

    static func matchesLegacyRemoval(
        _ current: LegacyAuthenticatedEnrollmentOutput,
        installationID: Data,
        externalIdentityID: Data
    ) -> Bool {
        current.trust.installationID == installationID
            && current.trust.externalIdentityID == externalIdentityID
    }

    static func allowsLocalForget(
        active: Bool,
        expiresAt: Date,
        now: Date
    ) -> Bool {
        !active || now >= expiresAt
    }

    private func deleteStoredEnrollment() throws {
        #if canImport(Security)
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PlatformFailure.invalidConfiguration
        }
        NotificationCenter.default.post(
            name: Self.enrollmentDidChangeNotification,
            object: nil
        )
        #else
        throw PlatformFailure.invalidConfiguration
        #endif
    }

    static func decodeInventory(_ data: Data) throws -> EnrollmentInventoryRecord {
        if let current = try? JSONDecoder().decode(
            AuthenticatedEnrollmentOutput.self,
            from: data
        ) {
            return .current(current)
        }
        do {
            return .legacy(
                try JSONDecoder().decode(
                    LegacyAuthenticatedEnrollmentOutput.self,
                    from: data
                )
            )
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
    }

    private func existingCurrentForInstall() throws -> AuthenticatedEnrollmentOutput? {
        switch try loadInventory() {
        case nil:
            return nil
        case let .current(output):
            return output
        case .legacy:
            throw PlatformFailure.invalidConfiguration
        }
    }

    private func loadCurrent() throws -> AuthenticatedEnrollmentOutput? {
        Self.currentEnrollment(from: try loadInventory())
    }

    static func currentEnrollment(
        from inventory: EnrollmentInventoryRecord?
    ) -> AuthenticatedEnrollmentOutput? {
        guard case let .current(output)? = inventory else { return nil }
        return output
    }

    private func loadInventory() throws -> EnrollmentInventoryRecord? {
        #if canImport(Security)
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              data.count <= 16_384
        else { throw PlatformFailure.invalidConfiguration }
        do {
            return try Self.decodeInventory(data)
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
        #else
        return nil
        #endif
    }

    private func baseQuery() -> [String: Any] {
        #if canImport(Security)
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
        #else
        return [:]
        #endif
    }
}
