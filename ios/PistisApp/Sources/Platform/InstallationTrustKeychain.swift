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
    /// The exact HTTPS origin authenticated by the signed first-device
    /// presentation. Host allow-lists alone are insufficient for later
    /// authentication because they do not bind the endpoint to the presented
    /// certificate key.
    let httpsOrigin: String
    /// SHA-256 of the exact DER SubjectPublicKeyInfo for the presented TLS
    /// leaf. This is public endpoint identity, not a credential.
    let tlsSPKISHA256: Data

    init(
        trust: InstallationTrustRecord,
        responseContext: DeviceResponseContext,
        allowedHosts: Set<String>,
        httpsOrigin: String,
        tlsSPKISHA256: Data
    ) throws {
        guard trust.userID == responseContext.userID,
              trust.externalIdentityID == responseContext.externalIdentityID,
              !allowedHosts.isEmpty,
              allowedHosts.allSatisfy({ CanonicalHTTPSHost.parse($0) != nil }),
              let canonicalOrigin = CanonicalHTTPSOrigin.parse(httpsOrigin),
              tlsSPKISHA256.count == 32,
              !tlsSPKISHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.invalidConfiguration }
        storageProfile = 3
        self.trust = trust
        self.responseContext = responseContext
        self.allowedHosts = allowedHosts
        self.httpsOrigin = canonicalOrigin
        self.tlsSPKISHA256 = tlsSPKISHA256
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case storageProfile
        case trust
        case responseContext
        case allowedHosts
        case httpsOrigin
        case tlsSPKISHA256
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
        guard try container.decode(UInt64.self, forKey: .storageProfile) == 3 else {
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
            allowedHosts: container.decode(Set<String>.self, forKey: .allowedHosts),
            httpsOrigin: container.decode(String.self, forKey: .httpsOrigin),
            tlsSPKISHA256: container.decode(Data.self, forKey: .tlsSPKISHA256)
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

    var installationID: Data {
        switch self {
        case let .current(output): output.trust.installationID
        case let .legacy(output): output.trust.installationID
        }
    }
}

private struct EnrollmentInventoryV2: Codable, Equatable, Sendable {
    let storageProfile: UInt64
    let records: [AuthenticatedEnrollmentOutput]
    let selectedInstallationID: Data?

    init(records: [AuthenticatedEnrollmentOutput], selectedInstallationID: Data?) throws {
        guard Self.storageProfileValue == 3,
              records.count <= 64,
              Set(records.map { $0.trust.installationID }).count == records.count,
              records.allSatisfy({ $0.trust.installationID.count == 16 }),
              selectedInstallationID == nil
                  || records.contains(where: { $0.trust.installationID == selectedInstallationID })
        else { throw PlatformFailure.invalidConfiguration }
        storageProfile = Self.storageProfileValue
        self.records = records
        self.selectedInstallationID = selectedInstallationID
    }

    private static let storageProfileValue: UInt64 = 3

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case storageProfile
        case records
        case selectedInstallationID
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: TrustCodingKey.self)
        guard Set(untyped.allKeys.map(\.stringValue))
            == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "invalid inventory fields")
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(UInt64.self, forKey: .storageProfile) == Self.storageProfileValue
        else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "invalid inventory profile")
            )
        }
        try self.init(
            records: container.decode([AuthenticatedEnrollmentOutput].self, forKey: .records),
            selectedInstallationID: container.decodeIfPresent(Data.self, forKey: .selectedInstallationID)
        )
    }
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

/// Keychain-backed multi-installation trust repository.
///
/// The v1 `primary` item is retained as a read-only migration source. New
/// writes use the bounded v2 inventory so installations/personas are keyed by
/// their installation ID instead of replacing one another.
actor InstallationTrustKeychain: InstallationTrustStoring {
    static let shared = InstallationTrustKeychain()
    nonisolated static let enrollmentDidChangeNotification = Notification.Name(
        "org.mnemosynebiosciences.pistis.enrollment-did-change"
    )

    private let service = "org.mnemosynebiosciences.pistis.installation-trust.v1"
    private let account = "primary"
    private let inventoryService = "org.mnemosynebiosciences.pistis.installation-trust.v2"
    private let inventoryAccount = "inventory"

    func record(installationID: Data) throws -> InstallationTrustRecord? {
        guard let output = try currentRecords().first(where: {
            $0.trust.installationID == installationID
        }) else { return nil }
        return output.trust
    }

    func activeEnrollment() throws -> AuthenticatedEnrollmentOutput? {
        let records = try currentRecords()
        let active = records.filter { $0.trust.active && Date() < $0.trust.expiresAt }
        if active.count == 1 { return active[0] }
        guard let selected = try loadV2Envelope()?.selectedInstallationID else { return nil }
        return active.first { $0.trust.installationID == selected }
    }

    /// Return every locally enrolled installation. The returned array is
    /// keyed by installation ID and may contain multiple user personas.
    func enrollmentInventoryRecords() throws -> [EnrollmentInventoryRecord] {
        try loadInventoryRecords()
    }

    func activeEnrollment(for installationID: Data) throws -> AuthenticatedEnrollmentOutput? {
        try currentRecords().first {
            $0.trust.installationID == installationID
                && $0.trust.active
                && Date() < $0.trust.expiresAt
        }
    }

    /// Return the durable record for inventory presentation, including an
    /// expired or inactive record that must no longer authorize requests.
    func enrollmentInventoryRecord() throws -> EnrollmentInventoryRecord? {
        try selectedInventoryRecord()
    }

    func enrollmentInventoryRecord(installationID: Data) throws -> EnrollmentInventoryRecord? {
        try loadInventoryRecords().first { $0.installationID == installationID }
    }

    /// Select the installation/persona used by flows that do not carry an
    /// explicit installation ID. Selection is local UI state only; it cannot
    /// activate expired or legacy trust.
    func selectInstallation(installationID: Data) throws {
        let inventory = try loadInventoryRecords()
        guard inventory.allSatisfy({
            if case .current = $0 { return true }
            return false
        }) else { throw PlatformFailure.invalidConfiguration }
        let records = inventory.compactMap { record -> AuthenticatedEnrollmentOutput? in
            guard case let .current(output) = record else { return nil }
            return output
        }
        guard let selected = records.first(where: {
            $0.trust.installationID == installationID
                && $0.trust.active
                && Date() < $0.trust.expiresAt
        }) else { throw PlatformFailure.invalidConfiguration }
        try saveInventory(records: records, selectedInstallationID: selected.trust.installationID)
    }

    /// Whether the create-once slot is occupied, including by expired trust.
    func hasStoredEnrollment() throws -> Bool {
        try !loadInventoryRecords().isEmpty
    }

    func installAuthenticated(_ output: AuthenticatedEnrollmentOutput) throws {
        let inventory = try loadInventoryRecords()
        guard !inventory.contains(where: {
            if case .legacy = $0 { return true }
            return false
        }) else {
            // Never silently discard an incompatible legacy profile while
            // adding another installation. The user must explicitly retire
            // that profile through the existing guarded flow.
            throw PlatformFailure.invalidConfiguration
        }
        var records = inventory.compactMap { record -> AuthenticatedEnrollmentOutput? in
            guard case let .current(output) = record else { return nil }
            return output
        }
        if let index = records.firstIndex(where: {
            $0.trust.installationID == output.trust.installationID
        }) {
            let disposition = try Self.firstInstallDisposition(
                existing: records[index],
                proposed: output
            )
            if disposition == .idempotent {
                try saveInventory(records: records, selectedInstallationID: output.trust.installationID)
                return
            }
            records[index] = output
        } else {
            records.append(output)
        }
        try saveInventory(records: records, selectedInstallationID: output.trust.installationID)
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
              existing.httpsOrigin == proposed.httpsOrigin,
              existing.tlsSPKISHA256 == proposed.tlsSPKISHA256,
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
        var records = try loadInventoryRecords()
        guard records.contains(where: { $0.installationID == installationID }) else { return }
        records.removeAll { $0.installationID == installationID }
        try saveInventory(records: records.compactMap { record in
            guard case let .current(output) = record else { return nil }
            return output
        }, selectedInstallationID: records.first?.installationID)
    }

    /// Erase every device-local installation and identity authorisation record.
    ///
    /// This is the credential-removal boundary used only by the explicit
    /// whole-device reset. It does not contact an authority, revoke a server
    /// session, delete audit evidence, or claim that the installation no
    /// longer recognises this device.
    func resetAllLocalEnrollments() throws {
        #if canImport(Security)
        let statuses = [
            SecItemDelete(inventoryQuery() as CFDictionary),
            SecItemDelete(baseQuery() as CFDictionary),
        ]
        guard statuses.allSatisfy({ $0 == errSecSuccess || $0 == errSecItemNotFound }) else {
            throw PlatformFailure.invalidConfiguration
        }
        NotificationCenter.default.post(
            name: Self.enrollmentDidChangeNotification,
            object: nil
        )
        #else
        throw PlatformFailure.secureHardwareUnavailable
        #endif
    }

    /// Forget local material only when it cannot authorize. This does not
    /// represent or perform authority-side revocation.
    func forgetExpired(installationID: Data, now: Date = Date()) throws {
        var records = try loadInventoryRecords()
        guard let current = records.first(where: { $0.installationID == installationID }),
              case let .current(output) = current,
              Self.allowsLocalForget(
                  active: output.trust.active,
                  expiresAt: output.trust.expiresAt,
                  now: now
              )
        else { throw PlatformFailure.invalidConfiguration }
        records.removeAll { $0.installationID == installationID }
        try saveInventory(
            records: records.compactMap { record in
                guard case let .current(output) = record else { return nil }
                return output
            },
            selectedInstallationID: records.first?.installationID
        )
    }

    /// Retire the exact preceding profile. It is structurally incapable of
    /// authorising in current software and this does not represent server
    /// revocation.
    func forgetIncompatible(
        installationID: Data,
        externalIdentityID: Data
    ) throws {
        var records = try loadInventoryRecords()
        guard let current = records.first(where: { $0.installationID == installationID }),
              case let .legacy(output) = current,
              Self.matchesLegacyRemoval(
                  output,
                  installationID: installationID,
                  externalIdentityID: externalIdentityID
              )
        else { throw PlatformFailure.invalidConfiguration }
        records.removeAll { $0.installationID == installationID }
        try saveInventory(
            records: records.compactMap { record in
                guard case let .current(output) = record else { return nil }
                return output
            },
            selectedInstallationID: records.first?.installationID
        )
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

    static func currentEnrollment(
        from inventory: EnrollmentInventoryRecord?
    ) -> AuthenticatedEnrollmentOutput? {
        guard case let .current(output)? = inventory else { return nil }
        return output
    }

    private func currentRecords() throws -> [AuthenticatedEnrollmentOutput] {
        try loadInventoryRecords().compactMap { record in
            guard case let .current(output) = record else { return nil }
            return output
        }
    }

    private func selectedInventoryRecord() throws -> EnrollmentInventoryRecord? {
        let records = try loadInventoryRecords()
        guard !records.isEmpty else { return nil }
        #if canImport(Security)
        if let selected = try loadV2Envelope()?.selectedInstallationID,
           let record = records.first(where: { $0.installationID == selected }) {
            return record
        }
        #endif
        return records.first
    }

    private func loadInventoryRecords() throws -> [EnrollmentInventoryRecord] {
        #if canImport(Security)
        if let envelope = try loadV2Envelope() {
            return envelope.records.map(EnrollmentInventoryRecord.current)
        }
        #endif
        guard let legacy = try loadLegacyInventory() else { return [] }
        return [legacy]
    }

    #if canImport(Security)
    private func loadV2Envelope() throws -> EnrollmentInventoryV2? {
        var query = inventoryQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data, data.count <= 64 * 1024
        else { throw PlatformFailure.invalidConfiguration }
        do {
            return try JSONDecoder().decode(EnrollmentInventoryV2.self, from: data)
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
    }

    private func loadLegacyInventory() throws -> EnrollmentInventoryRecord? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data, data.count <= 16_384
        else { throw PlatformFailure.invalidConfiguration }
        do {
            return try Self.decodeInventory(data)
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
    }

    private func saveInventory(
        records: [AuthenticatedEnrollmentOutput],
        selectedInstallationID: Data?
    ) throws {
        let envelope = try EnrollmentInventoryV2(
            records: records,
            selectedInstallationID: selectedInstallationID
        )
        let data = try JSONEncoder().encode(envelope)
        guard data.count <= 64 * 1024 else { throw PlatformFailure.invalidConfiguration }
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let query = inventoryQuery()
        let status = SecItemAdd(
            query.merging(attributes) { _, new in new } as CFDictionary,
            nil
        )
        let finalStatus: OSStatus
        if status == errSecDuplicateItem {
            finalStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        } else {
            finalStatus = status
        }
        guard finalStatus == errSecSuccess else {
            throw PlatformFailure.invalidConfiguration
        }
        NotificationCenter.default.post(
            name: Self.enrollmentDidChangeNotification,
            object: nil
        )
    }

    private func inventoryQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: inventoryService,
            kSecAttrAccount as String: inventoryAccount,
            kSecAttrSynchronizable as String: false,
        ]
    }
    #else
    private func loadLegacyInventory() throws -> EnrollmentInventoryRecord? { nil }
    #endif

    private func loadInventory() throws -> EnrollmentInventoryRecord? {
        try selectedInventoryRecord()
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
