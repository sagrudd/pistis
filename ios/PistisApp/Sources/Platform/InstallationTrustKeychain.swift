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
                .init(codingPath: decoder.codingPath, debugDescription: "invalid trust fields")
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
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

    private let service = "org.mnemosynebiosciences.pistis.installation-trust.v1"
    private let account = "primary"

    func record(installationID: Data) throws -> InstallationTrustRecord? {
        guard let output = try load(), output.trust.installationID == installationID else {
            return nil
        }
        return output.trust
    }

    func activeEnrollment() throws -> AuthenticatedEnrollmentOutput? {
        guard let output = try load(), output.trust.active,
              Date() < output.trust.expiresAt
        else { return nil }
        return output
    }

    /// Whether the create-once slot is occupied, including by expired trust.
    func hasStoredEnrollment() throws -> Bool {
        try load() != nil
    }

    func installAuthenticated(_ output: AuthenticatedEnrollmentOutput) throws {
        if try Self.firstInstallDisposition(
            existing: load(),
            proposed: output
        ) == .idempotent {
            return
        }
        let data = try JSONEncoder().encode(output)
        guard data.count <= 16_384 else { throw PlatformFailure.invalidConfiguration }
        #if canImport(Security)
        let query = baseQuery()
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        var insertion = query
        attributes.forEach { insertion[$0.key] = $0.value }
        guard SecItemAdd(insertion as CFDictionary, nil) == errSecSuccess else {
            throw PlatformFailure.invalidConfiguration
        }
        #else
        throw PlatformFailure.invalidConfiguration
        #endif
    }

    enum FirstInstallDisposition: Equatable {
        case create
        case idempotent
    }

    static func firstInstallDisposition(
        existing: AuthenticatedEnrollmentOutput?,
        proposed: AuthenticatedEnrollmentOutput
    ) throws -> FirstInstallDisposition {
        guard let existing else { return .create }
        guard existing == proposed else {
            throw PlatformFailure.invalidConfiguration
        }
        return .idempotent
    }

    func revoke(installationID: Data) throws {
        guard let current = try load() else { return }
        guard current.trust.installationID == installationID else {
            throw PlatformFailure.invalidConfiguration
        }
        #if canImport(Security)
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PlatformFailure.invalidConfiguration
        }
        #else
        throw PlatformFailure.invalidConfiguration
        #endif
    }

    private func load() throws -> AuthenticatedEnrollmentOutput? {
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
            return try JSONDecoder().decode(AuthenticatedEnrollmentOutput.self, from: data)
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
