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
              allowedHosts.allSatisfy({
                  !$0.isEmpty && $0 == $0.lowercased() && !$0.contains("/")
              })
        else { throw PlatformFailure.invalidConfiguration }
        self.trust = trust
        self.responseContext = responseContext
        self.allowedHosts = allowedHosts
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

    func installAuthenticated(_ output: AuthenticatedEnrollmentOutput) throws {
        let data = try JSONEncoder().encode(output)
        guard data.count <= 16_384 else { throw PlatformFailure.invalidConfiguration }
        #if canImport(Security)
        let query = baseQuery()
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var insertion = query
            attributes.forEach { insertion[$0.key] = $0.value }
            guard SecItemAdd(insertion as CFDictionary, nil) == errSecSuccess else {
                throw PlatformFailure.invalidConfiguration
            }
        } else if status != errSecSuccess {
            throw PlatformFailure.invalidConfiguration
        }
        #else
        throw PlatformFailure.invalidConfiguration
        #endif
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
