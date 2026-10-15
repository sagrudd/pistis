import Foundation
import PistisCore
#if canImport(Security)
import Security

/// Protected atomic add-only fences, scoped solely to issuer ceremonies. No
/// reset/delete path and no LAContext or private key is ever persisted here.
final class IssuerSiteRootAttemptLedger: @unchecked Sendable {
    private let service = "org.mnemosyne.pistis.issuer-site-root-attempt.v1"

    func begin(_ readiness: IssuerPhoneReadiness) throws {
        try insert(account: account(readiness.ceremonyID, ordinal: 0), value: readiness.digest)
    }
    func beforeInvocation(_ readiness: IssuerPhoneReadiness, task: IssuerPhoneTask) throws {
        guard task.ceremonyID == readiness.ceremonyID, task.readinessDigest == readiness.digest else {
            throw IssuerPhoneError.binding
        }
        // Bound exact full task and full readiness digests, not selected fields.
        let value = readiness.digest + task.digest + withUnsafeBytes(of: task.ordinal.bigEndian) { Data($0) }
        try insert(account: account(readiness.ceremonyID, ordinal: task.ordinal), value: value)
    }
    private func account(_ ceremony: Data, ordinal: UInt64) -> String {
        ceremony.map { String(format: "%02x", $0) }.joined() + "-\(ordinal)"
    }
    private func insert(account: String, value: Data) throws {
        guard !value.isEmpty, value.count <= 262_144 else { throw IssuerPhoneError.bound }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: service,
            kSecAttrAccount: account, kSecAttrSynchronizable: false,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: value,
        ]
        // Duplicate means invoked/ambiguous/previous process; never overwrite it.
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else {
            throw IssuerPhoneError.uncertain
        }
    }
}
#endif
