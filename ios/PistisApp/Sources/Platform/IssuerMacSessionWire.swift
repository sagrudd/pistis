import Foundation
import CryptoKit
import PistisCore

/// Closed comparison DATA only. A displayed record never selects trust or a
/// credential; the actual private AuthenticateSession supplies those separately.
enum IssuerMacSessionWire {
    static let maximumBytes = 4096
    static let requestSchema = "monas.pistis.bind-mac-session.v1"
    struct Pending {
        let original: Data
        let values: [String: StrictJSONObject.Value]
        let macSessionID: String
        let operationID: String
        let installationID: String
        let siteID: String
        let origin: String
        let spki: String
        let issuedAt: UInt64
        let expiresAt: UInt64

        init(_ original: Data, now: Date) throws {
            let v = try IssuerMacSessionWire.object(original)
            guard Set(v.keys) == ["schema", "operation_id", "mac_session_id", "mac_nonce_b64url", "server_nonce_b64url", "descriptor_sha256", "policy_sha256", "installation_id", "site_id", "root_origin", "root_tls_spki_sha256", "issued_at", "expires_at"],
                  try IssuerMacSessionWire.text(v, "schema") == "mnemosyne.kleidophylax.mac-session-pending.v1" else { throw IssuerPhoneError.binding }
            for key in ["operation_id", "mac_session_id", "installation_id", "site_id"] { _ = try IssuerNativeSessionWire.uuid(IssuerMacSessionWire.text(v, key)) }
            for key in ["mac_nonce_b64url", "server_nonce_b64url"] {
                let nonce = try IssuerNativeSessionWire.base64(IssuerMacSessionWire.text(v, key), minimum: 32, maximum: 32)
                guard !nonce.allSatisfy({ $0 == 0 }) else { throw IssuerPhoneError.binding }
            }
            for key in ["descriptor_sha256", "policy_sha256", "root_tls_spki_sha256"] { try IssuerMacSessionWire.digest(IssuerMacSessionWire.text(v, key)) }
            let root = try IssuerMacSessionWire.text(v, "root_origin")
            guard CanonicalHTTPSOrigin.parse(root) == root else { throw IssuerPhoneError.binding }
            let issued = try IssuerMacSessionWire.number(v, "issued_at"), expires = try IssuerMacSessionWire.number(v, "expires_at")
            guard issued < expires, expires - issued <= 30,
                  now.timeIntervalSince1970 >= Double(issued), now.timeIntervalSince1970 < Double(expires) else { throw IssuerPhoneError.expired }
            self.original = original; values = v
            macSessionID = try IssuerMacSessionWire.text(v, "mac_session_id"); operationID = try IssuerMacSessionWire.text(v, "operation_id")
            installationID = try IssuerMacSessionWire.text(v, "installation_id"); siteID = try IssuerMacSessionWire.text(v, "site_id")
            origin = root; spki = try IssuerMacSessionWire.text(v, "root_tls_spki_sha256"); issuedAt = issued; expiresAt = expires
        }
        func check(enrollment: AuthenticatedEnrollmentOutput, ack: SiteRootConvergenceAckRecordV2, now: Date) throws {
            guard now.timeIntervalSince1970 >= Double(issuedAt), now.timeIntervalSince1970 < Double(expiresAt),
                  enrollment.trust.active, now < enrollment.trust.expiresAt,
                  installationID == (try IssuerNativeSessionWire.uuid(enrollment.trust.installationID)).uuidString.lowercased(),
                  siteID == ack.siteUUID, ack.generation > 0,
                  origin == enrollment.httpsOrigin,
                  spki == "sha256:" + IssuerNativeSessionWire.hex(enrollment.tlsSPKISHA256),
                  enrollment.responseContext.deviceKeyID.count == 32,
                  !enrollment.responseContext.deviceKeyID.allSatisfy({ $0 == 0 }),
                  enrollment.trust.installationKeyID.count == 32,
                  !enrollment.trust.installationKeyID.allSatisfy({ $0 == 0 }),
                  enrollment.trust.installationPublicKey.count == 33 else { throw IssuerPhoneError.binding }
        }
        func request() throws -> Data {
            var v = values
            v["schema"] = .string(IssuerMacSessionWire.requestSchema)
            v.removeValue(forKey: "issued_at"); v.removeValue(forKey: "expires_at")
            return try IssuerMacSessionWire.encode(v)
        }
    }
    static func validateRequest(_ bytes: Data) throws {
        let v = try object(bytes)
        guard Set(v.keys) == ["schema", "mac_session_id", "operation_id", "mac_nonce_b64url", "server_nonce_b64url", "descriptor_sha256", "policy_sha256", "installation_id", "site_id", "root_origin", "root_tls_spki_sha256"],
              try text(v, "schema") == requestSchema else { throw IssuerPhoneError.binding }
        for key in ["mac_session_id", "operation_id", "installation_id", "site_id"] { _ = try IssuerNativeSessionWire.uuid(text(v, key)) }
        for key in ["mac_nonce_b64url", "server_nonce_b64url"] {
            guard !(try IssuerNativeSessionWire.base64(text(v, key), minimum: 32, maximum: 32)).allSatisfy({ $0 == 0 }) else { throw IssuerPhoneError.binding }
        }
        for key in ["descriptor_sha256", "policy_sha256", "root_tls_spki_sha256"] { try digest(text(v, key)) }
        let root = try text(v, "root_origin")
        guard CanonicalHTTPSOrigin.parse(root) == root else { throw IssuerPhoneError.binding }
    }
    /// Receipt DATA never creates/recreates either the phone or Mac owner.
    static func receipt(_ bytes: Data, pending: Pending, now: Date) throws {
        let v = try object(bytes)
        guard Set(v.keys) == ["schema", "mac_session_id", "operation_id", "transcript_sha256", "expires_at"],
              try text(v, "schema") == "monas.pistis.mac-session-bound.v1",
              try text(v, "mac_session_id") == pending.macSessionID,
              try text(v, "operation_id") == pending.operationID else { throw IssuerPhoneError.binding }
        guard try text(v, "transcript_sha256") == "sha256:" + IssuerNativeSessionWire.hex(Data(SHA256.hash(data: pending.original))) else { throw IssuerPhoneError.binding }
        let expires = try number(v, "expires_at")
        guard expires > pending.issuedAt, expires <= pending.expiresAt,
              now.timeIntervalSince1970 >= Double(pending.issuedAt), now.timeIntervalSince1970 < Double(expires) else { throw IssuerPhoneError.expired }
    }
    private static func object(_ bytes: Data) throws -> [String: StrictJSONObject.Value] {
        let v = try StrictJSONObject(data: bytes, maximumBytes: maximumBytes).values
        guard try encode(v) == bytes else { throw IssuerPhoneError.malformed }
        return v
    }
    private static func encode(_ values: [String: StrictJSONObject.Value]) throws -> Data {
        var object: [String: Any] = [:]
        for (key, value) in values {
            switch value {
            case let .string(s):
                guard s.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 32 && $0.value < 127 }) else { throw IssuerPhoneError.malformed }
                object[key] = s
            case let .number(n):
                guard !n.isEmpty, n.utf8.allSatisfy({ (48...57).contains($0) }), n.count == 1 || !n.hasPrefix("0"),
                      let number = UInt64(n), number <= 9_007_199_254_740_991 else { throw IssuerPhoneError.malformed }
                object[key] = number
            default: throw IssuerPhoneError.malformed
            }
        }
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard bytes.count <= maximumBytes else { throw IssuerPhoneError.bound }; return bytes
    }
    private static func text(_ v: [String: StrictJSONObject.Value], _ key: String) throws -> String {
        guard case let .string(s)? = v[key], !s.isEmpty else { throw IssuerPhoneError.binding }; return s
    }
    private static func number(_ v: [String: StrictJSONObject.Value], _ key: String) throws -> UInt64 {
        guard case let .number(s)? = v[key], let n = UInt64(s), n > 0, n <= 9_007_199_254_740_991 else { throw IssuerPhoneError.binding }; return n
    }
    private static func digest(_ s: String) throws {
        guard s.hasPrefix("sha256:"), s.utf8.count == 71 else { throw IssuerPhoneError.binding }
        let hex = s.dropFirst(7)
        guard hex.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }), hex.contains(where: { $0 != "0" }) else { throw IssuerPhoneError.binding }
    }
}
