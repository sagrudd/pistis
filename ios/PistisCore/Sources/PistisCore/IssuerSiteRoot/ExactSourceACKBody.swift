import Foundation

/// Closed ADR0022 public body DATA. Parsing never appoints a role, enrolled key
/// or prepared operation. The platform adapter must retain the actual current
/// authenticated server operation and independently selected ACK registration.
public struct ExactSourceACKBody: Equatable, Sendable {
    public enum Kind: Equatable, Sendable { case enrollment, technicalReview }
    public let original: Data
    public let fields: [String: String]
    public let kind: Kind

    public static func parse(_ original: Data, now: UInt64) throws -> Self {
        guard !original.isEmpty, original.count <= 32_768,
              original.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }) else { throw IssuerPhoneError.bound }
        let bytes = Array(original)
        var at = 0
        func take(_ expected: UInt8) throws {
            guard at < bytes.count, bytes[at] == expected else { throw IssuerPhoneError.malformed }
            at += 1
        }
        func string() throws -> String {
            try take(0x22)
            let start = at
            while at < bytes.count, bytes[at] != 0x22 {
                // All allocated fields have literal ASCII grammar. Rejecting
                // escapes avoids duplicate/normalised spellings at this boundary.
                guard bytes[at] != 0x5c, bytes[at] >= 0x20 else { throw IssuerPhoneError.malformed }
                at += 1
            }
            let value = String(decoding: bytes[start..<at], as: UTF8.self)
            try take(0x22)
            return value
        }
        try take(0x7b)
        var values: [String: String] = [:]
        var prior: String?
        while at < bytes.count, bytes[at] != 0x7d {
            let key = try string()
            guard !key.isEmpty, prior.map({ $0 < key }) ?? true,
                  values[key] == nil else { throw IssuerPhoneError.malformed }
            try take(0x3a)
            values[key] = try string()
            prior = key
            guard at < bytes.count else { throw IssuerPhoneError.malformed }
            if bytes[at] == 0x2c { at += 1; guard at < bytes.count, bytes[at] == 0x22 else { throw IssuerPhoneError.malformed } }
            else { break }
        }
        try take(0x7d)
        guard at == bytes.count else { throw IssuerPhoneError.malformed }
        let kind: Kind
        let expected: Set<String>
        switch values["schema"] {
        case "mnemosyne.proxenos.exact-source-purpose-enrollment.v1":
            kind = .enrollment; expected = enrollmentFields
            guard values["purpose"] == "thesaurophylax.github-exact-source-qualification-credential-projection.v1",
                  values["scope"] == "classic-commit-status:mnemosyne/expedition" else { throw IssuerPhoneError.binding }
        case "mnemosyne.proxenos.exact-source-technical-review.v1":
            kind = .technicalReview; expected = reviewFields
            guard original.count <= 8_192,
                  ["independent-subject", "recorded-owner-exception"].contains(values["mode"] ?? ""),
                  values["repository"] == "https://github.com/sagrudd/pistis",
                  values["verdict"] == "pass", values["scope"] == "exact-source-authority-origin" else { throw IssuerPhoneError.binding }
        default: throw IssuerPhoneError.binding
        }
        guard Set(values.keys) == expected else { throw IssuerPhoneError.malformed }
        for (key, value) in values {
            if key.hasSuffix("_sha256") || key == "nonce" || key == "device_target" || key == "reviewer_device_target" {
                guard hex(value, length: 64), value != String(repeating: "0", count: 64) else { throw IssuerPhoneError.binding }
            } else if key == "source_revision" || key == "source_tree_revision" {
                guard hex(value, length: 40), value != String(repeating: "0", count: 40) else { throw IssuerPhoneError.binding }
            } else if key == "installation_id" || key == "site_uuid" {
                guard let uuid = UUID(uuidString: value), uuid.uuidString.lowercased() == value,
                      value != "00000000-0000-0000-0000-000000000000" else { throw IssuerPhoneError.binding }
            } else if key == "revocation_generation" {
                guard value == "0" || ((try? positive(value)) != nil) else { throw IssuerPhoneError.binding }
            } else if ["issued_at", "expires_at", "device_generation", "reviewer_device_generation"].contains(key) {
                _ = try positive(value)
            } else if ["site", "custody_generation", "issuer_generation", "recipient", "reviewer_subject"].contains(key) {
                guard identifier(value, subject: key == "reviewer_subject") else { throw IssuerPhoneError.binding }
            }
        }
        let issued = try positive(values["issued_at"] ?? "")
        let expiry = try positive(values["expires_at"] ?? "")
        guard issued <= now, now < expiry, issued < expiry, expiry - issued <= 600 else { throw IssuerPhoneError.expired }
        return Self(original: original, fields: values, kind: kind)
    }
    private static func positive(_ value: String) throws -> UInt64 {
        guard let first = value.utf8.first, first >= 49, first <= 57,
              value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              let result = UInt64(value), result > 0 else { throw IssuerPhoneError.binding }
        return result
    }
    private static func hex(_ value: String, length: Int) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func identifier(_ value: String, subject: Bool) -> Bool {
        let b = Array(value.utf8)
        func alnum(_ c: UInt8) -> Bool { (48...57).contains(c) || (65...90).contains(c) || (97...122).contains(c) }
        return !b.isEmpty && b.count <= 128 && alnum(b[0]) && b.allSatisfy {
            alnum($0) || [UInt8(46), 95, 58, 45].contains($0) || (subject && [UInt8(47), 64].contains($0))
        }
    }
    private static let enrollmentFields: Set<String> = ["schema", "purpose", "installation_id", "site_uuid", "site", "custody_generation", "device_target", "device_generation", "approval_action_sha256", "approval_audit_sha256", "admission_sha256", "review_sha256", "installation_evidence_sha256", "issuer_generation", "issuer_public_key_sha256", "issuer_record_sha256", "issuer_audit_sha256", "expectation_sha256", "canonical_request_sha256", "scope", "recipient", "nonce", "issued_at", "expires_at", "revocation_generation"]
    private static let reviewFields: Set<String> = ["schema", "mode", "installation_id", "site_uuid", "admission_intent_sha256", "repository", "source_revision", "source_tree_revision", "original_review_sha256", "verdict", "scope", "reviewer_subject", "reviewer_device_target", "reviewer_device_generation", "reviewer_role_decision_sha256", "governance_witness_sha256", "owner_approval_merge_witness_sha256", "issued_at", "expires_at", "nonce"]
}
