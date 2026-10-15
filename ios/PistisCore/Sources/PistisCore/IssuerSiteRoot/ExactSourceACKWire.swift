import Foundation

/// Closed local task transport DATA, distinct from ADR0045 readiness/exchange.
/// Only an authenticated fixed server operation may prepare it for signing.
public enum ExactSourceACKWire {
    public static let preparePath = "/pistis/v1/exact-source-purpose/prepare"
    public static let submitPath = "/pistis/v1/exact-source-purpose/submit"
    public struct TaskData: Equatable, Sendable {
        public let correlation: Data
        public let challenge: Data
        public let body: ExactSourceACKBody
        public let originals: [Data]
        public let expiresAt: UInt64
        public let actionIssuedAt: UInt64
        public let actionExpiresAt: UInt64
        public let digest: Data
    }
    public static func prepare(challenge: Data, kind: ExactSourceACKBody.Kind,
                               target: Data, generation: UInt64) throws -> Data {
        guard challenge.count == 32, !challenge.allSatisfy({ $0 == 0 }),
              target.count == 32, generation > 0 else { throw IssuerPhoneError.binding }
        return try IssuerCBOR.array([.unsigned(1), .bytes(Data("exact-source-ack-prepare-v1".utf8)),
            .bytes(challenge), .unsigned(kind == .enrollment ? 1 : 2), .bytes(target), .unsigned(generation)]).encoded()
    }
    public static func task(_ raw: Data, challenge: Data, kind: ExactSourceACKBody.Kind,
                            now: UInt64) throws -> TaskData {
        let a = try IssuerCBOR.decode(raw).array(8)
        guard try a[0].uint() == 1,
              try a[1].bytes(range: 1...128) == Data("exact-source-ack-task-v1".utf8),
              try a[3].bytes(range: 32...32) == challenge,
              try a[4].uint() == (kind == .enrollment ? 1 : 2) else { throw IssuerPhoneError.binding }
        let correlation = try a[2].bytes(range: 16...16)
        guard !correlation.allSatisfy({ $0 == 0 }) else { throw IssuerPhoneError.binding }
        let body = try ExactSourceACKBody.parse(a[5].bytes(range: 1...32_768), now: now)
        guard body.kind == kind else { throw IssuerPhoneError.binding }
        let limits = kind == .enrollment
            ? [8192, 8192, 16384, 8192, 32768, 32, 32, 32768, 8192, 8192, 65536, 8192, 8192]
            : [8192, 8192, 16384, 65536, 8192, 8192]
        let nodes = try a[6].array(limits.count)
        let originals = try zip(nodes, limits).map { try $0.0.bytes(range: 1...$0.1) }
        let expiry = try a[7].uint()
        guard expiry > now, expiry - now <= 30,
              let bodyExpiry = UInt64(body.fields["expires_at"] ?? ""), expiry <= bodyExpiry else { throw IssuerPhoneError.expired }
        func hex(_ b: Data) -> String { b.map { String(format: "%02x", $0) }.joined() }
        func match(_ field: String, _ original: Data) throws {
            guard body.fields[field] == hex(IssuerPhoneWire.sha256(original)) else { throw IssuerPhoneError.binding }
        }
        if kind == .enrollment {
            for (field, index) in [("approval_audit_sha256", 0), ("approval_action_sha256", 1), ("admission_sha256", 2), ("review_sha256", 3), ("installation_evidence_sha256", 4), ("issuer_public_key_sha256", 5), ("issuer_audit_sha256", 7), ("canonical_request_sha256", 8), ("expectation_sha256", 9)] { try match(field, originals[index]) }
            guard originals[5].count == 32, originals[6].count == 32,
                  body.fields["issuer_record_sha256"] == hex(originals[6]) else { throw IssuerPhoneError.binding }
        } else {
            for (field, index) in [("reviewer_role_decision_sha256", 0), ("admission_intent_sha256", 2), ("original_review_sha256", 3), ("governance_witness_sha256", 4), ("owner_approval_merge_witness_sha256", 5)] { try match(field, originals[index]) }
        }
        let actionWindow = try actionGraph(body, originals: originals, now: now, taskExpiry: expiry)
        return TaskData(correlation: correlation, challenge: challenge, body: body,
                        originals: originals, expiresAt: expiry, actionIssuedAt: actionWindow.0, actionExpiresAt: actionWindow.1, digest: IssuerPhoneWire.sha256(raw))
    }
    private static func actionGraph(_ body: ExactSourceACKBody, originals: [Data], now: UInt64, taskExpiry: UInt64) throws -> (UInt64, UInt64) {
        let raw = originals[1]
        guard let action = try JSONSerialization.jsonObject(with: raw) as? [String: String],
              Set(action.keys) == Set(["operation", "purpose", "audience", "action_body_sha256", "admission_binding_sha256", "installation_id", "site_uuid", "challenge", "issued_at", "expires_at"]),
              try JSONSerialization.data(withJSONObject: action, options: [.sortedKeys, .withoutEscapingSlashes]) == raw else { throw IssuerPhoneError.binding }
        var intent = body.fields
        if body.kind == .enrollment {
            intent.removeValue(forKey: "approval_action_sha256")
            intent.removeValue(forKey: "approval_audit_sha256")
        } else { intent.removeValue(forKey: "reviewer_role_decision_sha256") }
        let intentRaw = try JSONSerialization.data(withJSONObject: intent, options: [.sortedKeys, .withoutEscapingSlashes])
        func digest(_ raw: Data) -> String { IssuerPhoneWire.sha256(raw).map { String(format: "%02x", $0) }.joined() }
        guard let issued = UInt64(action["issued_at"] ?? ""), issued > 0,
              action["issued_at"] == String(issued),
              let expires = UInt64(action["expires_at"] ?? ""), action["expires_at"] == String(expires),
              issued <= now, now < expires, expires > issued, expires - issued <= 60,
              taskExpiry <= expires,
              let challenge = action["challenge"], challenge.utf8.count == 64,
              challenge.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              challenge != String(repeating: "0", count: 64),
              action["operation"] == "exact_source_role_decision", action["audience"] == "jenkins",
              action["purpose"] == (body.kind == .enrollment ? "operator-enrollment" : "technical-review"),
              action["action_body_sha256"] == digest(intentRaw),
              action["admission_binding_sha256"] == digest(originals[2]),
              action["installation_id"] == body.fields["installation_id"],
              action["site_uuid"] == body.fields["site_uuid"] else { throw IssuerPhoneError.binding }
        return (issued, expires)
    }
    public static func submission(_ task: TaskData, proof: Data) throws -> Data {
        guard !proof.isEmpty, proof.count <= 8192 else { throw IssuerPhoneError.bound }
        return try IssuerCBOR.array([.unsigned(1), .bytes(Data("exact-source-ack-submit-v1".utf8)),
            .bytes(task.correlation), .bytes(task.challenge), .bytes(task.digest), .bytes(proof)]).encoded()
    }
    public static func accepted(_ raw: Data, task: TaskData) throws {
        let a = try IssuerCBOR.decode(raw).array(4)
        guard try a[0].uint() == 1,
              try a[1].bytes(range: 1...128) == Data("exact-source-ack-retained-v1".utf8),
              try a[2].bytes(range: 16...16) == task.correlation,
              try a[3].bytes(range: 32...32) == task.digest else { throw IssuerPhoneError.binding }
    }
}
