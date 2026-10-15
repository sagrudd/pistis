import Foundation
import PistisCore

/// Closed native-profile DATA codec. Its output is never a current-session owner.
enum IssuerNativeSessionWire {
    static let profile = "issuer-site-root-native-v1"
    static let beginPath = "/auth/pistis/v2/begin"
    static let submitPath = "/auth/pistis/v2/submit"
    static let finalizePath = "/auth/pistis/v2/finalize"
    static let maximumBytes = 16_384

    final class Begin {
        let reference: String
        let signedChallenge: Data
        let transfer: String
        let expiresAt: Date
        // Only the awaited native flow in the companion session file may retain
        // this capability. It is never Codable, logged or installed in Keychain.
        private var initiatorSecret: Data
        private var taken = false
        fileprivate init(reference: String, signedChallenge: Data, transfer: String, expiresAt: Date, initiatorSecret: Data) {
            self.reference = reference; self.signedChallenge = signedChallenge
            self.transfer = transfer; self.expiresAt = expiresAt; self.initiatorSecret = initiatorSecret
        }
        func takeInitiatorSecret() throws -> Data {
            guard !taken else { throw IssuerPhoneError.order }
            taken = true
            let result = initiatorSecret
            initiatorSecret.resetBytes(in: initiatorSecret.startIndex..<initiatorSecret.endIndex)
            initiatorSecret.removeAll(keepingCapacity: false)
            return result
        }
        deinit { initiatorSecret.resetBytes(in: initiatorSecret.startIndex..<initiatorSecret.endIndex) }
    }
    struct Finalized {
        let sessionID: UUID
        let principalID: UUID
        let installationID: UUID
        let deviceID: UUID
        let deviceKeyID: String
        let bindingID: UUID
        let bindingGeneration: UInt64
        let policyGeneration: UInt64
        let revocationGeneration: UInt64
        let completionID: UUID
        let challengeID: UUID
        let expiresAt: Date
    }
    static func begin(_ data: Data, now: Date) throws -> Begin {
        let v = try StrictJSONObject(data: data, maximumBytes: maximumBytes).values
        guard Set(v.keys) == ["profile", "reference", "initiator_secret_b64url", "signed_challenge_b64url", "transfer", "expires_at_utc"],
              try text(v, "profile") == profile else { throw IssuerPhoneError.binding }
        let reference = try text(v, "reference")
        _ = try base64(reference, minimum: 32, maximum: 32)
        let secret = try base64(text(v, "initiator_secret_b64url"), minimum: 32, maximum: 32)
        let signed = try base64(text(v, "signed_challenge_b64url"), minimum: 1, maximum: 2_048)
        let transfer = try text(v, "transfer")
        guard transfer.utf8.count <= 4_096,
              try ProductionQRV2.decodeChallenge(transfer) == signed else { throw IssuerPhoneError.binding }
        return Begin(reference: reference, signedChallenge: signed, transfer: transfer,
            expiresAt: try date(text(v, "expires_at_utc"), now: now), initiatorSecret: secret)
    }
    static func finalized(_ data: Data, now: Date) throws -> Finalized {
        let v = try StrictJSONObject(data: data, maximumBytes: maximumBytes).values
        guard Set(v.keys) == ["profile", "session_id", "principal_id", "installation_id", "device_id", "device_key_id", "binding_id", "binding_generation", "policy_generation", "revocation_generation", "completion_id", "challenge_id", "expires_at_utc"],
              try text(v, "profile") == profile else { throw IssuerPhoneError.binding }
        let key = try text(v, "device_key_id")
        guard key.utf8.count == 64, key.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw IssuerPhoneError.binding }
        return Finalized(sessionID: try uuid(text(v, "session_id")), principalID: try uuid(text(v, "principal_id")),
            installationID: try uuid(text(v, "installation_id")), deviceID: try uuid(text(v, "device_id")),
            deviceKeyID: key, bindingID: try uuid(text(v, "binding_id")),
            bindingGeneration: try number(v, "binding_generation", nonzero: true),
            policyGeneration: try number(v, "policy_generation", nonzero: true),
            revocationGeneration: try number(v, "revocation_generation", nonzero: false),
            completionID: try uuid(text(v, "completion_id")), challengeID: try uuid(text(v, "challenge_id")),
            expiresAt: try date(text(v, "expires_at_utc"), now: now))
    }
    static func completedStatus(_ data: Data) throws {
        let values = try StrictJSONObject(data: data, maximumBytes: maximumBytes).values
        guard Set(values.keys).isSubset(of: ["state", "evidence_id"]),
              case .string("completed")? = values["state"] else { throw IssuerPhoneError.uncertain }
        if let evidence = values["evidence_id"] {
            switch evidence {
            case .null: break
            case let .string(value):
                guard !value.isEmpty, value.utf8.count <= 128,
                      !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { throw IssuerPhoneError.binding }
            default: throw IssuerPhoneError.binding
            }
        }
    }
    static func checkFinalized(_ result: Finalized, enrollment: AuthenticatedEnrollmentOutput,
                               challengeID: UUID, actualDeviceKeyID: Data) throws {
        guard result.challengeID == challengeID,
              result.principalID == (try uuid(enrollment.trust.userID)),
              result.installationID == (try uuid(enrollment.trust.installationID)),
              result.deviceID == (try uuid(enrollment.responseContext.deviceID)),
              result.deviceKeyID == hex(actualDeviceKeyID),
              actualDeviceKeyID == enrollment.responseContext.deviceKeyID,
              result.policyGeneration >= enrollment.trust.policyGeneration,
              result.revocationGeneration >= enrollment.trust.revocationGeneration else { throw IssuerPhoneError.binding }
    }
    /// Closed request assembly DATA, shared by the actual private session and
    /// request tests. This does not authenticate a token or construct an owner.
    static func issuerRequestData(_ request: URLRequest, sessionID: UUID,
                                  secret: Data, enrolledOrigin: String) throws -> URLRequest {
        guard let url = request.url, CanonicalHTTPSOrigin.from(url) == enrolledOrigin,
              [IssuerPhoneWire.readinessPath, IssuerPhoneWire.exchangePath].contains(url.path),
              url.query == nil, url.fragment == nil, request.httpMethod == "POST",
              request.value(forHTTPHeaderField: "Content-Type") == "application/cbor",
              request.value(forHTTPHeaderField: "Cookie") == nil,
              request.value(forHTTPHeaderField: "Origin") == nil,
              request.value(forHTTPHeaderField: "Authorization") == nil,
              request.value(forHTTPHeaderField: "Pistis-Session-Profile").map({ $0 == profile }) ?? true,
              secret.count == 32 else { throw IssuerPhoneError.binding }
        var result = request
        result.setValue(profile, forHTTPHeaderField: "Pistis-Session-Profile")
        result.setValue("Pistis \(sessionID.uuidString.lowercased()).\(encode(secret))", forHTTPHeaderField: "Authorization")
        return result
    }
    static func uuid(_ text: String) throws -> UUID {
        guard let value = UUID(uuidString: text), value.uuidString.lowercased() == text,
              text != "00000000-0000-0000-0000-000000000000" else { throw IssuerPhoneError.binding }
        return value
    }
    static func uuid(_ bytes: Data) throws -> UUID {
        guard bytes.count == 16 else { throw IssuerPhoneError.binding }
        let b = Array(bytes)
        return try uuid(UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])).uuidString.lowercased())
    }
    static func base64(_ text: String, minimum: Int, maximum: Int) throws -> Data {
        guard !text.isEmpty, text.utf8.count <= (maximum * 4 + 2) / 3,
              text.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { throw IssuerPhoneError.binding }
        var padded = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        guard let bytes = Data(base64Encoded: padded), (minimum...maximum).contains(bytes.count), encode(bytes) == text else { throw IssuerPhoneError.binding }
        return bytes
    }
    static func encode(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    static func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private static func text(_ values: [String: StrictJSONObject.Value], _ key: String) throws -> String {
        guard case let .string(value)? = values[key], !value.isEmpty else { throw IssuerPhoneError.binding }
        return value
    }
    private static func number(_ values: [String: StrictJSONObject.Value], _ key: String, nonzero: Bool) throws -> UInt64 {
        guard case let .number(text)? = values[key], !text.isEmpty,
              text.utf8.allSatisfy({ (48...57).contains($0) }), text.count == 1 || !text.hasPrefix("0"),
              let number = UInt64(text), !nonzero || number > 0 else { throw IssuerPhoneError.binding }
        return number
    }
    private static func date(_ text: String, now: Date) throws -> Date {
        guard text.utf8.count <= 40,
              text.unicodeScalars.allSatisfy(\.isASCII),
              !text.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              text.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?(Z|\\+00:00)$", options: .regularExpression) != nil
        else { throw IssuerPhoneError.binding }
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var value = parser.date(from: text)
        if value == nil { parser.formatOptions = [.withInternetDateTime]; value = parser.date(from: text) }
        guard let value, value > now else { throw IssuerPhoneError.expired }
        return value
    }
}
