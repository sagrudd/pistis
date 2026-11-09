import Foundation
import CryptoKit

/// A broker V2 invitation is untrusted input, never an authority profile.
struct SiteRootBrokerPresentationV2: Sendable {
    static let schema = "monas.site-root-genesis-registration-presentation.v2"
    let reference: String
    let site: String
    let correlation: Data
    let ceremonyID: String
    let challenge: Data
    let expiresAt: UInt64

    init(qrText: String, nowMillis: UInt64) throws {
        let bytes = Data(qrText.utf8)
        guard bytes.count <= 8_192, bytes.allSatisfy({ $0 < 128 && $0 != 0x5c }) else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let values: [String: StrictJSONObject.Value]
        do { values = try StrictJSONObject(data: bytes, maximumBytes: 8_192).values }
        catch { throw PlatformFailure.qrPayloadUnsupported }
        guard Set(values.keys) == ["schema", "reference", "correlation_b64url", "site_trust_domain",
              "registration_url", "app_attest_ceremony_id_b64url", "app_attest_challenge_digest_b64url",
              "expires_at_unix_millis"],
              case let .string(schema)? = values["schema"], schema == Self.schema,
              case let .string(ref)? = values["reference"], Self.identifier(ref, maximum: 128),
              case let .string(site)? = values["site_trust_domain"], Self.identifier(site, maximum: 255),
              case let .string(url)? = values["registration_url"],
              url == MonasSiteRootGenesisBrokerEndpointV1.origin + MonasSiteRootGenesisBrokerEndpointV1.registrationPath,
              case let .string(correlationText)? = values["correlation_b64url"],
              let correlation = Self.base64(correlationText, exact: 32),
              case let .string(ceremony)? = values["app_attest_ceremony_id_b64url"],
              Self.base64(ceremony, exact: 16) != nil,
              case let .string(challengeText)? = values["app_attest_challenge_digest_b64url"],
              let challenge = Self.base64(challengeText, exact: 32),
              case let .number(expiryText)? = values["expires_at_unix_millis"],
              !expiryText.isEmpty, expiryText.utf8.allSatisfy({ (48...57).contains($0) }),
              (expiryText == "0" || expiryText.first != "0"), let expiry = UInt64(expiryText)
        else { throw PlatformFailure.qrPayloadUnsupported }
        guard expiry > nowMillis else { throw PlatformFailure.siteRootGenesisPresentationExpired }
        guard expiry - nowMillis <= SiteRootGenesisRegistrationPresentationV1.maximumLifetimeMillis else {
            throw PlatformFailure.invalidFirstDevicePresentation
        }
        reference = ref; self.site = site; self.correlation = correlation
        ceremonyID = ceremony; self.challenge = challenge; expiresAt = expiry
    }

    static func identifier(_ text: String, maximum: Int) -> Bool {
        !text.isEmpty && text.utf8.count <= maximum && text.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                || [45, 46, 58, 95].contains($0)
        }
    }
    static func base64(
        _ text: String, exact: Int? = nil, maximum: Int = 300_000, requireNonzero: Bool = true
    ) -> Data? {
        guard !text.isEmpty, text.utf8.allSatisfy({
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                || $0 == 45 || $0 == 95
        }), text.count % 4 != 1 else { return nil }
        let standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - text.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard), !decoded.isEmpty, decoded.count <= maximum,
              exact == nil || decoded.count == exact,
              !requireNonzero || !decoded.allSatisfy({ $0 == 0 }), encode(decoded) == text else { return nil }
        return decoded
    }
    static func encode(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

/// Closed no-escape request grammar. Canonicality is not authentication.
enum SiteRootBrokerRegistrationWireV2 {
    static let schema = "monas.site-root-genesis-registration.v2"
    private struct Request: Encodable {
        let schema = SiteRootBrokerRegistrationWireV2.schema
        let reference: String
        let operationID: String
        let siteRootKey: MonasSiteRootGenesisRegistrationRequest.SiteRootKey
        let appAttestRegistration: AppleAppAttestRegistrationEnvelope
        enum CodingKeys: String, CodingKey {
            case schema, reference
            case operationID = "operation_id_b64url"
            case siteRootKey = "site_root_key"
            case appAttestRegistration = "app_attest_registration"
        }
    }

    /// Shape-only canonicality check, used for fixture comparison. It grants no
    /// authority and accepts no substitute for the semantic validator below.
    static func canonicalWire(_ data: Data) throws -> Data {
        guard data.count <= 12 * 1024, data.allSatisfy({ $0 < 128 && $0 != 0x5c }) else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let values: [String: StrictJSONObject.Value]
        do { values = try StrictJSONObject(data: data, maximumBytes: 12 * 1024).values }
        catch { throw PlatformFailure.qrPayloadUnsupported }
        func render(_ object: [String: StrictJSONObject.Value]) throws -> String {
            try "{" + object.keys.sorted().map { key in
                guard SiteRootBrokerPresentationV2.identifier(key, maximum: 128), let value = object[key] else {
                    throw PlatformFailure.qrPayloadUnsupported
                }
                let encoded: String
                switch value {
                case let .string(text):
                    guard SiteRootBrokerPresentationV2.identifier(text, maximum: 12 * 1024) else {
                        throw PlatformFailure.qrPayloadUnsupported
                    }
                    encoded = "\"" + text + "\""
                case let .object(nested): encoded = try render(nested)
                default: throw PlatformFailure.qrPayloadUnsupported
                }
                return "\"" + key + "\":" + encoded
            }.joined(separator: ",") + "}"
        }
        let canonical = Data(try render(values).utf8)
        guard canonical == data else { throw PlatformFailure.qrPayloadUnsupported }
        return canonical
    }

    static func encode(
        presentation: SiteRootBrokerPresentationV2, operationID: Data,
        siteRootKey: SiteRootKeyRegistrationV1, appAttest: AppleAppAttestRegistrationEnvelope
    ) throws -> Data {
        let request = Request(reference: presentation.reference,
            operationID: SiteRootBrokerPresentationV2.encode(operationID),
            siteRootKey: .init(siteRootKey), appAttestRegistration: appAttest)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(request)
        try validate(bytes, presentation: presentation, operationID: operationID)
        return bytes
    }

    static func validate(_ data: Data, presentation: SiteRootBrokerPresentationV2, operationID: Data) throws {
        _ = try canonicalWire(data)
        let values = try StrictJSONObject(data: data, maximumBytes: 12 * 1024).values
        guard Set(values.keys) == ["schema", "reference", "operation_id_b64url", "site_root_key", "app_attest_registration"],
              values["schema"] == .string(schema), values["reference"] == .string(presentation.reference),
              values["operation_id_b64url"] == .string(SiteRootBrokerPresentationV2.encode(operationID)),
              operationID.count == 16, !operationID.allSatisfy({ $0 == 0 }),
              case let .object(key)? = values["site_root_key"],
              Set(key.keys) == ["schema", "device_key_id", "public_key_compressed_sec1_base64url", "secure_enclave_attestation"],
              key["schema"] == .string("pistis.site-root-key-registration.v1"),
              key["secure_enclave_attestation"] == .string("not-asserted"),
              case let .string(publicKeyText)? = key["public_key_compressed_sec1_base64url"],
              let publicKey = SiteRootBrokerPresentationV2.base64(publicKeyText, exact: 33),
              (try? P256.Signing.PublicKey(compressedRepresentation: publicKey)) != nil,
              case let .string(keyID)? = key["device_key_id"],
              keyID == "site-root-" + SHA256.hash(data: publicKey).map({ String(format: "%02x", $0) }).joined(),
              case let .object(apple)? = values["app_attest_registration"],
              Set(apple.keys) == ["protocol", "ceremony_id", "site_trust_domain", "app_identifier", "key_id_b64url", "client_data_hash_b64url", "attestation_object_b64url"],
              apple["protocol"] == .string(AppleAppAttestRegistrationEnvelope.protocolVersion),
              apple["ceremony_id"] == .string(presentation.ceremonyID),
              apple["site_trust_domain"] == .string(presentation.site),
              apple["app_identifier"] == .string(AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier),
              case let .string(appleID)? = apple["key_id_b64url"],
              SiteRootBrokerPresentationV2.base64(appleID, maximum: 128, requireNonzero: false) != nil,
              case let .string(hash)? = apple["client_data_hash_b64url"],
              let actualHash = SiteRootBrokerPresentationV2.base64(hash, exact: 32),
              actualHash == (try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
                  operationID: operationID, correlation: presentation.correlation,
                  reference: presentation.reference, hostChallenge: presentation.challenge)),
              case let .string(attestation)? = apple["attestation_object_b64url"],
              SiteRootBrokerPresentationV2.base64(attestation, maximum: 12 * 1024, requireNonzero: false) != nil
        else { throw PlatformFailure.qrPayloadUnsupported }
    }
}
