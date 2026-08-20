import Foundation

enum SiteRootConvergenceProfileV2 {
    static let provisionSchema = "monas.site-root-bundle-receipt-provision-presentation.v1"
    static let provisionSubmissionSchema =
        "monas.site-root-bundle-receipt-provision-submission.v1"
    static let provisionPurpose = "site-root-bundle-receipt-provision"
    static let provisionPath = "/v1/pistis/site-root-bundle-receipt-provision/submit"
    static let ackSchema = "monas.pistis-site-root-ack-presentation.v1"
    static let ackPurpose = "site-root-convergence-ack"
    static let ackSubmissionPath = "/v1/pistis/site-root-convergence-ack/submit"
    static let registrationPath = "/auth/pistis/site-root-convergence/v2/register"
    static let pxakContentType = "application/vnd.mnemosyne.pxak.v2"
    static let pxraContentType = "application/vnd.mnemosyne.pxra.v2"
    static let x509ProvisionSchema = "monas.site-x509-first-provision-presentation.v1"
    static let x509SubmissionSchema = "monas.site-x509-first-provision-submission.v1"
    static let x509Purpose = "site-x509-first-provision"
    static let x509RootPurpose = "site-x509-root-first-provision"
    static let x509IssuerPurpose = "site-x509-issuer-first-provision"
    static let x509SubmitPath = "/v1/pistis/site-x509-first-provision/submit"
    static let x509ContentType = "application/vnd.mnemosyne.pxfp.v1"
    static let x509BrokerProvisionSchema =
        "monas.site-x509-first-provision-broker-presentation.v1"
    static let x509BrokerSubmissionSchema =
        "mnemosyne.monas.first-install-broker.pistis-site-x509-first-provision-submission.v1"
    static let x509BrokerPurpose = "site-x509-first-provision"
    static let x509BrokerOrigin = "https://install.mnemosyne.co.uk"
    static let x509BrokerAttemptSchema =
        "mnemosyne.monas.first-install-broker.pistis-site-x509-first-provision-attempt.v1"
    static let x509BrokerAttemptPath =
        "/api/first-install/v1/pistis/site-x509-first-provision/attempt"
    static let x509BrokerAttemptResponseState = "reserved"
    static let x509BrokerResponseSchema = "mnemosyne.monas.first-install-broker.response.v1"
    static let x509BrokerSubmitPath =
        "/api/first-install/v1/pistis/site-x509-first-provision/submit"
}

struct SiteX509FirstProvisionPresentationV1: Equatable, Sendable {
    static let roles = ["site-x509-root", "site-x509-issuer"]

    let siteUUID: String
    let transactionUUID: String
    let challenge: Data
    let expiresAtUnixSeconds: UInt64
    let generation: UInt64

    init(qrText: String, nowUnixSeconds: UInt64) throws {
        let object = try SiteRootConvergenceEncoding.object(qrText, maximumBytes: 8_192)
        guard Set(object.keys) == [
            "schema", "purpose", "site_uuid", "transaction_uuid",
            "canonical_challenge_b64url", "expires_at_unix_seconds", "generation", "roles",
            "submission_path",
        ],
        SiteRootConvergenceEncoding.string(object, "schema")
            == SiteRootConvergenceProfileV2.x509ProvisionSchema,
        SiteRootConvergenceEncoding.string(object, "purpose")
            == SiteRootConvergenceProfileV2.x509Purpose,
        let siteText = SiteRootConvergenceEncoding.string(object, "site_uuid"),
        let siteBytes = SiteRootConvergenceEncoding.uuidBytes(siteText),
        let transactionText = SiteRootConvergenceEncoding.string(object, "transaction_uuid"),
        let transaction = SiteRootConvergenceEncoding.uuidBytes(transactionText),
        let challenge = SiteRootConvergenceEncoding.bytes(
            object, "canonical_challenge_b64url", maximum: 2_048, nonzero: true
        ),
        let expiry = SiteRootConvergenceEncoding.positiveUInt64(
            object, "expires_at_unix_seconds"
        ),
        nowUnixSeconds < expiry, expiry - nowUnixSeconds <= 300,
        let generation = SiteRootConvergenceEncoding.positiveUInt64(object, "generation"),
        SiteRootConvergenceEncoding.stringArray(object, "roles") == Self.roles,
        SiteRootConvergenceEncoding.string(object, "submission_path")
            == SiteRootConvergenceProfileV2.x509SubmitPath
        else { throw PlatformFailure.qrPayloadUnsupported }
        let parsed = try SiteX509FirstProvisionChallengeV1(
            challenge, nowUnixSeconds: nowUnixSeconds
        )
        guard parsed.siteUUID == siteBytes, parsed.transactionID == transaction,
              parsed.generation == generation, parsed.expiresAtUnixSeconds == expiry
        else { throw PlatformFailure.qrPayloadUnsupported }
        siteUUID = siteText
        transactionUUID = transactionText
        self.challenge = challenge
        expiresAtUnixSeconds = expiry
        self.generation = generation
    }
}

struct SiteX509FirstProvisionBrokerPresentationV1: Equatable, Sendable {
    static let roles = ["site-x509-root-first-provision", "site-x509-issuer-first-provision"]
    private static let enrolledSiteRootPublicKeyIDField =
        "enrolled_site_root_public_key_id_b64url"

    let siteUUID: String
    let transactionUUID: String
    let challenge: Data
    let correlation: Data
    let enrolledSiteRootPublicKeyID: Data
    let expiresAtUnixSeconds: UInt64
    let generation: UInt64
    let submissionURL: URL

    init(qrText: String, nowUnixSeconds: UInt64) throws {
        let object = try SiteRootConvergenceEncoding.object(qrText, maximumBytes: 8_192)
        let requiredFields: Set<String> = [
            "schema", "purpose", "site_uuid", "transaction_uuid", "generation",
            "canonical_challenge_b64url", "correlation_b64url", "roles",
            "expires_at_unix_seconds", "submission_url",
            Self.enrolledSiteRootPublicKeyIDField,
        ]
        guard Set(object.keys) == requiredFields,
        SiteRootConvergenceEncoding.string(object, "schema")
            == SiteRootConvergenceProfileV2.x509BrokerProvisionSchema,
        SiteRootConvergenceEncoding.string(object, "purpose")
            == SiteRootConvergenceProfileV2.x509BrokerPurpose,
        let siteText = SiteRootConvergenceEncoding.string(object, "site_uuid"),
        let siteBytes = SiteRootConvergenceEncoding.uuidBytes(siteText),
        let transactionText = SiteRootConvergenceEncoding.string(object, "transaction_uuid"),
        let transaction = SiteRootConvergenceEncoding.uuidBytes(transactionText),
        let challenge = SiteRootConvergenceEncoding.bytes(
            object, "canonical_challenge_b64url", maximum: 2_048, nonzero: true
        ),
        let correlation = SiteRootConvergenceEncoding.bytes(
            object, "correlation_b64url", count: 32, nonzero: true
        ),
        let expiry = SiteRootConvergenceEncoding.positiveUInt64(
            object, "expires_at_unix_seconds"
        ),
        nowUnixSeconds < expiry, expiry - nowUnixSeconds <= 300,
        let generation = SiteRootConvergenceEncoding.positiveUInt64(object, "generation"),
        SiteRootConvergenceEncoding.stringArray(object, "roles") == Self.roles,
        let urlText = SiteRootConvergenceEncoding.string(object, "submission_url"),
        let submissionURL = URL(string: urlText),
        let brokerOrigin = URL(string: SiteRootConvergenceProfileV2.x509BrokerOrigin),
        SiteRootConvergenceEncoding.matches(
            submissionURL, origin: brokerOrigin,
            path: SiteRootConvergenceProfileV2.x509BrokerSubmitPath
        ) else { throw PlatformFailure.qrPayloadUnsupported }
        guard let enrolledSiteRootPublicKeyID = SiteRootConvergenceEncoding.bytes(
            object, Self.enrolledSiteRootPublicKeyIDField, count: 32, nonzero: true
        ) else { throw PlatformFailure.qrPayloadUnsupported }
        let parsed = try SiteX509FirstProvisionChallengeV1(
            challenge, nowUnixSeconds: nowUnixSeconds
        )
        guard parsed.siteUUID == siteBytes, parsed.transactionID == transaction,
              parsed.generation == generation, parsed.expiresAtUnixSeconds == expiry
        else { throw PlatformFailure.qrPayloadUnsupported }
        siteUUID = siteText
        transactionUUID = transactionText
        self.challenge = challenge
        self.correlation = correlation
        self.enrolledSiteRootPublicKeyID = enrolledSiteRootPublicKeyID
        expiresAtUnixSeconds = expiry
        self.generation = generation
        self.submissionURL = submissionURL
    }
}

private struct SiteX509FirstProvisionChallengeV1 {
    let siteUUID: Data
    let transactionID: Data
    let generation: UInt64
    let expiresAtUnixSeconds: UInt64

    init(_ data: Data, nowUnixSeconds: UInt64) throws {
        guard data.starts(with: Data("PXFP/v1\u{1}".utf8)) else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        var reader = SiteRootTLVReader(Data(data.dropFirst(8)))
        let purpose = try reader.field(tag: 0x01, count: nil)
        let site = try reader.field(tag: 0x02, count: 16)
        let transaction = try reader.field(tag: 0x03, count: 16)
        let generationBytes = try reader.field(tag: 0x04, count: 8)
        let rootPurpose = try reader.field(tag: 0x05, count: nil)
        let rootPublic = try reader.field(tag: 0x06, count: 33)
        let rootSPKI = try reader.field(tag: 0x07, count: 32)
        let rootObject = try reader.field(tag: 0x08, count: 32)
        let issuerPurpose = try reader.field(tag: 0x09, count: nil)
        let issuerPublic = try reader.field(tag: 0x0a, count: 33)
        let issuerSPKI = try reader.field(tag: 0x0b, count: 32)
        let issuerObject = try reader.field(tag: 0x0c, count: 32)
        let expiryBytes = try reader.field(tag: 0x0d, count: 8)
        let nonce = try reader.field(tag: 0x0e, count: 32)
        try reader.requireEnd()
        guard String(data: purpose, encoding: .utf8) == SiteRootConvergenceProfileV2.x509Purpose,
              String(data: rootPurpose, encoding: .utf8)
                == SiteRootConvergenceProfileV2.x509RootPurpose,
              String(data: issuerPurpose, encoding: .utf8)
                == SiteRootConvergenceProfileV2.x509IssuerPurpose,
              !site.allSatisfy({ $0 == 0 }), !transaction.allSatisfy({ $0 == 0 }),
              [rootPublic, rootSPKI, rootObject, issuerPublic, issuerSPKI, issuerObject, nonce]
                .allSatisfy({ !$0.allSatisfy({ $0 == 0 }) }),
              rootPublic != issuerPublic, rootSPKI != issuerSPKI, rootObject != issuerObject,
              let generation = SiteRootConvergenceEncoding.uint64(generationBytes), generation > 0,
              let expiry = SiteRootConvergenceEncoding.uint64(expiryBytes),
              nowUnixSeconds < expiry, expiry - nowUnixSeconds <= 300
        else { throw PlatformFailure.qrPayloadUnsupported }
        siteUUID = site
        transactionID = transaction
        self.generation = generation
        expiresAtUnixSeconds = expiry
    }
}

struct SiteRootBundleReceiptProvisionPresentationV1: Equatable, Sendable {
    let correlation: Data
    let canonicalChallenge: Data
    let siteTrustDomain: String
    let receiptKeyGeneration: UInt64
    let expiresAtUnixSeconds: UInt64

    init(qrText: String, nowUnixSeconds: UInt64) throws {
        let object = try SiteRootConvergenceEncoding.object(qrText, maximumBytes: 8_192)
        let required: Set<String> = [
            "schema", "purpose", "correlation_b64url", "canonical_challenge_b64url",
            "site_trust_domain", "receipt_key_generation", "expires_at_unix_seconds",
            "submission_path",
        ]
        guard Set(object.keys) == required,
              SiteRootConvergenceEncoding.string(object, "schema")
                == SiteRootConvergenceProfileV2.provisionSchema,
              SiteRootConvergenceEncoding.string(object, "purpose")
                == SiteRootConvergenceProfileV2.provisionPurpose,
              let correlation = SiteRootConvergenceEncoding.bytes(
                  object, "correlation_b64url", count: 16, nonzero: true
              ),
              let challenge = SiteRootConvergenceEncoding.bytes(
                  object, "canonical_challenge_b64url", maximum: 1_024, nonzero: true
              ),
              let site = SiteRootConvergenceEncoding.identifier(
                  object, "site_trust_domain", maximum: 255
              ),
              let generation = SiteRootConvergenceEncoding.positiveUInt64(
                  object, "receipt_key_generation"
              ),
              let expiry = SiteRootConvergenceEncoding.positiveUInt64(
                  object, "expires_at_unix_seconds"
              ),
              nowUnixSeconds < expiry, expiry - nowUnixSeconds <= 300,
              SiteRootConvergenceEncoding.string(object, "submission_path")
                == SiteRootConvergenceProfileV2.provisionPath
        else { throw PlatformFailure.qrPayloadUnsupported }
        self.correlation = correlation
        canonicalChallenge = challenge
        siteTrustDomain = site
        receiptKeyGeneration = generation
        expiresAtUnixSeconds = expiry
    }

    func validateChallenge(deviceKeyID: String) throws {
        let fields = try SiteRootProvisionChallengeV1(canonicalChallenge)
        guard fields.siteTrustDomain == siteTrustDomain,
              fields.generationName == "site-root-bundle-receipt-\(receiptKeyGeneration)",
              fields.deviceKeyID == deviceKeyID
        else { throw PlatformFailure.qrPayloadUnsupported }
    }
}

private struct SiteRootProvisionChallengeV1 {
    let siteTrustDomain: String
    let generationName: String
    let deviceKeyID: String

    init(_ data: Data) throws {
        var reader = SiteRootTLVReader(data)
        let schema = try reader.field(tag: 0x01, count: nil)
        let purpose = try reader.field(tag: 0x02, count: nil)
        let site = try reader.field(tag: 0x03, count: nil)
        let generation = try reader.field(tag: 0x04, count: nil)
        let device = try reader.field(tag: 0x05, count: nil)
        _ = try reader.field(tag: 0x06, count: 33)
        _ = try reader.field(tag: 0x07, count: 32)
        try reader.requireEnd()
        guard String(data: schema, encoding: .utf8)
                == "mnemosyne.thesaurophylax.site-root-bundle-receipt-provision.v1",
              String(data: purpose, encoding: .utf8)
                == SiteRootConvergenceProfileV2.provisionPurpose,
              let siteText = String(data: site, encoding: .utf8),
              let generationText = String(data: generation, encoding: .utf8),
              let deviceText = String(data: device, encoding: .utf8)
        else { throw PlatformFailure.qrPayloadUnsupported }
        siteTrustDomain = siteText
        generationName = generationText
        deviceKeyID = deviceText
    }
}

struct SiteRootConvergenceAckPresentationV2: Equatable, Sendable {
    let unsignedPXRA: Data
    let submissionURL: URL
    let assertion: UnsignedSiteRootConvergenceAssertionV2

    init(qrText: String, authorityOrigin: URL, nowUnixMilliseconds: UInt64) throws {
        let object = try SiteRootConvergenceEncoding.object(qrText, maximumBytes: 2_048)
        guard Set(object.keys) == [
            "schema", "purpose", "unsigned_pxra_v2_b64url", "submission_url",
        ],
        SiteRootConvergenceEncoding.string(object, "schema")
            == SiteRootConvergenceProfileV2.ackSchema,
        SiteRootConvergenceEncoding.string(object, "purpose")
            == SiteRootConvergenceProfileV2.ackPurpose,
        let unsigned = SiteRootConvergenceEncoding.bytes(
            object, "unsigned_pxra_v2_b64url", maximum: 512, nonzero: true
        ),
        let urlText = SiteRootConvergenceEncoding.string(object, "submission_url"),
        let url = URL(string: urlText),
        SiteRootConvergenceEncoding.matches(
            url, origin: authorityOrigin,
            path: SiteRootConvergenceProfileV2.ackSubmissionPath
        ) else { throw PlatformFailure.qrPayloadUnsupported }
        self.unsignedPXRA = unsigned
        submissionURL = url
        assertion = try UnsignedSiteRootConvergenceAssertionV2(
            unsigned, nowUnixMilliseconds: nowUnixMilliseconds
        )
    }
}

struct UnsignedSiteRootConvergenceAssertionV2: Equatable, Sendable {
    enum Action: UInt8, Equatable, Sendable { case install = 1, replace = 2, remove = 3 }

    let siteUUID: Data
    let siteUUIDText: String
    let targetID: Data
    let action: Action
    let transactionID: Data
    let rootGeneration: UInt64
    let trustRevision: UInt64
    let rootFingerprint: Data
    let previousRootFingerprint: Data
    let issuedAtUnixMilliseconds: UInt64
    let expiresAtUnixMilliseconds: UInt64
    let nonce: Data
    let ackKeyGeneration: UInt64

    init(_ data: Data, nowUnixMilliseconds: UInt64) throws {
        guard data.count <= 512, data.starts(with: Data("PXRA/v2\u{1}".utf8))
        else { throw PlatformFailure.qrPayloadUnsupported }
        var reader = SiteRootTLVReader(Data(data.dropFirst(8)))
        let site = try reader.field(tag: 0x01, count: 16)
        let target = try reader.field(tag: 0x02, count: 32)
        let actionBytes = try reader.field(tag: 0x03, count: 1)
        let transaction = try reader.field(tag: 0x04, count: 16)
        let root = try reader.field(tag: 0x05, count: 8)
        let trust = try reader.field(tag: 0x06, count: 8)
        let fingerprint = try reader.field(tag: 0x07, count: 32)
        let nativeAction = try reader.field(tag: 0x08, count: 1)
        let previous = try reader.field(tag: 0x09, allowedCounts: [0, 32])
        let issued = try reader.field(tag: 0x0a, count: 8)
        let expiry = try reader.field(tag: 0x0b, count: 8)
        let nonce = try reader.field(tag: 0x0c, count: 32)
        let generation = try reader.field(tag: 0x0d, count: 8)
        try reader.requireEnd()
        guard let action = Action(rawValue: actionBytes[0]),
              nativeAction == actionBytes,
              !site.allSatisfy({ $0 == 0 }), !target.allSatisfy({ $0 == 0 }),
              !transaction.allSatisfy({ $0 == 0 }), !fingerprint.allSatisfy({ $0 == 0 }),
              !nonce.allSatisfy({ $0 == 0 }),
              let rootValue = SiteRootConvergenceEncoding.uint64(root), rootValue > 0,
              let trustValue = SiteRootConvergenceEncoding.uint64(trust), trustValue > 0,
              let issuedValue = SiteRootConvergenceEncoding.uint64(issued), issuedValue > 0,
              let expiryValue = SiteRootConvergenceEncoding.uint64(expiry),
              issuedValue <= nowUnixMilliseconds + 30_000,
              nowUnixMilliseconds < expiryValue,
              expiryValue > issuedValue, expiryValue - issuedValue <= 300_000,
              let generationValue = SiteRootConvergenceEncoding.uint64(generation),
              generationValue > 0,
              (action == .install ? previous.isEmpty : previous.count == 32),
              previous.isEmpty || !previous.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.qrPayloadUnsupported }
        siteUUID = site
        siteUUIDText = Self.uuidText(site)
        targetID = target
        self.action = action
        transactionID = transaction
        rootGeneration = rootValue
        trustRevision = trustValue
        rootFingerprint = fingerprint
        previousRootFingerprint = previous
        issuedAtUnixMilliseconds = issuedValue
        expiresAtUnixMilliseconds = expiryValue
        self.nonce = nonce
        ackKeyGeneration = generationValue
    }

    private static func uuidText(_ bytes: Data) -> String {
        let b = [UInt8](bytes)
        return String(
            format: "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10],
            b[11], b[12], b[13], b[14], b[15]
        )
    }
}

private struct SiteRootTLVReader {
    private let data: Data
    private var offset = 0

    init(_ data: Data) { self.data = data }

    mutating func field(tag: UInt8, count: Int?) throws -> Data {
        let value = try field(tag: tag, allowedCounts: count.map { [$0] })
        return value
    }

    mutating func field(tag: UInt8, allowedCounts: Set<Int>?) throws -> Data {
        guard offset + 3 <= data.count, data[offset] == tag else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let length = Int(data[offset + 1]) << 8 | Int(data[offset + 2])
        offset += 3
        guard offset + length <= data.count,
              allowedCounts?.contains(length) ?? true
        else { throw PlatformFailure.qrPayloadUnsupported }
        defer { offset += length }
        return data.subdata(in: offset ..< offset + length)
    }

    mutating func requireEnd() throws {
        guard offset == data.count else { throw PlatformFailure.qrPayloadUnsupported }
    }
}

enum SiteRootConvergenceEncoding {
    static func object(_ text: String, maximumBytes: Int) throws
        -> [String: StrictJSONObject.Value]
    {
        guard let data = text.data(using: .utf8), data.count <= maximumBytes else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        do { return try StrictJSONObject(data: data, maximumBytes: maximumBytes).values }
        catch { throw PlatformFailure.qrPayloadUnsupported }
    }

    static func string(_ object: [String: StrictJSONObject.Value], _ key: String) -> String? {
        guard case let .string(value)? = object[key] else { return nil }
        return value
    }

    static func identifier(
        _ object: [String: StrictJSONObject.Value], _ key: String, maximum: Int
    ) -> String? {
        guard let value = string(object, key), !value.isEmpty,
              value.utf8.count <= maximum,
              value.utf8.allSatisfy({
                  (48 ... 57).contains($0) || (65 ... 90).contains($0)
                    || (97 ... 122).contains($0) || [45, 46, 58, 95].contains($0)
              }) else { return nil }
        return value
    }

    static func positiveUInt64(
        _ object: [String: StrictJSONObject.Value], _ key: String
    ) -> UInt64? {
        guard case let .number(text)? = object[key], let value = UInt64(text), value > 0
        else { return nil }
        return value
    }

    static func stringArray(
        _ object: [String: StrictJSONObject.Value], _ key: String
    ) -> [String]? {
        guard case let .array(values)? = object[key] else { return nil }
        return values.reduce(into: [String]?([])) { result, value in
            guard case let .string(text) = value else { result = nil; return }
            result?.append(text)
        }
    }

    static func bytes(
        _ object: [String: StrictJSONObject.Value], _ key: String,
        count: Int? = nil, maximum: Int? = nil, nonzero: Bool
    ) -> Data? {
        guard let text = string(object, key), let data = base64URL(text),
              count.map({ data.count == $0 }) ?? true,
              maximum.map({ data.count <= $0 }) ?? true,
              !nonzero || !data.allSatisfy({ $0 == 0 }) else { return nil }
        return data
    }

    static func base64URL(_ value: String) -> Data? {
        guard !value.isEmpty, !value.contains("="), value.count % 4 != 1,
              value.utf8.allSatisfy({
                  (48 ... 57).contains($0) || (65 ... 90).contains($0)
                    || (97 ... 122).contains($0) || $0 == 45 || $0 == 95
              }) else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: standard), encode(data) == value else { return nil }
        return data
    }

    static func encode(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func uint64(_ data: Data) -> UInt64? {
        guard data.count == 8 else { return nil }
        return data.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    static func uint64Bytes(_ value: UInt64) -> Data {
        Data((0 ..< 8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
    }

    static func uuidBytes(_ value: String) -> Data? {
        let parts = value.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.map(\.count) == [8, 4, 4, 4, 12],
              value == value.lowercased() else { return nil }
        let hex = parts.joined()
        var result = Data()
        result.reserveCapacity(16)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        return result.count == 16 && !result.allSatisfy({ $0 == 0 }) ? result : nil
    }

    static func matches(_ candidate: URL, origin: URL, path: String) -> Bool {
        candidate.scheme == origin.scheme && candidate.host == origin.host
            && candidate.port == origin.port && candidate.user == nil && candidate.password == nil
            && candidate.path == path && candidate.query == nil && candidate.fragment == nil
    }
}
