import CryptoKit
import Foundation

enum SiteOriginRelocationProfileV1 {
    static let purpose = "proxenos.site-origin-relocation.v1"
    static let audience = "pistis:site-origin-relocation:v1"
    static let presentationSchema = "monas.site-origin-relocation-presentation.v1"
    static let submissionSchema = "monas.site-origin-relocation-submission.v1"
    static let statusSchema = "monas.site-origin-relocation-status.v1"
    static let cancelSchema = "monas.site-origin-relocation-cancel.v1"
    static let presentationPath = "/v1/pistis/site-origin-relocation/v1/presentation"
    static let submissionPath = "/v1/pistis/site-origin-relocation/v1/submission"
    static let statusPath = "/v1/pistis/site-origin-relocation/v1/status"
    static let cancelPath = "/v1/pistis/site-origin-relocation/v1/cancel"
    static let contentType = "application/vnd.mnemosyne.pxsr.v1"
    static let warning = "Commit is forward-only. The former authority origin cannot be restored."
    static let clientDataDomain = Data("PISTIS-PXSR-APP-ATTEST/v1\0".utf8)
}

/// Strict QR presentation whose display and signing authority comes only from
/// the byte-exact canonical Proxenos PXSR/v1 proposal.
struct SiteOriginRelocationPresentationV1: Sendable {
    let canonicalProposal: Data
    let proposalDigest: Data
    let siteUUID: Data
    let siteTrustDomain: String
    let sourceOrigin: URL
    let targetOrigin: URL
    let sourceGeneration: UInt64
    let proposedGeneration: UInt64
    let authorityGeneration: String
    let custodyGeneration: String
    let siteRootGeneration: String
    let issuingCAGeneration: String
    let ceremonyID: Data
    let challengeDigest: Data
    let installationID: Data
    let appAttestKeyID: Data
    let issuedAt: UInt64
    let expiresAt: UInt64

    init(qrText: String, nowUnixSeconds: UInt64) throws {
        guard let data = qrText.data(using: .utf8), data.count <= 8_192 else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let object = try StrictJSONObject(data: data, maximumBytes: 8_192).values
        let keys: Set<String> = [
            "schema", "canonical_proposal_b64", "proposal_sha256_b64url",
            "installation_id_b64url", "app_attest_key_id_b64url", "state", "warning",
        ]
        guard Set(object.keys) == keys,
              case let .string(schema)? = object["schema"],
              schema == SiteOriginRelocationProfileV1.presentationSchema,
              case let .string(encoded)? = object["canonical_proposal_b64"],
              let canonical = Self.standardBase64(encoded, range: 1 ... 4_096),
              case let .string(digestText)? = object["proposal_sha256_b64url"],
              let advertisedDigest = Self.base64URL(digestText, count: 32),
              case let .string(installationText)? = object["installation_id_b64url"],
              let installation = Self.base64URL(installationText, count: 16),
              case let .string(keyText)? = object["app_attest_key_id_b64url"],
              let key = Self.base64URL(keyText, count: 32),
              case let .string(state)? = object["state"], state == "prepared",
              case let .string(warning)? = object["warning"],
              warning == SiteOriginRelocationProfileV1.warning
        else { throw PlatformFailure.qrPayloadUnsupported }
        let parsed = try PXSR(canonical)
        let digest = Data(SHA256.hash(data: canonical))
        guard digest == advertisedDigest,
              parsed.issuedAt <= nowUnixSeconds, nowUnixSeconds < parsed.expiresAt
        else { throw PlatformFailure.qrPayloadUnsupported }
        canonicalProposal = canonical
        proposalDigest = digest
        siteUUID = parsed.siteUUID
        siteTrustDomain = parsed.siteTrustDomain
        sourceOrigin = parsed.sourceOrigin
        targetOrigin = parsed.targetOrigin
        sourceGeneration = parsed.sourceGeneration
        proposedGeneration = parsed.proposedGeneration
        authorityGeneration = parsed.authorityGeneration
        custodyGeneration = parsed.custodyGeneration
        siteRootGeneration = parsed.siteRootGeneration
        issuingCAGeneration = parsed.issuingCAGeneration
        ceremonyID = parsed.ceremonyID
        challengeDigest = parsed.challengeDigest
        installationID = installation
        appAttestKeyID = key
        issuedAt = parsed.issuedAt
        expiresAt = parsed.expiresAt
    }

    func clientDataHash(siteAuthoritySignatureSHA256: Data) throws -> Data {
        guard siteAuthoritySignatureSHA256.count == 32,
              !siteAuthoritySignatureSHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.appAttestInvalidInput }
        return Data(SHA256.hash(data:
            SiteOriginRelocationProfileV1.clientDataDomain + installationID + appAttestKeyID
                + proposalDigest + ceremonyID + challengeDigest + siteAuthoritySignatureSHA256
        ))
    }

    private struct PXSR {
        let siteUUID: Data
        let siteTrustDomain: String
        let sourceOrigin: URL
        let targetOrigin: URL
        let sourceGeneration: UInt64
        let proposedGeneration: UInt64
        let authorityGeneration: String
        let custodyGeneration: String
        let siteRootGeneration: String
        let issuingCAGeneration: String
        let ceremonyID: Data
        let challengeDigest: Data
        let issuedAt: UInt64
        let expiresAt: UInt64

        init(_ data: Data) throws {
            guard data.count >= 8, data.prefix(8) == Data("PXSR/v1\0".utf8) else {
                throw PlatformFailure.qrPayloadUnsupported
            }
            var cursor = 8
            var fields: [Data] = []
            for tag in UInt8(1) ... UInt8(20) {
                guard cursor + 3 <= data.count, data[cursor] == tag else {
                    throw PlatformFailure.qrPayloadUnsupported
                }
                let length = Int(data[cursor + 1]) << 8 | Int(data[cursor + 2])
                cursor += 3
                guard length > 0, cursor + length <= data.count else {
                    throw PlatformFailure.qrPayloadUnsupported
                }
                fields.append(Data(data[cursor ..< cursor + length]))
                cursor += length
            }
            guard cursor == data.count,
                  Self.text(fields[0]) == SiteOriginRelocationProfileV1.purpose,
                  Self.text(fields[1]) == SiteOriginRelocationProfileV1.purpose,
                  Self.text(fields[2]) == SiteOriginRelocationProfileV1.audience,
                  fields[3].count == 16, !fields[3].allSatisfy({ $0 == 0 }),
                  let domain = Self.identifier(fields[4]),
                  let source = Self.origin(fields[5]), let target = Self.origin(fields[6]),
                  source != target, source.port == target.port,
                  let sourceGen = Self.u64(fields[7]), sourceGen > 0,
                  let proposedGen = Self.u64(fields[8]), proposedGen == sourceGen + 1,
                  let authority = Self.identifier(fields[9]),
                  let custody = Self.identifier(fields[10]),
                  let root = Self.identifier(fields[11]),
                  let issuer = Self.identifier(fields[12]),
                  Self.text(fields[13]) == "service-monas-web",
                  Self.text(fields[14]) == target.host,
                  fields[15].count == 16, !fields[15].allSatisfy({ $0 == 0 }),
                  fields[16].count == 32, !fields[16].allSatisfy({ $0 == 0 }),
                  let issued = Self.u64(fields[17]), issued > 0,
                  let expires = Self.u64(fields[18]), expires > issued, expires - issued <= 300,
                  fields[19].count == 32, !fields[19].allSatisfy({ $0 == 0 })
            else { throw PlatformFailure.qrPayloadUnsupported }
            siteUUID = fields[3]; siteTrustDomain = domain
            sourceOrigin = source; targetOrigin = target
            sourceGeneration = sourceGen; proposedGeneration = proposedGen
            authorityGeneration = authority; custodyGeneration = custody
            siteRootGeneration = root; issuingCAGeneration = issuer
            ceremonyID = fields[15]; challengeDigest = fields[16]
            issuedAt = issued; expiresAt = expires
        }

        private static func text(_ data: Data) -> String? {
            guard !data.isEmpty, data.count <= 128 else { return nil }
            return String(data: data, encoding: .utf8)
        }
        private static func identifier(_ data: Data) -> String? {
            guard let value = text(data), value.utf8.allSatisfy({
                $0.isASCIIAlphaNumeric || [45, 46, 58, 95].contains($0)
            }) else { return nil }
            return value
        }
        private static func u64(_ data: Data) -> UInt64? {
            guard data.count == 8 else { return nil }
            return data.reduce(0) { ($0 << 8) | UInt64($1) }
        }
        private static func origin(_ data: Data) -> URL? {
            guard data.count <= 96, let text = text(data), let url = URL(string: text),
                  url.scheme == "https", url.user == nil, url.password == nil,
                  url.path == "/", url.query == nil, url.fragment == nil,
                  let host = url.host, let port = url.port, port > 0,
                  text == "https://\(host.contains(":") ? "[\(host)]" : host):\(port)/",
                  Self.privateIPAddress(host)
            else { return nil }
            return url
        }
        private static func privateIPAddress(_ host: String) -> Bool {
            let parts = host.split(separator: ".").compactMap { UInt8($0) }
            if parts.count == 4 {
                return parts[0] == 10 || (parts[0] == 172 && (16 ... 31).contains(parts[1]))
                    || (parts[0] == 192 && parts[1] == 168)
            }
            return host.lowercased().hasPrefix("fc") || host.lowercased().hasPrefix("fd")
        }
    }

    static func standardBase64(_ value: String, range: ClosedRange<Int>) -> Data? {
        guard !value.isEmpty, value.count % 4 == 0, !value.contains("-"), !value.contains("_"),
              let data = Data(base64Encoded: value), range.contains(data.count),
              data.base64EncodedString() == value else { return nil }
        return data
    }
    static func base64URL(_ value: String, count: Int) -> Data? {
        guard !value.contains("="), value.utf8.allSatisfy({
            $0.isASCIIAlphaNumeric || $0 == 45 || $0 == 95
        }) else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: standard), data.count == count,
              Self.base64URL(data) == value, !data.allSatisfy({ $0 == 0 }) else { return nil }
        return data
    }
    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

private extension UInt8 {
    var isASCIIAlphaNumeric: Bool {
        (48 ... 57).contains(self) || (65 ... 90).contains(self) || (97 ... 122).contains(self)
    }
}

struct SiteOriginRelocationSubmissionV1: Encodable, Sendable {
    let schema = SiteOriginRelocationProfileV1.submissionSchema
    let canonicalProposalB64: String
    let proposalSHA256B64URL: String
    let detachedCOSESign1B64URL: String
    let appAttest: AppleAppAttestAssertionEnvelope
    enum CodingKeys: String, CodingKey {
        case schema
        case canonicalProposalB64 = "canonical_proposal_b64"
        case proposalSHA256B64URL = "proposal_sha256_b64url"
        case detachedCOSESign1B64URL = "detached_cose_sign1_b64url"
        case appAttest = "app_attest"
    }
}

struct SiteOriginRelocationStatusV1: Sendable {
    enum State: String, Sendable { case prepared, approved, certificateReady = "certificate_ready", committed, converged, cancelled }
    let state: State
    init(data: Data, expected: SiteOriginRelocationPresentationV1) throws {
        let object = try StrictJSONObject(data: data, maximumBytes: 4_096).values
        guard Set(object.keys) == ["schema", "ceremony_id_b64url", "proposal_sha256_b64url", "state"],
              case let .string(schema)? = object["schema"], schema == SiteOriginRelocationProfileV1.statusSchema,
              case let .string(ceremony)? = object["ceremony_id_b64url"],
              SiteOriginRelocationPresentationV1.base64URL(ceremony, count: 16) == expected.ceremonyID,
              case let .string(digest)? = object["proposal_sha256_b64url"],
              SiteOriginRelocationPresentationV1.base64URL(digest, count: 32) == expected.proposalDigest,
              case let .string(stateText)? = object["state"], let parsed = State(rawValue: stateText)
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        state = parsed
    }
}

/// Produces the existing Site-authority COSE proof and App Attest assertion
/// after one Face ID evaluation; it creates no generic grant or browser token.
final class SecureEnclaveSiteOriginRelocationProducerV1: @unchecked Sendable {
    private let appAttest: AppleAppAttestClient
    init(appAttest: AppleAppAttestClient = AppleAppAttestClient()) { self.appAttest = appAttest }

    func produce(_ value: SiteOriginRelocationPresentationV1) async throws
        -> SiteOriginRelocationSubmissionV1
    {
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Move this Site authority from \(value.sourceOrigin.absoluteString) to \(value.targetOrigin.absoluteString)"
        )
        let signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Approve this exact forward-only Site authority move"
        )
        guard try signer.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let protected = try DetachedES256Cose.protectedHeaders(
            kid: Data(value.authorityGeneration.utf8), contentType: SiteOriginRelocationProfileV1.contentType
        )
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: value.canonicalProposal
        )
        let signature = try signer.sign(message: structure, using: ceremony)
        let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)
        let signatureDigest = Data(SHA256.hash(data: cose))
        let clientHash = try value.clientDataHash(siteAuthoritySignatureSHA256: signatureDigest)
        let assertion = try await appAttest.prepareSiteOriginRelocationAssertion(
            ceremonyID: value.ceremonyID, expectedKeyID: value.appAttestKeyID,
            clientDataHash: clientHash
        )
        return SiteOriginRelocationSubmissionV1(
            canonicalProposalB64: value.canonicalProposal.base64EncodedString(),
            proposalSHA256B64URL: SiteOriginRelocationPresentationV1.base64URL(value.proposalDigest),
            detachedCOSESign1B64URL: SiteOriginRelocationPresentationV1.base64URL(cose),
            appAttest: assertion
        )
    }
}

/// Exact-target Site-root TLS transport. It accepts no URL from the JSON
/// wrapper, follows no redirect and reconciles an ambiguous submit by reading
/// only the same ceremony and proposal digest from authoritative status.
struct MonasSiteOriginRelocationTransportV1: Sendable {
    private let origin: URL
    private let session: URLSession

    init(
        targetOrigin: URL,
        trustPolicy: MonasServerTrustPolicy,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        guard targetOrigin.scheme == "https", targetOrigin.path == "/",
              targetOrigin.user == nil, targetOrigin.password == nil,
              targetOrigin.query == nil, targetOrigin.fragment == nil,
              targetOrigin.host != nil, targetOrigin.port != nil
        else { throw PlatformFailure.invalidConfiguration }
        origin = targetOrigin
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(
            configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(origin: targetOrigin, trustPolicy: trustPolicy),
            delegateQueue: nil
        )
    }

    func submit(
        _ submission: SiteOriginRelocationSubmissionV1,
        expected: SiteOriginRelocationPresentationV1
    ) async throws -> SiteOriginRelocationStatusV1 {
        do {
            return try await post(
                submission, path: SiteOriginRelocationProfileV1.submissionPath,
                expected: expected, maximumRequestBytes: 32_768
            )
        } catch is URLError {
            let observed = try await status(expected)
            guard observed.state != .prepared else {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
            return observed
        }
    }

    func status(_ expected: SiteOriginRelocationPresentationV1) async throws
        -> SiteOriginRelocationStatusV1
    {
        let ceremony = SiteOriginRelocationPresentationV1.base64URL(expected.ceremonyID)
        let digest = SiteOriginRelocationPresentationV1.base64URL(expected.proposalDigest)
        guard var components = URLComponents(
            url: try endpoint(SiteOriginRelocationProfileV1.statusPath),
            resolvingAgainstBaseURL: false
        ) else { throw PlatformFailure.siteRootAuthorityUnavailable }
        components.queryItems = [
            URLQueryItem(name: "ceremony_id_b64url", value: ceremony),
            URLQueryItem(name: "proposal_sha256_b64url", value: digest),
        ]
        guard let url = components.url else { throw PlatformFailure.siteRootAuthorityUnavailable }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"; request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        return try await response(request, expected: expected)
    }

    func cancel(_ expected: SiteOriginRelocationPresentationV1) async throws
        -> SiteOriginRelocationStatusV1
    {
        let request = CancelRequest(
            ceremonyIDB64URL: SiteOriginRelocationPresentationV1.base64URL(expected.ceremonyID),
            proposalSHA256B64URL: SiteOriginRelocationPresentationV1.base64URL(expected.proposalDigest)
        )
        let status: SiteOriginRelocationStatusV1 = try await post(
            request, path: SiteOriginRelocationProfileV1.cancelPath,
            expected: expected, maximumRequestBytes: 2_048
        )
        guard status.state == .cancelled else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return status
    }

    private func post<T: Encodable>(
        _ body: T, path: String, expected: SiteOriginRelocationPresentationV1,
        maximumRequestBytes: Int
    ) async throws -> SiteOriginRelocationStatusV1 {
        let encoded = try JSONEncoder().encode(body)
        guard !encoded.isEmpty, encoded.count <= maximumRequestBytes else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        var request = URLRequest(url: try endpoint(path))
        request.httpMethod = "POST"; request.httpBody = encoded; request.timeoutInterval = 15
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        return try await response(request, expected: expected)
    }

    private func response(
        _ request: URLRequest, expected: SiteOriginRelocationPresentationV1
    ) async throws -> SiteOriginRelocationStatusV1 {
        let (data, response) = try await session.data(for: request)
        guard data.count <= 4_096, let http = response as? HTTPURLResponse,
              http.url == request.url, http.statusCode == 200,
              http.value(forHTTPHeaderField: "Cache-Control")?.lowercased().contains("no-store") == true
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return try SiteOriginRelocationStatusV1(data: data, expected: expected)
    }

    private func endpoint(_ path: String) throws -> URL {
        guard var components = URLComponents(url: origin, resolvingAgainstBaseURL: false) else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        components.path = path
        guard let value = components.url, value.scheme == origin.scheme,
              value.host == origin.host, value.port == origin.port,
              value.path == path, value.query == nil, value.fragment == nil
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return value
    }

    private struct CancelRequest: Encodable {
        let schema = SiteOriginRelocationProfileV1.cancelSchema
        let ceremonyIDB64URL: String
        let proposalSHA256B64URL: String
        enum CodingKeys: String, CodingKey {
            case schema
            case ceremonyIDB64URL = "ceremony_id_b64url"
            case proposalSHA256B64URL = "proposal_sha256_b64url"
        }
    }
}
