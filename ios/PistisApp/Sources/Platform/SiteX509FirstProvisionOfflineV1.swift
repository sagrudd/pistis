import CryptoKit
import Darwin
import Foundation

enum SiteX509FirstProvisionOfflineProfileV2 {
    static let presentationMagic = Data("PXFP/v2\u{2}".utf8)
    static let responseMagic = Data("PXFP/v2\u{3}".utf8)
    static let contextMagic = Data("PXCT/v2\0".utf8)
    static let challengeMagic = Data("PXFP/v1\u{1}".utf8)
    static let transcriptMagic = Data("PXAT/v2\0".utf8)
    static let purpose = "site-x509-first-provision-offline-v2"
    static let audience = "pistis:site-x509-first-provision-offline:v2"
    static let contentType = "application/vnd.mnemosyne.pxfp.v1"
    static let presentationQRPrefix = "PXFP2:P:"
    static let responseQRPrefix = "PXFP2:R:"
    static let maximumQRBytes = 2_953
    static let maximumPresentationFileBytes = 8_192
}

struct SiteX509FirstProvisionOfflineServiceV2: Equatable, Sendable {
    let serviceID: String
    let privateIPs: [String]
}

/// Byte-exact ADR-0014 presentation parsed from strict QR text or a raw file.
struct SiteX509FirstProvisionOfflinePresentationV2: Equatable, Sendable {
    let canonical: Data
    let canonicalChallenge: Data
    let presentationDigest: Data
    let contextDigest: Data
    let challengeDigest: Data
    let siteUUID: Data
    let transactionUUID: Data
    let generation: UInt64
    let rootPublicKey: Data
    let issuerPublicKey: Data
    let siteTrustDomain: String
    let authorityGeneration: String
    let custodyGeneration: String
    let revocationGeneration: UInt64
    let installationID: String
    let deviceID: String
    let appAttestKeyID: String
    let appAttestApplicationID: String
    let siteRootApprovalKeyID: Data
    let siteRootApprovalPublicKey: Data
    let targetKind: String
    let targetID: Data
    let services: [SiteX509FirstProvisionOfflineServiceV2]
    let replayReference: Data
    let ceremonyChallenge: Data
    let preparedAt: UInt64
    let expiresAt: UInt64

    init(qrText: String, nowUnixSeconds: UInt64) throws {
        guard let bytes = Self.decodeQR(qrText, prefix: SiteX509FirstProvisionOfflineProfileV2.presentationQRPrefix) else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        try self.init(fileBytes: bytes, nowUnixSeconds: nowUnixSeconds)
    }

    init(fileBytes: Data, nowUnixSeconds: UInt64) throws {
        let fields = try TLV.parse(fileBytes, magic: SiteX509FirstProvisionOfflineProfileV2.presentationMagic, tags: 1 ... 9)
        guard (1 ... 2_048).contains(fields[0].count), fields[1].count == 32,
              Data(SHA256.hash(data: fields[0])) == fields[1], fields[2].count == 16,
              (1 ... 4_096).contains(fields[3].count), fields[4].count == 32,
              Data(SHA256.hash(data: fields[3])) == fields[4], fields[5].count == 32,
              fields[6].count == 32, let prepared = Self.u64(fields[7]),
              let expiry = Self.u64(fields[8]), prepared <= nowUnixSeconds,
              nowUnixSeconds < expiry, expiry > prepared, expiry - prepared <= 300
        else { throw PlatformFailure.qrPayloadUnsupported }
        let challenge = try Challenge(fields[0], now: nowUnixSeconds)
        let context = try Context(fields[3])
        guard challenge.transactionUUID == fields[2], challenge.expiresAt == expiry,
              challenge.generation == context.siteRootGeneration,
              challenge.generation == context.issuerGeneration,
              context.siteRootApprovalPublicKey != challenge.rootPublicKey,
              context.siteRootApprovalPublicKey != challenge.issuerPublicKey,
              !fields[5].allSatisfy({ $0 == 0 }), !fields[6].allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.qrPayloadUnsupported }
        canonical = fileBytes; canonicalChallenge = fields[0]
        presentationDigest = Data(SHA256.hash(data: fileBytes)); contextDigest = fields[4]
        challengeDigest = fields[1]; siteUUID = challenge.siteUUID
        transactionUUID = challenge.transactionUUID; generation = challenge.generation
        rootPublicKey = challenge.rootPublicKey; issuerPublicKey = challenge.issuerPublicKey
        siteTrustDomain = context.siteTrustDomain
        authorityGeneration = context.authorityGeneration
        custodyGeneration = context.custodyGeneration
        revocationGeneration = context.revocationGeneration
        installationID = context.installationID; deviceID = context.deviceID
        appAttestKeyID = context.appAttestKeyID
        appAttestApplicationID = context.appAttestApplicationID
        siteRootApprovalKeyID = context.siteRootApprovalKeyID
        siteRootApprovalPublicKey = context.siteRootApprovalPublicKey
        targetKind = context.targetKind; targetID = context.targetID; services = context.services
        replayReference = fields[5]; ceremonyChallenge = fields[6]
        preparedAt = prepared; expiresAt = expiry
    }

    func appAttestClientDataHash(detachedApproval: Data) throws -> Data {
        guard !detachedApproval.isEmpty, detachedApproval.count <= 4_096 else {
            throw PlatformFailure.appAttestInvalidInput
        }
        return Data(SHA256.hash(data:
            SiteX509FirstProvisionOfflineProfileV2.transcriptMagic
                + presentationDigest + contextDigest + challengeDigest + transactionUUID
                + replayReference + ceremonyChallenge
                + Data(SHA256.hash(data: detachedApproval))
        ))
    }

    private struct Challenge {
        let siteUUID: Data; let transactionUUID: Data; let generation: UInt64
        let rootPublicKey: Data; let issuerPublicKey: Data; let expiresAt: UInt64
        init(_ bytes: Data, now: UInt64) throws {
            let f = try TLV.parse(bytes, magic: SiteX509FirstProvisionOfflineProfileV2.challengeMagic, tags: 1 ... 14)
            let rootKey = try? P256.Signing.PublicKey(compressedRepresentation: f[5])
            let issuerKey = try? P256.Signing.PublicKey(compressedRepresentation: f[9])
            guard TLV.text(f[0]) == "site-x509-first-provision", f[1].count == 16,
                  f[2].count == 16, let generation = SiteX509FirstProvisionOfflinePresentationV2.u64(f[3]), generation > 0,
                  TLV.text(f[4]) == "site-x509-root-first-provision", f[5].count == 33,
                  [6, 7, 10, 11].allSatisfy({ f[$0].count == 32 && !f[$0].allSatisfy({ $0 == 0 }) }),
                  TLV.text(f[8]) == "site-x509-issuer-first-provision", f[9].count == 33,
                  let expiry = SiteX509FirstProvisionOfflinePresentationV2.u64(f[12]), now < expiry,
                  f[13].count == 32, !f[13].allSatisfy({ $0 == 0 }),
                  rootKey != nil, issuerKey != nil, f[5] != f[9]
            else { throw PlatformFailure.qrPayloadUnsupported }
            siteUUID = f[1]; transactionUUID = f[2]; self.generation = generation
            rootPublicKey = f[5]; issuerPublicKey = f[9]; expiresAt = expiry
        }
    }

    private struct Context {
        let siteTrustDomain: String; let authorityGeneration: String; let custodyGeneration: String
        let revocationGeneration: UInt64; let siteRootGeneration: UInt64; let issuerGeneration: UInt64
        let installationID: String; let deviceID: String; let appAttestKeyID: String
        let appAttestApplicationID: String; let targetKind: String; let targetID: Data
        let siteRootApprovalKeyID: Data; let siteRootApprovalPublicKey: Data
        let services: [SiteX509FirstProvisionOfflineServiceV2]
        init(_ bytes: Data) throws {
            let f = try TLV.parse(bytes, magic: SiteX509FirstProvisionOfflineProfileV2.contextMagic, tags: 1 ... 17)
            guard TLV.text(f[0]) == SiteX509FirstProvisionOfflineProfileV2.purpose,
                  TLV.text(f[1]) == SiteX509FirstProvisionOfflineProfileV2.audience,
                  let domain = TLV.identifier(f[2]), let authority = TLV.identifier(f[3]),
                  let custody = TLV.identifier(f[4]), let revocation = SiteX509FirstProvisionOfflinePresentationV2.u64(f[5]), revocation > 0,
                  let root = SiteX509FirstProvisionOfflinePresentationV2.u64(f[6]), root > 0,
                  let issuer = SiteX509FirstProvisionOfflinePresentationV2.u64(f[7]), issuer > 0,
                  let installation = TLV.identifier(f[8]), let device = TLV.identifier(f[9]),
                  let key = TLV.identifier(f[10]), let app = TLV.identifier(f[11]),
                  app == AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
                  let targetKind = TLV.identifier(f[12]), f[12].count <= 128,
                  f[13].count == 32, !f[13].allSatisfy({ $0 == 0 }),
                  f[15].count == 32, !f[15].allSatisfy({ $0 == 0 }),
                  f[16].count == 33,
                  let approvalKey = try? P256.Signing.PublicKey(
                      compressedRepresentation: f[16]
                  ),
                  approvalKey.compressedRepresentation == f[16],
                  Data(SHA256.hash(data: f[16])) == f[15]
            else { throw PlatformFailure.qrPayloadUnsupported }
            siteTrustDomain = domain; authorityGeneration = authority; custodyGeneration = custody
            revocationGeneration = revocation; siteRootGeneration = root; issuerGeneration = issuer
            installationID = installation; deviceID = device; appAttestKeyID = key
            appAttestApplicationID = app; self.targetKind = targetKind; targetID = f[13]
            services = try ServiceProjection(f[14]).values
            siteRootApprovalKeyID = f[15]; siteRootApprovalPublicKey = f[16]
        }
    }

    private struct ServiceProjection {
        let values: [SiteX509FirstProvisionOfflineServiceV2]
        init(_ bytes: Data) throws {
            guard bytes.count >= 2 else { throw PlatformFailure.qrPayloadUnsupported }
            var cursor = 2; let count = Int(bytes[0]) << 8 | Int(bytes[1])
            guard (1 ... 16).contains(count) else { throw PlatformFailure.qrPayloadUnsupported }
            var result: [SiteX509FirstProvisionOfflineServiceV2] = []
            var priorService = ""
            for _ in 0 ..< count {
                guard cursor < bytes.count else { throw PlatformFailure.qrPayloadUnsupported }
                let idLength = Int(bytes[cursor]); cursor += 1
                guard idLength > 0, cursor + idLength < bytes.count,
                      let id = TLV.identifier(Data(bytes[cursor ..< cursor + idLength])), id > priorService
                else { throw PlatformFailure.qrPayloadUnsupported }
                cursor += idLength; priorService = id
                let ipCount = Int(bytes[cursor]); cursor += 1
                guard (1 ... 16).contains(ipCount) else { throw PlatformFailure.qrPayloadUnsupported }
                var ips: [String] = []; var prior = Data()
                for _ in 0 ..< ipCount {
                    guard cursor < bytes.count else { throw PlatformFailure.qrPayloadUnsupported }
                    let family = bytes[cursor]; let length = family == 4 ? 4 : family == 6 ? 16 : 0
                    guard length > 0, cursor + 1 + length <= bytes.count else { throw PlatformFailure.qrPayloadUnsupported }
                    let canonical = Data(bytes[cursor ..< cursor + 1 + length])
                    guard prior.isEmpty || prior.lexicographicallyPrecedes(canonical),
                          let display = Self.privateIP(canonical)
                    else { throw PlatformFailure.qrPayloadUnsupported }
                    prior = canonical; ips.append(display); cursor += 1 + length
                }
                result.append(.init(serviceID: id, privateIPs: ips))
            }
            guard cursor == bytes.count else { throw PlatformFailure.qrPayloadUnsupported }
            values = result
        }
        private static func privateIP(_ value: Data) -> String? {
            let bytes = [UInt8](value.dropFirst())
            if value.first == 4, bytes.count == 4,
               bytes[0] == 10 || (bytes[0] == 172 && (16 ... 31).contains(bytes[1])) || (bytes[0] == 192 && bytes[1] == 168) {
                return bytes.map(String.init).joined(separator: ".")
            }
            guard value.first == 6, bytes.count == 16, bytes[0] & 0xfe == 0xfc else { return nil }
            var address = in6_addr()
            withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: bytes) }
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &address, &output, socklen_t(output.count)) != nil,
                  let end = output.firstIndex(of: 0)
            else { return nil }
            return String(decoding: output[..<end].map(UInt8.init(bitPattern:)), as: UTF8.self)
        }
    }

    private enum TLV {
        static func parse(_ bytes: Data, magic: Data, tags: ClosedRange<Int>) throws -> [Data] {
            guard bytes.starts(with: magic) else { throw PlatformFailure.qrPayloadUnsupported }
            var cursor = magic.count; var result: [Data] = []
            for tag in tags {
                guard cursor + 3 <= bytes.count, bytes[cursor] == UInt8(tag) else { throw PlatformFailure.qrPayloadUnsupported }
                let length = Int(bytes[cursor + 1]) << 8 | Int(bytes[cursor + 2]); cursor += 3
                guard length > 0, cursor + length <= bytes.count else { throw PlatformFailure.qrPayloadUnsupported }
                result.append(Data(bytes[cursor ..< cursor + length])); cursor += length
            }
            guard cursor == bytes.count else { throw PlatformFailure.qrPayloadUnsupported }
            return result
        }
        static func text(_ bytes: Data) -> String? { String(data: bytes, encoding: .utf8) }
        static func identifier(_ bytes: Data) -> String? {
            guard !bytes.isEmpty, bytes.count <= 128, bytes.allSatisfy({ (0x21 ... 0x7e).contains($0) }) else { return nil }
            return text(bytes)
        }
    }

    private static func u64(_ bytes: Data) -> UInt64? {
        guard bytes.count == 8 else { return nil }
        return bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }
    private static func decodeQR(_ text: String, prefix: String) -> Data? {
        guard text.utf8.count <= SiteX509FirstProvisionOfflineProfileV2.maximumQRBytes,
              text.hasPrefix(prefix) else { return nil }
        let encoded = String(text.dropFirst(prefix.count))
        guard !encoded.isEmpty, !encoded.contains("="), encoded.utf8.allSatisfy({ $0.isBase64URL }) else { return nil }
        let standard = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        guard let bytes = Data(base64Encoded: standard), base64URL(bytes) == encoded else { return nil }
        return bytes
    }
    static func base64URL(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

/// Face-ID-gated producer for the existing Site-root approval and registered App Attest assertion.
protocol SiteX509FirstProvisionOfflineProducing: Sendable {
    func produce(
        _ value: SiteX509FirstProvisionOfflinePresentationV2,
        nowUnixSeconds: UInt64
    ) async throws -> Data
}

final class SecureEnclaveSiteX509FirstProvisionOfflineProducerV2:
    SiteX509FirstProvisionOfflineProducing, @unchecked Sendable {
    private let appAttest: AppleAppAttestClient
    init(appAttest: AppleAppAttestClient = AppleAppAttestClient()) { self.appAttest = appAttest }
    func produce(_ value: SiteX509FirstProvisionOfflinePresentationV2, nowUnixSeconds: UInt64) async throws -> Data {
        guard value.preparedAt <= nowUnixSeconds, nowUnixSeconds < value.expiresAt else { throw PlatformFailure.qrPayloadUnsupported }
        let ceremony = try await FaceIDCeremonyContext.authenticate(reason: "Approve first Site HTTPS for the displayed services and private addresses")
        let signer = try SecureEnclaveSigner(namespace: "site-root-delegation-v1", authenticationReason: "Approve this exact first Site X.509 challenge")
        do {
            guard try signer.hasExistingKey() else {
                throw PlatformFailure.siteRootAuthorityKeyMissing
            }
        } catch let failure as PlatformFailure {
            if failure == .keyInvalidated {
                throw PlatformFailure.siteRootAuthorityKeyInvalidated
            }
            throw failure
        }
        let publicKey: Data
        do {
            publicKey = try signer.publicKey(using: ceremony).compressedSEC1
        } catch let failure as PlatformFailure {
            if failure == .keyInvalidated {
                throw PlatformFailure.siteRootAuthorityKeyInvalidated
            }
            if failure == .keyNotFound {
                throw PlatformFailure.siteRootAuthorityKeyMissing
            }
            throw failure
        }
        if let failure = Self.siteRootAuthorityKeyValidationFailure(
            expectedPublicKey: value.siteRootApprovalPublicKey,
            expectedKeyID: value.siteRootApprovalKeyID,
            actualPublicKey: publicKey
        ) {
            throw failure
        }
        let protected = try DetachedES256Cose.protectedHeaders(kid: value.siteRootApprovalKeyID, contentType: SiteX509FirstProvisionOfflineProfileV2.contentType)
        let structure = try DetachedES256Cose.signatureStructure(protected: protected, payload: value.canonicalChallenge)
        let signature: Data
        do {
            signature = try signer.sign(message: structure, using: ceremony)
        } catch let failure as PlatformFailure {
            if let mapped = Self.siteRootAuthorityKeyFailure(for: failure) {
                throw mapped
            }
            throw failure
        }
        let approval = try DetachedES256Cose.envelope(protected: protected, signature: signature)
        let clientHash = try value.appAttestClientDataHash(detachedApproval: approval)
        let assertion = try await appAttest.prepareSiteX509FirstProvisionOfflineAssertion(expectedKeyID: value.appAttestKeyID, clientDataHash: clientHash)
        return try Self.response(value, approval: approval, assertion: assertion)
    }
    static func response(_ value: SiteX509FirstProvisionOfflinePresentationV2, approval: Data, assertion: Data) throws -> Data {
        let clientHash = try value.appAttestClientDataHash(detachedApproval: approval)
        let fields: [Data] = [value.presentationDigest, value.contextDigest, value.challengeDigest,
                              value.transactionUUID, value.replayReference, value.ceremonyChallenge,
                              Data(SHA256.hash(data: approval)), approval, assertion, clientHash]
        var result = SiteX509FirstProvisionOfflineProfileV2.responseMagic
        for (index, field) in fields.enumerated() {
            guard !field.isEmpty, field.count <= Int(UInt16.max) else { throw PlatformFailure.appAttestInvalidInput }
            result.append(UInt8(index + 1)); result.append(UInt8(field.count >> 8)); result.append(UInt8(field.count & 0xff)); result.append(field)
        }
        return result
    }

    /// Classify the local-vs-presentation authority binding without touching
    /// Secure Enclave state. Keeping this decision pure makes the dangerous
    /// mismatch path testable on the simulator and guarantees that no proof
    /// construction is reached for a missing or substituted key.
    static func siteRootAuthorityKeyValidationFailure(
        expectedPublicKey: Data,
        expectedKeyID: Data,
        actualPublicKey: Data?
    ) -> PlatformFailure? {
        guard let actualPublicKey else { return .siteRootAuthorityKeyMissing }
        guard actualPublicKey == expectedPublicKey,
              expectedKeyID == Data(SHA256.hash(data: actualPublicKey))
        else { return .siteRootAuthorityKeyMismatch }
        return nil
    }

    /// Map only the two Security lookup failures that can arise while using
    /// the enrolled Site-root key. All unrelated signing failures retain their
    /// original meaning and are never relabelled as an authority mismatch.
    static func siteRootAuthorityKeyFailure(for failure: PlatformFailure) -> PlatformFailure? {
        switch failure {
        case .keyNotFound: return .siteRootAuthorityKeyMissing
        case .keyInvalidated: return .siteRootAuthorityKeyInvalidated
        default: return nil
        }
    }
    static func responseQRText(_ canonical: Data) throws -> String {
        let text = SiteX509FirstProvisionOfflineProfileV2.responseQRPrefix
            + SiteX509FirstProvisionOfflinePresentationV2.base64URL(canonical)
        guard text.utf8.count <= SiteX509FirstProvisionOfflineProfileV2.maximumQRBytes else { throw PlatformFailure.qrPayloadTooLarge }
        return text
    }
}

private extension UInt8 {
    var isBase64URL: Bool {
        (48 ... 57).contains(self) || (65 ... 90).contains(self)
            || (97 ... 122).contains(self) || self == 45 || self == 95
    }
}
