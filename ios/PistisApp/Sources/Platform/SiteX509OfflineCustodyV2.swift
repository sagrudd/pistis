import CryptoKit
import Foundation

/// An immutable presentation authenticated through a separately entered host digest.
/// The ACK registration supplies the enrolled Site-root hash, never its ACK key.
struct SiteX509OfflineCustodyV2: Sendable {
    static let maximumFileBytes = 24_576
    let presentation: SiteX509AttendedUnlockPresentationV2
    let registration: SiteRootConvergenceAckRecordV2

    init(
        data: Data,
        expectedRole: SiteX509AttendedUnlockRoleV2,
        independentDigestHex: String,
        registration: SiteRootConvergenceAckRecordV2,
        nowUnixSeconds: UInt64
    ) throws {
        do {
            _ = try StrictJSONObject(data: data, maximumBytes: Self.maximumFileBytes)
            let expected = try Self.digestBytes(independentDigestHex)
            let value = try SiteX509AttendedUnlockPresentationV2(
                data: data, expectedRole: expectedRole, nowUnixSeconds: nowUnixSeconds
            )
            guard Data(SHA256.hash(data: value.canonicalChallenge)) == expected,
                  registration.generation > 0,
                  let uuid = UUID(uuidString: registration.siteUUID),
                  uuid.uuidString.lowercased() == registration.siteUUID,
                  uuid.uuidString != "00000000-0000-0000-0000-000000000000",
                  value.siteTrustDomain == "site-" + registration.siteUUID,
                  value.deviceKeyID == "site-root-" + (try Self.targetBytes(registration)).hexadecimal
            else { throw PlatformFailure.custodyRewrapUnavailable }
            presentation = value
            self.registration = registration
        } catch {
            throw PlatformFailure.custodyRewrapUnavailable
        }
    }

    /// Revalidate protected registration and expiry around authentication and production.
    func requireCurrent(
        registration: SiteRootConvergenceAckRecordV2,
        nowUnixSeconds: UInt64
    ) throws {
        guard registration == self.registration,
              presentation.expiresAtUnixSeconds > nowUnixSeconds
        else { throw PlatformFailure.custodyRewrapUnavailable }
    }

    /// Check the actual existing Site-root key before invoking the unchanged producer.
    func requireExistingRootPublicKey(_ compressedSEC1: Data) throws {
        guard Data(SHA256.hash(data: compressedSEC1)) == (try Self.targetBytes(registration))
        else { throw PlatformFailure.custodyRewrapUnavailable }
    }

    private static func targetBytes(_ record: SiteRootConvergenceAckRecordV2) throws -> Data {
        let text = record.targetIDB64URL
        guard text.utf8.count == 43,
              text.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0)
                      || (97...122).contains($0) || $0 == 45 || $0 == 95
              }),
              let bytes = Data(base64Encoded: text.replacingOccurrences(of: "-", with: "+")
                  .replacingOccurrences(of: "_", with: "/") + "="),
              bytes.count == 32, bytes.base64URLEncoded == text
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return bytes
    }

    private static func digestBytes(_ text: String) throws -> Data {
        let chars = Array(text.utf8)
        guard chars.count == 64 else { throw PlatformFailure.custodyRewrapUnavailable }
        func nibble(_ byte: UInt8) throws -> UInt8 {
            switch byte {
            case 48...57: byte - 48
            case 65...70: byte - 65 + 10
            case 97...102: byte - 97 + 10
            default: throw PlatformFailure.custodyRewrapUnavailable
            }
        }
        var bytes = Data()
        for index in stride(from: 0, to: chars.count, by: 2) {
            bytes.append(try nibble(chars[index]) * 16 + nibble(chars[index + 1]))
        }
        return bytes
    }

    /// Testable sequencing only: injected authentication never represents physical Face ID.
    @MainActor
    static func perform<Authentication, Response>(
        requireCurrent: () throws -> Void,
        requireExistingKey: () throws -> Void,
        authenticate: () async throws -> Authentication,
        produce: (Authentication) throws -> Response
    ) async throws -> Response {
        try Task.checkCancellation()
        try requireCurrent()
        try requireExistingKey()
        let authentication = try await authenticate()
        try Task.checkCancellation()
        try requireCurrent()
        try requireExistingKey()
        let response = try produce(authentication)
        try Task.checkCancellation()
        try requireCurrent()
        return response
    }

    /// Produce only the existing V2 submission; this adapter has no transport or key creation.
    @MainActor
    func response(requireCurrentOperation: () throws -> Void) async throws -> Data {
        let store = SiteRootConvergenceAckStoreV2()
        let signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Create this exact Site X.509 custody response"
        )
        return try await Self.perform(
            requireCurrent: {
                try requireCurrentOperation()
                try self.requireCurrent(
                    registration: store.current(),
                    nowUnixSeconds: UInt64(Date().timeIntervalSince1970)
                )
            },
            requireExistingKey: {
                guard try signer.hasExistingKey() else { throw PlatformFailure.keyNotFound }
            },
            authenticate: {
                try await FaceIDCeremonyContext.authenticate(
                    reason: "Create the Site X.509 \(presentation.role.rawValue) custody response"
                )
            },
            produce: { ceremony in
                try self.requireExistingRootPublicKey(signer.publicKey(using: ceremony).compressedSEC1)
                try requireCurrentOperation()
                try self.requireCurrent(
                    registration: store.current(),
                    nowUnixSeconds: UInt64(Date().timeIntervalSince1970)
                )
                let response = try SecureEnclaveSiteX509AttendedUnlockProducerV2(
                    role: presentation.role
                ).produce(presentation, using: ceremony)
                let bytes = try JSONEncoder().encode(response)
                guard bytes.count <= Self.maximumFileBytes else {
                    throw PlatformFailure.custodyRewrapUnavailable
                }
                return bytes
            }
        )
    }
}

private extension Data {
    var hexadecimal: String { map { String(format: "%02x", $0) }.joined() }
    var base64URLEncoded: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
