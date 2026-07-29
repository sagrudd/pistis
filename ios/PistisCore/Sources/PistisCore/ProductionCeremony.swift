import Foundation

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#else
#error("PistisCore requires CryptoKit or Apple Swift Crypto")
#endif

public enum ProductionCeremonyError: Error, Equatable, Sendable {
    case malformedFrame
    case oversizedFrame
    case invalidChecksum
    case wrongTransferKind
    case invalidChallenge
    case unknownInstallation
    case inactiveInstallation
    case keyMismatch
    case invalidSignature
    case wrongAudience
    case wrongIdentity
    case expired
    case invalidEndpoint
}

public enum AuthenticationDecision: String, Sendable {
    case approved
    case denied
}

/// Host-authorised installation material installed by an authenticated enrolment.
///
/// This type is deliberately not constructible from a QR challenge. A repository
/// may persist it only after independently validating the authority receipt.
public struct InstallationTrustRecord: Codable, Equatable, Sendable {
    public let installationID: Data
    public let displayName: String
    public let audience: String
    public let userID: Data
    public let externalIdentityID: Data
    public let fingerprint: Data
    public let installationKeyID: Data
    public let installationPublicKey: Data
    public let authorityKeyID: Data
    public let authorityReceipt: Data
    public let policyGeneration: UInt64
    public let revocationGeneration: UInt64
    public let expiresAt: Date
    public let active: Bool

    public init(
        installationID: Data,
        displayName: String,
        audience: String,
        userID: Data,
        externalIdentityID: Data,
        fingerprint: Data,
        installationKeyID: Data,
        installationPublicKey: Data,
        authorityKeyID: Data,
        authorityReceipt: Data,
        policyGeneration: UInt64,
        revocationGeneration: UInt64,
        expiresAt: Date,
        active: Bool
    ) throws {
        guard installationID.count == 16,
              fingerprint.count == 32,
              userID.count == 16,
              externalIdentityID.count == 16,
              installationKeyID.count == 32,
              installationPublicKey.count == 33,
              authorityKeyID.count == 32,
              !authorityReceipt.isEmpty,
              Self.bounded(displayName, maximum: 128),
              Self.bounded(audience, maximum: 128)
        else {
            throw ProductionCeremonyError.inactiveInstallation
        }
        self.installationID = installationID
        self.displayName = displayName
        self.audience = audience
        self.userID = userID
        self.externalIdentityID = externalIdentityID
        self.fingerprint = fingerprint
        self.installationKeyID = installationKeyID
        self.installationPublicKey = installationPublicKey
        self.authorityKeyID = authorityKeyID
        self.authorityReceipt = authorityReceipt
        self.policyGeneration = policyGeneration
        self.revocationGeneration = revocationGeneration
        self.expiresAt = expiresAt
        self.active = active
    }

    private static func bounded(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
    }
}

public protocol InstallationTrustReading: Sendable {
    func record(installationID: Data) async throws -> InstallationTrustRecord?
}

public struct VerifiedAuthenticationChallenge: Equatable, Sendable {
    public let exactPayload: Data
    public let issuedAtMilliseconds: UInt64
    public let expiresAtMilliseconds: UInt64
    public let installationID: Data
    public let installationKeyID: Data
    public let challengeID: Data
    public let nonce: Data
    public let userID: Data
    public let externalIdentityID: Data
    public let audience: String
    public let installationName: String
    public let localUsername: String
    public let displayContextDigest: Data
    public let installationFingerprint: Data
    public let endpointHints: [URL]
}

public struct DeviceResponseContext: Codable, Equatable, Sendable {
    public let deviceID: Data
    public let deviceKeyID: Data
    public let userID: Data
    public let externalIdentityID: Data

    public init(deviceID: Data, deviceKeyID: Data, userID: Data, externalIdentityID: Data) throws {
        guard deviceID.count == 16, deviceKeyID.count == 32,
              userID.count == 16, externalIdentityID.count == 16
        else { throw ProductionCeremonyError.invalidChallenge }
        self.deviceID = deviceID
        self.deviceKeyID = deviceKeyID
        self.userID = userID
        self.externalIdentityID = externalIdentityID
    }
}

public enum ProductionQRV2 {
    public static let maximumTextBytes = 2_331

    /// Returns exact COSE bytes from an ADR 0021 challenge frame.
    public static func decodeChallenge(_ text: String) throws -> Data {
        guard text.utf8.count <= maximumTextBytes else {
            throw ProductionCeremonyError.oversizedFrame
        }
        guard text.unicodeScalars.allSatisfy(\.isASCII),
              text.hasPrefix("PISTIS1:"),
              let separator = text.lastIndex(of: ".")
        else { throw ProductionCeremonyError.malformedFrame }
        let bodyStart = text.index(text.startIndex, offsetBy: 8)
        let body = String(text[bodyStart ..< separator])
        let checksum = String(text[text.index(after: separator)...])
        guard !body.isEmpty, checksum.count == 16,
              body.utf8.allSatisfy({
                  (48 ... 57).contains($0) || (65 ... 90).contains($0)
                      || (97 ... 122).contains($0) || $0 == 45 || $0 == 95
              }),
              checksum.utf8.allSatisfy({
                  (48 ... 57).contains($0) || (97 ... 102).contains($0)
              })
        else { throw ProductionCeremonyError.malformedFrame }
        let expected = SHA256.hash(data: Data(body.utf8)).prefix(8)
            .map { String(format: "%02x", $0) }.joined()
        guard checksum == expected else { throw ProductionCeremonyError.invalidChecksum }
        var padded = body.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        guard let bytes = Data(base64Encoded: padded) else {
            throw ProductionCeremonyError.malformedFrame
        }
        var reader = CeremonyCBORReader(bytes)
        try reader.requireMap(count: 3)
        try reader.requireUnsigned(0)
        try reader.requireUnsigned(2)
        try reader.requireUnsigned(1)
        try reader.requireUnsigned(1)
        try reader.requireUnsigned(2)
        let cose = try reader.byteString(maximum: 2_048)
        guard reader.isAtEnd else { throw ProductionCeremonyError.malformedFrame }
        _ = try CoseSign1.decode(cose)
        return cose
    }
}

public enum ProductionChallengeVerifier {
    public static func verify(
        qrText: String,
        trustRepository: any InstallationTrustReading,
        expectedAudience: String,
        expectedExternalIdentityID: Data,
        now: Date
    ) async throws -> VerifiedAuthenticationChallenge {
        let cose = try CoseSign1.decode(ProductionQRV2.decodeChallenge(qrText))
        let challenge = try decodeChallenge(cose.payload)
        guard let trust = try await trustRepository.record(
            installationID: challenge.installationID
        ) else { throw ProductionCeremonyError.unknownInstallation }
        guard trust.active, now < trust.expiresAt else {
            throw ProductionCeremonyError.inactiveInstallation
        }
        guard trust.installationID == challenge.installationID,
              trust.installationKeyID == challenge.installationKeyID,
              trust.installationKeyID == cose.keyID,
              trust.fingerprint == challenge.installationFingerprint
        else { throw ProductionCeremonyError.keyMismatch }
        guard trust.audience == expectedAudience, challenge.audience == expectedAudience else {
            throw ProductionCeremonyError.wrongAudience
        }
        guard trust.userID == challenge.userID,
              trust.externalIdentityID == challenge.externalIdentityID,
              challenge.externalIdentityID == expectedExternalIdentityID
        else {
            throw ProductionCeremonyError.wrongIdentity
        }
        guard trust.displayName == challenge.installationName else {
            throw ProductionCeremonyError.keyMismatch
        }
        let nowMilliseconds = UInt64(now.timeIntervalSince1970 * 1_000)
        guard nowMilliseconds >= challenge.issuedAtMilliseconds,
              nowMilliseconds < challenge.expiresAtMilliseconds
        else { throw ProductionCeremonyError.expired }
        let publicKey: P256.Signing.PublicKey
        do {
            publicKey = try P256.Signing.PublicKey(
                compressedRepresentation: trust.installationPublicKey
            )
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: cose.signature)
            guard publicKey.isValidSignature(signature, for: cose.signatureStructure()) else {
                throw ProductionCeremonyError.invalidSignature
            }
        } catch let error as ProductionCeremonyError {
            throw error
        } catch {
            throw ProductionCeremonyError.invalidSignature
        }
        return challenge
    }

    private static func decodeChallenge(_ payload: Data) throws
        -> VerifiedAuthenticationChallenge
    {
        var reader = CeremonyCBORReader(payload)
        try reader.requireMap(count: 17)
        try reader.requireUnsigned(0); try reader.requireUnsigned(1)
        try reader.requireUnsigned(1)
        try reader.requireText("pistis.authentication-challenge.v1")
        try reader.requireUnsigned(2); let issued = try reader.unsigned()
        try reader.requireUnsigned(3); let expires = try reader.unsigned()
        try reader.requireUnsigned(4); let installationID = try reader.bytes(count: 16)
        try reader.requireUnsigned(5); let installationKeyID = try reader.bytes(count: 32)
        try reader.requireUnsigned(6); let challengeID = try reader.bytes(count: 16)
        try reader.requireUnsigned(7); let nonce = try reader.bytes(count: 32)
        try reader.requireUnsigned(8); let userID = try reader.bytes(count: 16)
        try reader.requireUnsigned(9); let externalIdentityID = try reader.bytes(count: 16)
        try reader.requireUnsigned(10); try reader.requireText("authenticate-session")
        try reader.requireUnsigned(11); let audience = try reader.text(maximum: 128)
        try reader.requireUnsigned(12); let installationName = try reader.text(maximum: 128)
        try reader.requireUnsigned(13); let localUsername = try reader.text(maximum: 128)
        try reader.requireUnsigned(14); let displayDigest = try reader.bytes(count: 32)
        try reader.requireUnsigned(15); let fingerprint = try reader.bytes(count: 32)
        try reader.requireUnsigned(16)
        let endpointStrings = try reader.textArray(maximumCount: 2, maximumText: 256)
        guard reader.isAtEnd, issued < expires,
              Set(endpointStrings).count == endpointStrings.count
        else { throw ProductionCeremonyError.invalidChallenge }
        let endpoints = try endpointStrings.map { value -> URL in
            guard let url = URL(string: value), url.scheme == "https",
                  url.user == nil, url.password == nil, url.host != nil,
                  url.fragment == nil
            else { throw ProductionCeremonyError.invalidEndpoint }
            return url
        }
        return VerifiedAuthenticationChallenge(
            exactPayload: payload,
            issuedAtMilliseconds: issued,
            expiresAtMilliseconds: expires,
            installationID: installationID,
            installationKeyID: installationKeyID,
            challengeID: challengeID,
            nonce: nonce,
            userID: userID,
            externalIdentityID: externalIdentityID,
            audience: audience,
            installationName: installationName,
            localUsername: localUsername,
            displayContextDigest: displayDigest,
            installationFingerprint: fingerprint,
            endpointHints: endpoints
        )
    }
}

public enum AuthenticationResponseEncoder {
    public static func payload(
        challenge: VerifiedAuthenticationChallenge,
        context: DeviceResponseContext,
        decision: AuthenticationDecision,
        issuedAtMilliseconds: UInt64,
        userVerifiedAtMilliseconds: UInt64
    ) throws -> Data {
        guard issuedAtMilliseconds <= userVerifiedAtMilliseconds,
              context.userID == challenge.userID,
              context.externalIdentityID == challenge.externalIdentityID
        else { throw ProductionCeremonyError.wrongIdentity }
        var output = Data([0xad])
        output.append(CeremonyCBOR.unsigned(0)); output.append(CeremonyCBOR.unsigned(1))
        output.append(CeremonyCBOR.unsigned(1))
        output.append(CeremonyCBOR.text("pistis.authentication-response.v1"))
        output.append(CeremonyCBOR.unsigned(2)); output.append(CeremonyCBOR.unsigned(issuedAtMilliseconds))
        output.append(CeremonyCBOR.unsigned(3)); output.append(CeremonyCBOR.unsigned(userVerifiedAtMilliseconds))
        output.append(CeremonyCBOR.unsigned(4)); output.append(CeremonyCBOR.bytes(challenge.installationID))
        output.append(CeremonyCBOR.unsigned(5)); output.append(CeremonyCBOR.bytes(context.deviceKeyID))
        output.append(CeremonyCBOR.unsigned(6)); output.append(CeremonyCBOR.bytes(challenge.challengeID))
        output.append(CeremonyCBOR.unsigned(7)); output.append(CeremonyCBOR.bytes(challenge.nonce))
        output.append(CeremonyCBOR.unsigned(8))
        output.append(CeremonyCBOR.bytes(Data(SHA256.hash(data: challenge.exactPayload))))
        output.append(CeremonyCBOR.unsigned(9)); output.append(CeremonyCBOR.bytes(challenge.userID))
        output.append(CeremonyCBOR.unsigned(10)); output.append(CeremonyCBOR.bytes(context.deviceID))
        output.append(CeremonyCBOR.unsigned(11)); output.append(CeremonyCBOR.bytes(challenge.externalIdentityID))
        output.append(CeremonyCBOR.unsigned(12)); output.append(CeremonyCBOR.text(decision.rawValue))
        return output
    }
}

private enum CeremonyCBOR {
    static func unsigned(_ value: UInt64) -> Data { argument(major: 0, value: value) }
    static func bytes(_ value: Data) -> Data { argument(major: 2, value: UInt64(value.count)) + value }
    static func text(_ value: String) -> Data {
        let bytes = Data(value.utf8)
        return argument(major: 3, value: UInt64(bytes.count)) + bytes
    }
    private static func argument(major: UInt8, value: UInt64) -> Data {
        if value < 24 { return Data([major << 5 | UInt8(value)]) }
        if value <= UInt8.max { return Data([major << 5 | 24, UInt8(value)]) }
        if value <= UInt16.max {
            let number = UInt16(value).bigEndian
            return Data([major << 5 | 25]) + withUnsafeBytes(of: number) { Data($0) }
        }
        if value <= UInt32.max {
            let number = UInt32(value).bigEndian
            return Data([major << 5 | 26]) + withUnsafeBytes(of: number) { Data($0) }
        }
        let number = value.bigEndian
        return Data([major << 5 | 27]) + withUnsafeBytes(of: number) { Data($0) }
    }
}

private struct CeremonyCBORReader {
    private let data: Data
    private var offset = 0
    init(_ data: Data) { self.data = data }
    var isAtEnd: Bool { offset == data.count }

    mutating func requireMap(count: Int) throws {
        let (major, value) = try header()
        guard major == 5, value == count else { throw ProductionCeremonyError.invalidChallenge }
    }
    mutating func requireUnsigned(_ expected: UInt64) throws {
        guard try unsigned() == expected else { throw ProductionCeremonyError.invalidChallenge }
    }
    mutating func unsigned() throws -> UInt64 {
        let (major, value) = try header()
        guard major == 0 else { throw ProductionCeremonyError.invalidChallenge }
        return UInt64(value)
    }
    mutating func requireText(_ expected: String) throws {
        guard try text(maximum: expected.utf8.count) == expected else {
            throw ProductionCeremonyError.invalidChallenge
        }
    }
    mutating func bytes(count: Int) throws -> Data {
        let value = try byteString(maximum: count)
        guard value.count == count else { throw ProductionCeremonyError.invalidChallenge }
        return value
    }
    mutating func byteString(maximum: Int) throws -> Data {
        let (major, count) = try header()
        guard major == 2, count <= maximum, count <= data.count - offset else {
            throw ProductionCeremonyError.invalidChallenge
        }
        defer { offset += count }
        return data[offset ..< offset + count]
    }
    mutating func text(maximum: Int) throws -> String {
        let (major, count) = try header()
        guard major == 3, count > 0, count <= maximum, count <= data.count - offset,
              let value = String(data: data[offset ..< offset + count], encoding: .utf8),
              value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw ProductionCeremonyError.invalidChallenge }
        offset += count
        return value
    }
    mutating func textArray(maximumCount: Int, maximumText: Int) throws -> [String] {
        let (major, count) = try header()
        guard major == 4, count <= maximumCount else {
            throw ProductionCeremonyError.invalidChallenge
        }
        return try (0 ..< count).map { _ in try text(maximum: maximumText) }
    }
    private mutating func header() throws -> (UInt8, Int) {
        let initial = try byte()
        let major = initial >> 5
        let additional = initial & 31
        let value: UInt64
        switch additional {
        case 0 ... 23: value = UInt64(additional)
        case 24:
            value = UInt64(try byte())
            guard value >= 24 else { throw ProductionCeremonyError.invalidChallenge }
        case 25: value = try integer(bytes: 2); guard value > UInt8.max else { throw ProductionCeremonyError.invalidChallenge }
        case 26: value = try integer(bytes: 4); guard value > UInt16.max else { throw ProductionCeremonyError.invalidChallenge }
        case 27: value = try integer(bytes: 8); guard value > UInt32.max else { throw ProductionCeremonyError.invalidChallenge }
        default: throw ProductionCeremonyError.invalidChallenge
        }
        guard value <= UInt64(Int.max) else { throw ProductionCeremonyError.invalidChallenge }
        return (major, Int(value))
    }
    private mutating func integer(bytes: Int) throws -> UInt64 {
        var result: UInt64 = 0
        for _ in 0 ..< bytes { result = result << 8 | UInt64(try byte()) }
        return result
    }
    private mutating func byte() throws -> UInt8 {
        guard offset < data.count else { throw ProductionCeremonyError.invalidChallenge }
        defer { offset += 1 }
        return data[offset]
    }
}
