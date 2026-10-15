import Foundation
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

/// A verified installation-signed action presentation, carried as a bounded
/// file. This value is attendance DATA, never a current Site or Root owner.
/// Verification uses an already retained installation pin, not TLS or a key
/// advertised by the file. Only the existing AUTHN key may answer it.
public struct IssuerJointRootAttendance: Sendable {
    public let controlOriginal: Data
    public let signedChallenge: Data
    public let challengePayload: Data
    public let transitionID: Data
    public let sessionID: Data
    public let siteID: Data
    public let sitePublicKey: Data
    public let devicePublicKey: Data
    public let deviceKeyID: Data
    public let expiresAtMilliseconds: UInt64
    public let issuedAtMilliseconds: UInt64
    public let rootGrantID: Data
    public let rootGrantExpiry: UInt64
    public let originalExecutionExpiry: UInt64
    public let statusGrantExpiry: UInt64
    public let nextPolicyGeneration: UInt64
    public let nextRevocationGeneration: UInt64
    private let challengeID: Data
    private let nonce: Data
    private let installationID: Data
    private let principalID: Data
    private let externalIdentityID: Data
    private let deviceID: Data

    public init(fileBytes: Data, trust: InstallationTrustRecord,
                responseContext: DeviceResponseContext, nowMilliseconds: UInt64) throws {
        let wrapper = try IssuerCBOR.decode(fileBytes, maximum: 24_576).array(4)
        guard wrapper[0] == .unsigned(1),
              try wrapper[1].bytes() == Data("pistis-issuer-joint-root-attendance.v1".utf8)
        else { throw IssuerPhoneError.binding }
        let control = try wrapper[2].bytes(), signed = try wrapper[3].bytes()
        guard control.count <= 8192, signed.count <= 16_384,
              trust.active, trust.authorisedProductAudiences.contains("propylaion"),
              Date(timeIntervalSince1970: Double(nowMilliseconds) / 1000) < trust.expiresAt,
              trust.userID == responseContext.userID,
              trust.externalIdentityID == responseContext.externalIdentityID
        else { throw IssuerPhoneError.expired }
        let cose = try CoseSign1.decode(signed)
        guard cose.keyID == trust.installationKeyID else { throw IssuerPhoneError.binding }
        let key = try P256.Signing.PublicKey(compressedRepresentation: trust.installationPublicKey)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: cose.signature)
        guard key.isValidSignature(signature, for: cose.signatureStructure()) else {
            throw IssuerPhoneError.binding
        }
        let joint = try IssuerCBOR.decode(control, maximum: 8192).array(13)
        guard joint[0] == .unsigned(1),
              try joint[1].bytes() == Data("ProvisionIssuerSiteStatusAndContinueRootV1".utf8)
        else { throw IssuerPhoneError.binding }
        let old = try IssuerCBOR.decode(try joint[8].bytes(), maximum: 4096).array(37)
        let next = try IssuerCBOR.decode(try joint[9].bytes(), maximum: 4096).array(37)
        try Self.requireSuccessor(old, next)
        for i in [2, 4, 5, 7, 8, 9, 14, 18, 22] { _ = try old[i].bytes(16, nonzero: true) }
        for i in [19, 20, 21, 35] { _ = try old[i].bytes(32, nonzero: true) }
        for i in [6, 25, 34, 36] {
            _ = try P256.Signing.PublicKey(compressedRepresentation: old[i].bytes(33))
        }
        for i in [3, 11, 12, 13, 15, 16, 17, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33] { _ = try old[i].uint(1...UInt64.max) }
        guard try old[26].uint() < old[27].uint(), try old[28].uint() < old[29].uint(),
              try old[31].uint() < old[32].uint(),
              try old[33].uint() == min(min(old[27].uint(), old[29].uint()), old[30].uint()) else { throw IssuerPhoneError.binding }

        let transition = try joint[2].bytes(16), session = try old[14].bytes(16)
        let installation = try old[4].bytes(16), principal = try old[7].bytes(16)
        let device = try old[9].bytes(16), publicKey = try old[36].bytes(33)
        let keyID = Data(SHA256.hash(data: Data("pistis:key-id:v1\0".utf8) + publicKey))
        guard !transition.allSatisfy({ $0 == 0 }), installation == trust.installationID,
              principal == responseContext.userID, device == responseContext.deviceID,
              keyID == responseContext.deviceKeyID,
              try old[10].bytes() == Data(Self.hex(keyID).utf8),
              try old[34].bytes(33) == trust.installationPublicKey,
              try joint[4].bytes(16) == old[18].bytes(16),
              try joint[5].bytes(32) == old[19].bytes(32),
              try joint[6].bytes(32) == old[20].bytes(32),
              try joint[7].bytes(32) == old[21].bytes(32)
        else { throw IssuerPhoneError.binding }
        let issued = try joint[11].uint(), expiry = try joint[12].uint()
        let controlNonce = try joint[10].bytes(32)
        guard issued > 0, issued <= nowMilliseconds / 1000,
              nowMilliseconds / 1000 < expiry, expiry > issued, expiry - issued <= 60,
              try expiry <= old[33].uint(), try expiry <= old[32].uint(),
              try issued >= old[28].uint(), try issued >= old[31].uint(),
              !controlNonce.allSatisfy({ $0 == 0 })
        else { throw IssuerPhoneError.expired }
        let status = try IssuerCBOR.decode(try joint[3].bytes(), maximum: 4096).array(7)
        guard status[0] == .unsigned(1),
              try status[1].bytes() == Data("ProvisionIssuerRootCurrentStatusPermission".utf8),
              try status[3].bytes(16) == session, try status[4].bytes(32) == controlNonce,
              try status[5].uint() == issued, try status[6].uint() == expiry
        else { throw IssuerPhoneError.binding }
        let scope = try IssuerCBOR.decode(try status[2].bytes(), maximum: 2048).array(16)
        guard scope[0] == .unsigned(1),
              try scope[1].bytes() == Data("IssueIssuerRootCurrentStatus".utf8),
              try !scope[2].bytes(16).allSatisfy({ $0 == 0 }),
              try scope[3].bytes(16) == principal,
              try scope[4].bytes() == Data(Self.uuidText(installation).utf8),
              try scope[5].bytes(16) == old[5].bytes(16),
              try scope[6].bytes(32) == Data(SHA256.hash(data: old[6].bytes(33))),
              try scope[7].bytes(32) == old[21].bytes(32),
              scope[8] == old[22], scope[9] == old[23], scope[10] == old[24],
              try scope[11].bytes(32) == Data(SHA256.hash(data: old[25].bytes(33))),
              scope[12] == old[31], scope[13] == old[32],
              scope[14] == next[15], scope[15] == next[16]
        else { throw IssuerPhoneError.binding }
        let challenge = try JointActionCBOR.decode(cose.payload).map(15)
        try Self.header(challenge, "pistis.action-approval-challenge.v2")
        let ci = try challenge[2].number(), ce = try challenge[3].number()
        let bound = expiry.multipliedReportingOverflow(by: 1000)
        guard !bound.overflow, ci > 0, ci <= nowMilliseconds, nowMilliseconds < ce,
              ci / 1000 >= issued, ce <= bound.partialValue,
              try challenge[4].data(16) == installation,
              try challenge[5].data(32) == trust.installationKeyID,
              try challenge[7].data(32) == controlNonce,
              try challenge[8].data(16) == principal,
              try challenge[9].data(16) == responseContext.externalIdentityID,
              try challenge[10].text() == "propylaion",
              try challenge[11].text() == trust.displayName,
              try !challenge[12].text(maximum: 128).isEmpty,
              try challenge[13].data(32) == Data(SHA256.hash(data: trust.installationPublicKey))
        else { throw IssuerPhoneError.binding }
        let cid = try challenge[6].data(16)
        guard !cid.allSatisfy({ $0 == 0 }) else { throw IssuerPhoneError.binding }
        try Self.descriptor(try challenge[14].data(), control: control)
        self.controlOriginal = control; self.signedChallenge = signed
        self.challengePayload = cose.payload; self.transitionID = transition
        self.sessionID = session; self.siteID = try old[5].bytes(16)
        self.sitePublicKey = try old[6].bytes(33); self.devicePublicKey = publicKey
        self.deviceKeyID = keyID; self.expiresAtMilliseconds = ce
        self.issuedAtMilliseconds = ci; self.challengeID = cid; self.nonce = controlNonce
        self.rootGrantID = try old[18].bytes(16); self.rootGrantExpiry = try old[27].uint()
        self.originalExecutionExpiry = try old[29].uint(); self.statusGrantExpiry = try old[32].uint()
        self.nextPolicyGeneration = try next[15].uint(); self.nextRevocationGeneration = try next[16].uint()
        self.installationID = installation; self.principalID = principal
        self.externalIdentityID = responseContext.externalIdentityID; self.deviceID = device
    }

    /// Exact existing v2 response payload. No new signing purpose or SiteRoot
    /// signature is introduced. The caller must use the retained AUTHN key.
    public func approvedResponsePayload(issuedAt: UInt64, verifiedAt: UInt64) throws -> Data {
        guard issuedAtMilliseconds <= issuedAt, issuedAt <= verifiedAt,
              verifiedAt < expiresAtMilliseconds else { throw IssuerPhoneError.expired }
        return try JointActionCBOR.object([
            .number(2), .string("pistis.action-approval-response.v2"),
            .number(issuedAt), .number(verifiedAt), .bytes(installationID),
            .bytes(deviceKeyID), .bytes(challengeID), .bytes(nonce),
            .bytes(Data(SHA256.hash(data: challengePayload))), .bytes(principalID),
            .bytes(deviceID), .bytes(externalIdentityID), .string("approved")
        ]).encoded()
    }
    public func original(signedResponse: Data) throws -> Data {
        guard !signedResponse.isEmpty, signedResponse.count <= 8192 else {
            throw IssuerPhoneError.bound
        }
        return try IssuerCBOR.array([.unsigned(1), .bytes(controlOriginal),
            .bytes(signedChallenge), .bytes(signedResponse)]).encoded(maximum: 16_384)
    }
    private static func header(_ map: [JointActionCBOR], _ schema: String) throws {
        guard try map[0].number() == 2, try map[1].text() == schema else {
            throw IssuerPhoneError.binding
        }
    }
    private static func requireSuccessor(_ old: [IssuerCBOR], _ next: [IssuerCBOR]) throws {
        guard old[0] == .unsigned(1),
              try old[1].bytes() == Data("issuer-site-status-root-owner-tuple-v1".utf8)
        else { throw IssuerPhoneError.binding }
        for i in 0..<37 {
            if [3, 15, 16, 17].contains(i) {
                let value = try old[i].uint()
                guard value < UInt64.max, try next[i].uint() == value + 1 else {
                    throw IssuerPhoneError.binding
                }
            } else if old[i] != next[i] { throw IssuerPhoneError.binding }
        }
    }
    private static func descriptor(_ raw: Data, control: Data) throws {
        let fields = try JointActionCBOR.decode(raw).map(8)
        try header(fields, "pistis.action-descriptor.v2")
        // A joint attendance approves exactly this deployed image and one
        // control original. No additional command, environment or resource
        // intent may be hidden behind the bounded joint summary.
        let executable = "/usr/libexec/mnemosyne-monas/monas-server"
        guard try fields[2].text() == executable,
              try !fields[3].data(32).allSatisfy({ $0 == 0 }),
              try fields[4].array() == [.string(executable)],
              try fields[5].text() == "/",
              try fields[6].array().isEmpty else { throw IssuerPhoneError.binding }
        let resources = try fields[7].array()
        guard resources.count == 1 else { throw IssuerPhoneError.binding }
        let resource = try resources[0].map(3)
        guard try resource[0].number() == 1,
              try resource[1].text() == "urn:mnemosyne:issuer-control:ProvisionIssuerSiteStatusAndContinueRootV1",
              try resource[2].data(32) == Data(SHA256.hash(data: control))
        else { throw IssuerPhoneError.binding }
    }
    private static func uuidText(_ bytes: Data) -> String {
        let b = [UInt8](bytes)
        return UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])).uuidString.lowercased()
    }
    private static func hex(_ bytes: Data) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

/// Private bounded codec for the existing action-v2 map grammar. It is not an
/// extension of the array-only issuer protocol or its public input limits.
indirect enum JointActionCBOR: Equatable {
    case number(UInt64), bytes(Data), string(String), list([JointActionCBOR]), object([JointActionCBOR]), null
    static func decode(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= 16_384 else { throw IssuerPhoneError.bound }
        let bytes = [UInt8](data); var offset = 0; var nodes = 0
        func read(_ depth: Int) throws -> Self {
            nodes += 1
            guard depth <= 10, nodes <= 4096, offset < bytes.count else { throw IssuerPhoneError.bound }
            let first = bytes[offset]; offset += 1
            if first == 0xf6 { return .null }
            let major = first >> 5, tag = first & 31
            guard [UInt8(0), 2, 3, 4, 5].contains(major), tag <= 27 else { throw IssuerPhoneError.malformed }
            var length = UInt64(tag)
            if tag >= 24 {
                let width = 1 << Int(tag - 24)
                guard width <= bytes.count - offset else { throw IssuerPhoneError.malformed }
                length = 0
                for _ in 0..<width { length = (length << 8) | UInt64(bytes[offset]); offset += 1 }
                let minimum: [UInt64] = [24, 256, 65_536, 4_294_967_296]
                guard length >= minimum[Int(tag - 24)] else { throw IssuerPhoneError.malformed }
            }
            switch major {
            case 0: return .number(length)
            case 2, 3:
                guard length <= UInt64(bytes.count - offset) else { throw IssuerPhoneError.bound }
                let raw = Data(bytes[offset..<(offset + Int(length))]); offset += Int(length)
                if major == 2 { return .bytes(raw) }
                guard let text = String(data: raw, encoding: .utf8), Data(text.utf8) == raw else { throw IssuerPhoneError.malformed }
                return .string(text)
            case 4, 5:
                guard length <= 4096, length <= UInt64(bytes.count - offset) else { throw IssuerPhoneError.bound }
                var fields: [Self] = []
                for i in 0..<length {
                    if major == 5 { guard try read(depth + 1) == .number(i) else { throw IssuerPhoneError.malformed } }
                    fields.append(try read(depth + 1))
                }
                return major == 4 ? .list(fields) : .object(fields)
            default: throw IssuerPhoneError.malformed
            }
        }
        let result = try read(0)
        guard offset == bytes.count, try result.encoded() == data else { throw IssuerPhoneError.malformed }
        return result
    }
    func encoded() throws -> Data {
        var result = Data(); var nodes = 0
        func head(_ major: UInt8, _ n: UInt64) {
            if n < 24 { result.append(major << 5 | UInt8(n)); return }
            let width = n <= 255 ? 1 : n <= 65_535 ? 2 : n <= 4_294_967_295 ? 4 : 8
            let tag: UInt8 = width == 1 ? 24 : width == 2 ? 25 : width == 4 ? 26 : 27
            result.append(major << 5 | tag)
            for i in stride(from: width - 1, through: 0, by: -1) { result.append(UInt8(truncatingIfNeeded: n >> (i * 8))) }
        }
        func emit(_ value: Self, _ depth: Int) throws {
            nodes += 1
            guard depth <= 10, nodes <= 4096, result.count <= 16_384 else { throw IssuerPhoneError.bound }
            switch value {
            case let .number(n): head(0, n)
            case let .bytes(raw):
                guard raw.count <= 16_384 - result.count else { throw IssuerPhoneError.bound }
                head(2, UInt64(raw.count)); result.append(raw)
            case let .string(text):
                let raw = Data(text.utf8)
                guard raw.count <= 16_384 - result.count else { throw IssuerPhoneError.bound }
                head(3, UInt64(raw.count)); result.append(raw)
            case let .list(fields):
                head(4, UInt64(fields.count)); for field in fields { try emit(field, depth + 1) }
            case let .object(fields):
                head(5, UInt64(fields.count))
                for (i, field) in fields.enumerated() { head(0, UInt64(i)); try emit(field, depth + 1) }
            case .null: result.append(0xf6)
            }
            guard result.count <= 16_384 else { throw IssuerPhoneError.bound }
        }
        try emit(self, 0); return result
    }
    func map(_ count: Int) throws -> [Self] {
        guard case let .object(fields) = self, fields.count == count else { throw IssuerPhoneError.malformed }; return fields
    }
    func data(_ count: Int? = nil) throws -> Data {
        guard case let .bytes(raw) = self, count.map({ raw.count == $0 }) ?? true else { throw IssuerPhoneError.malformed }; return raw
    }
    func text(empty: Bool = false, maximum: Int = 4096) throws -> String {
        guard case let .string(text) = self, empty || !text.isEmpty, text.utf8.count <= maximum,
              text.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else { throw IssuerPhoneError.malformed }; return text
    }
    func number() throws -> UInt64 { guard case let .number(n) = self else { throw IssuerPhoneError.malformed }; return n }
    func array() throws -> [Self] { guard case let .list(a) = self else { throw IssuerPhoneError.malformed }; return a }
}
