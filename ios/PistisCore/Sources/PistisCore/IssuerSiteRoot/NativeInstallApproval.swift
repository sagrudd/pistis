import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Closed prospective native-purpose approval DATA. Parsing cannot establish
/// trust, appoint a key, grant permission or initialise an owner. The signing
/// route must independently join retained installation, SiteRoot and ACK trust.
public struct NativeInstallApprovalTask: Sendable {
    public struct RequestedKey: Sendable {
        public let role: String
        public let publicKey: Data
        public let purposes: [String]
    }
    public let taskID: Data
    public let bodyOriginal: Data
    public let bodyDigest: Data
    public let selectionOriginal: Data
    public let operationID: Data
    public let nonce: Data
    public let installationID: Data
    public let siteID: Data
    public let siteLabel: String
    public let nativeTarget: Data
    public let siteRootPublicKey: Data
    public let acknowledgementTarget: Data
    public let acknowledgementGeneration: UInt64
    public let acknowledgementPublicKey: Data
    public let requestedKeys: [RequestedKey]
    public let captureOriginal: Data
    public let scopeOriginal: Data
    public let placementOriginal: Data
    public let measurementOriginal: Data
    public let expiresAt: UInt64
    public let sourceRepository: String
    public let sourceRevision: Data
    public let lifecycle: Data
    public let separateMonasNativeDigest: Data

    public init(canonicalBytes: Data, now: UInt64) throws {
        let task = try IssuerCBOR.decode(canonicalBytes, maximum: 262_144).array(6)
        guard task[0] == .unsigned(1), task[1] == .unsigned(8) else { throw IssuerPhoneError.binding }
        taskID = try task[2].bytes(16, nonzero: true)
        bodyOriginal = try task[3].bytes(range: 1...196_608)
        bodyDigest = IssuerPhoneWire.sha256(bodyOriginal)
        selectionOriginal = try task[4].bytes(range: 1...4096)
        guard try task[5].bytes(32) == bodyDigest else { throw IssuerPhoneError.binding }
        let body = try IssuerCBOR.decode(bodyOriginal, maximum: 196_608).array(10)
        guard body[0] == .unsigned(1), try body[1].bytes() == Data("issuer-native-install-purpose-approval-v1".utf8),
              try body[6].bytes(32) == Self.adoptedSpec else { throw IssuerPhoneError.binding }
        operationID = try body[2].bytes(16, nonzero: true); nonce = try body[3].bytes(32, nonzero: true)
        let issued = try body[4].uint(1...UInt64.max)
        expiresAt = try body[5].uint(1...UInt64.max)
        guard issued <= now, now < expiresAt, issued < expiresAt, expiresAt-issued <= 30 else { throw IssuerPhoneError.expired }
        captureOriginal = try body[8].bytes(range: 1...40_960)
        scopeOriginal = try body[9].bytes(range: 1...8192)
        guard try body[7].bytes(32) == IssuerPhoneWire.sha256(captureOriginal) else { throw IssuerPhoneError.binding }
        let r = try IssuerCBOR.decode(captureOriginal, maximum: 40_960).array(24)
        guard r[0] == .unsigned(1), try r[1].bytes() == Data("issuer-native-purpose-current-record-v1".utf8) else { throw IssuerPhoneError.binding }
        lifecycle = try r[2].bytes(32, nonzero: true)
        for i in [3,4,5,7,8,9] { _ = try r[i].bytes(16, nonzero: true) }
        installationID = try r[4].bytes(16); siteID = try r[5].bytes(16)
        nativeTarget = try r[6].bytes(32, nonzero: true)
        let authKey = try r[10].ascii(64...64)
        guard authKey.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }), authKey.contains(where: { $0 != 48 }) else { throw IssuerPhoneError.binding }
        for i in 11...16 { _ = try r[i].uint(1...UInt64.max) }
        guard try r[16].uint() >= expiresAt else { throw IssuerPhoneError.expired }
        measurementOriginal = try r[17].bytes(range: 1...32_768)
        let nativeDigest = try r[18].bytes(32, nonzero: true)
        let ack = try r[19].array(5)
        guard try ack[0].bytes(16) == siteID else { throw IssuerPhoneError.binding }
        acknowledgementTarget = try ack[1].bytes(32, nonzero: true)
        acknowledgementGeneration = try ack[2].uint(1...UInt64.max)
        acknowledgementPublicKey = try Self.publicKey(ack[3]); siteRootPublicKey = try Self.publicKey(ack[4])
        guard IssuerPhoneWire.sha256(siteRootPublicKey) == acknowledgementTarget else { throw IssuerPhoneError.binding }
        let trio = try r[20].array(3).map(Self.publicKey)
        guard Set(trio).count == 3 else { throw IssuerPhoneError.binding }
        let old = try r[21].array(4)
        _ = try old[0].bytes(32, nonzero: true)
        let oldGeneration = try old[1].ascii(1...255)
        guard oldGeneration.allSatisfy({ 33...126 ~= $0 }) else { throw IssuerPhoneError.binding }
        _ = try old[2].uint()
        guard try old[3].bytes() == Self.issuerPurpose else { throw IssuerPhoneError.binding }
        let stable = try IssuerCBOR.array([.unsigned(1), .bytes(Data("issuer-native-purpose-lifecycle-v1".utf8)), .bytes(installationID), .bytes(siteID), .bytes(Self.issuerPurpose)]).encoded(maximum: 512)
        guard IssuerPhoneWire.sha256(stable) == lifecycle else { throw IssuerPhoneError.binding }
        let source = try r[22].array(7)
        sourceRepository = String(decoding: try source[0].ascii(3...201), as: UTF8.self)
        guard sourceRepository.utf8.allSatisfy({ 33...126 ~= $0 }) else { throw IssuerPhoneError.binding }
        sourceRevision = try source[1].bytes(20, nonzero: true)
        let configuration = try source[2].bytes(32, nonzero: true)
        guard try source[3].uint(1...UInt64.max) >= r[16].uint() else { throw IssuerPhoneError.expired }
        for i in 4...6 { _ = try source[i].bytes(32, nonzero: true) }
        let policy = try r[23].array(6)
        guard try policy[0].bytes(32) == Self.adoptedSpec, try policy[2].bytes(range: 1...8192) == scopeOriginal else { throw IssuerPhoneError.binding }
        _ = try policy[1].bytes(32, nonzero: true)
        placementOriginal = try policy[3].bytes(range: 1...8192)
        separateMonasNativeDigest = try policy[4].bytes(32, nonzero: true)
        guard try policy[5].bytes(range: 1...4096) == selectionOriginal else { throw IssuerPhoneError.binding }
        try Self.selection(selectionOriginal, site: siteID, target: nativeTarget, ack: ack)
        let scope = try IssuerCBOR.decode(scopeOriginal, maximum: 8192).array(9)
        guard scope[0] == .unsigned(1), try scope[1].bytes() == Data("issuer-pre-root-native-scope-v1".utf8),
              try scope[2].bytes() == Data("classic-commit-status:mnemosyne/expedition".utf8) else { throw IssuerPhoneError.binding }
        siteLabel = String(decoding: try scope[3].ascii(1...128), as: UTF8.self)
        let roles = try scope[4].array(3)
        let expected = [("W",["IHIS/1","IRSP/1","IROT/1"]),("P",["INAT/1","ICMT/1"]),("T",["ICMT/1"])]
        requestedKeys = try expected.enumerated().map { i, item in
            let role = try roles[i].array(5)
            guard try role[0].bytes() == Data(item.0.utf8), try role[1].bytes() == Data("ES256".utf8), role[2] == .unsigned(1), try Self.publicKey(role[3]) == trio[i],
                  try role[4].array(item.1.count) == item.1.map({ .bytes(Data($0.utf8)) }) else { throw IssuerPhoneError.binding }
            return RequestedKey(role: item.0, publicKey: trio[i], purposes: item.1)
        }
        let rule = try scope[5].array(3)
        guard rule == [.unsigned(1),.bytes(Data("fresh-native-purpose-only-v1".utf8)),.bytes(Data("independent-existing-issuance-checkpoint-at-commit-v1".utf8))] else { throw IssuerPhoneError.binding }
        let recovery = try IssuerCBOR.decode(scope[6].bytes(range: 1...4096), maximum: 4096).array(2)
        guard recovery == [.unsigned(1),.bytes(Data("no-native-purpose-recovery-authorized-v1".utf8))],
              try scope[7].bytes(32) == lifecycle, try scope[8].bytes(32) == IssuerPhoneWire.sha256(placementOriginal) else { throw IssuerPhoneError.binding }
        try NativeInstallMeasurement.validate(measurementOriginal, placement: placementOriginal, installation: installationID, site: siteID, label: siteLabel, configuration: configuration, nativeDigest: nativeDigest)
    }
    private static func publicKey(_ value: IssuerCBOR) throws -> Data {
        let raw = try value.bytes(33)
        _ = try P256.Signing.PublicKey(compressedRepresentation: raw)
        return raw
    }
    private static func selection(_ raw: Data, site: Data, target: Data, ack: [IssuerCBOR]) throws {
        let s = try IssuerCBOR.decode(raw, maximum: 4096).array(8)
        guard try s[0].bytes(16) == site, s[1] == ack[1], s[2] == ack[2], s[3] == ack[3], try s[4].bytes(32) == target else { throw IssuerPhoneError.binding }
        _ = try s[5].uint(1...3); _ = try s[6].uint(1...UInt64.max); _ = try s[7].bytes(32, nonzero: true)
    }
    private static let issuerPurpose = Data("thesaurophylax.github-exact-source-qualification-credential-projection.v1".utf8)
    private static let adoptedSpec = Data([0x9a,0x84,0x27,0x96,0x11,0xdc,0x44,0x2e,0x77,0xf3,0xad,0x2b,0x3a,0xd9,0x48,0x77,0x7c,0xf6,0x00,0x39,0xc8,0x37,0x56,0x3b,0xb7,0x9e,0x57,0xff,0xd0,0x01,0x88,0xcd])
}
