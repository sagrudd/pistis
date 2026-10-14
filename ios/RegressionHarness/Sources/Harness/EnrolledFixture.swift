import Crypto
import Foundation
import PistisCore

/// Ephemeral software material for this non-production test executable only.
/// The receipt and provider binding are modelled, not authenticated enrolment.
@MainActor
public final class EnrolledFixture {
  public static let now = Date(timeIntervalSince1970: 1_750_000_001)
  let installationKey = P256.Signing.PrivateKey()
  let deviceKey = P256.Signing.PrivateKey()
  let installationID = Data(repeating: 0x11, count: 16)
  let installationKeyID = Data(repeating: 0x22, count: 32)
  let fingerprint = Data(repeating: 0x33, count: 32)
  let externalID = Data(repeating: 0x44, count: 16)
  let userID = Data(repeating: 0x88, count: 16)
  public let trust: InstallationTrustRecord
  let responseContext: DeviceResponseContext

  public init(active: Bool = true) throws {
    trust = try InstallationTrustRecord(
      installationID: installationID,
      displayName: "Local conformance fixture",
      audience: "prosopikon:pistis:enrolment",
      authorisedProductAudiences: ["propylaion"],
      userID: userID,
      externalIdentityID: externalID,
      fingerprint: fingerprint,
      installationKeyID: installationKeyID,
      installationPublicKey: installationKey.publicKey.compressedRepresentation,
      authorityKeyID: Data(repeating: 0x55, count: 32),
      authorityReceipt: Data([0x01]),
      policyGeneration: 1,
      revocationGeneration: 1,
      expiresAt: Self.now.addingTimeInterval(3600),
      active: active
    )
    responseContext = try DeviceResponseContext(
      deviceID: Data(repeating: 0xaa, count: 16),
      deviceKeyID: Data(repeating: 0xbb, count: 32),
      userID: userID,
      externalIdentityID: externalID
    )
  }

  public func qr(
    audience: String = "propylaion",
    installation: Data? = nil,
    identity: Data? = nil,
    expired: Bool = false,
    invalidSignature: Bool = false,
    challengeByte: UInt8 = 0x66
  ) throws -> String {
    let issued: UInt64 = 1_750_000_000_000
    var payload = Data([0xb1])
    let fields: [Data] = [
      FixtureCBOR.uint(1),
      FixtureCBOR.text("pistis.authentication-challenge.v1"),
      FixtureCBOR.uint(issued),
      FixtureCBOR.uint(expired ? issued + 100 : issued + 60_000),
      FixtureCBOR.bytes(installation ?? installationID),
      FixtureCBOR.bytes(installationKeyID),
      FixtureCBOR.bytes(Data(repeating: challengeByte, count: 16)),
      FixtureCBOR.bytes(Data(repeating: 0x77, count: 32)),
      FixtureCBOR.bytes(userID),
      FixtureCBOR.bytes(identity ?? externalID),
      FixtureCBOR.text("authenticate-session"),
      FixtureCBOR.text(audience),
      FixtureCBOR.text(trust.displayName),
      FixtureCBOR.text("fixture-user"),
      FixtureCBOR.bytes(Data(repeating: 0x99, count: 32)),
      FixtureCBOR.bytes(fingerprint),
      Data([0x81]) + FixtureCBOR.text("https://fixture.invalid/auth/pistis"),
    ]
    for (index, value) in fields.enumerated() {
      payload += FixtureCBOR.uint(UInt64(index)) + value
    }
    let key = invalidSignature ? P256.Signing.PrivateKey() : installationKey
    let cose = try Self.sign(payload, keyID: installationKeyID, using: key)
    let frame = Data([0xa3, 0x00, 0x02, 0x01, 0x01, 0x02]) + FixtureCBOR.bytes(cose)
    let body = frame.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    let checksum = hex(Data(SHA256.hash(data: Data("PISTIS1:\(body)".utf8)).prefix(8)))
    return "PISTIS1:\(body).\(checksum)"
  }

  static func sign(
    _ payload: Data, keyID: Data, using key: P256.Signing.PrivateKey
  ) throws -> Data {
    let structure = try CoseSign1.signatureStructure(keyID: keyID, payload: payload)
    // The production codec enforces low-S. Retry ephemeral fixture signing
    // instead of implementing a separate scalar normalisation algorithm.
    for _ in 0..<64 {
      let signature = try key.signature(for: structure).rawRepresentation
      if let cose = try? CoseSign1(keyID: keyID, payload: payload, signature: signature) {
        return cose.encoded()
      }
    }
    throw FixtureFailure.signatureGeneration
  }
}

enum FixtureFailure: Error { case signatureGeneration }

func hex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

enum FixtureCBOR {
  static func uint(_ value: UInt64) -> Data { argument(0, value) }
  static func bytes(_ value: Data) -> Data { argument(2, UInt64(value.count)) + value }
  static func text(_ value: String) -> Data {
    argument(3, UInt64(value.utf8.count)) + Data(value.utf8)
  }
  static func argument(_ major: UInt8, _ value: UInt64) -> Data {
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
