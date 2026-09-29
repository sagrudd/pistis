import CryptoKit
import Foundation

/// The immutable Proxenos release pin for the offline PXRA presentation purpose.
///
/// The generic Pistis profile intentionally contains no pin. A release may add
/// one only after its public key and generation have been independently
/// verified against Proxenos-owned custody provenance. No imported file can
/// supply or replace this value.
struct ProxenosPXRAKeyPinV1: Equatable, Sendable {
  static let publicKeyInfoKey = "PistisProxenosPXRAKeyB64URL"
  static let keyGenerationInfoKey = "PistisProxenosPXRAKeyGeneration"
  static let keyDigestInfoKey = "PistisProxenosPXRAKeySHA256B64URL"
  static let siteUUIDInfoKey = "PistisProxenosPXRASiteUUID"
  static let purposeInfoKey = "PistisProxenosPXRAPurpose"
  static let purpose = "site-root-ack-presentation"

  let publicKey: Data
  let generation: UInt64
  let siteUUID: String

  init(
    publicKey: Data,
    generation: UInt64,
    siteUUID: String,
    purpose: String = Self.purpose
  ) throws {
    guard publicKey.count == 32, !publicKey.allSatisfy({ $0 == 0 }),
      generation > 0,
      purpose == Self.purpose,
      SiteRootConvergenceEncoding.uuidBytes(siteUUID) != nil,
      (try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey)) != nil
    else { throw PlatformFailure.invalidConfiguration }
    self.publicKey = publicKey
    self.generation = generation
    self.siteUUID = siteUUID
  }

  /// Reads only the signed application bundle. Empty or malformed values
  /// mean offline signing is unavailable; there is no fallback key source.
  static func fromSignedProfile(_ infoDictionary: [String: Any]) -> Self? {
    guard let keyText = infoDictionary[publicKeyInfoKey] as? String,
      let generationText = infoDictionary[keyGenerationInfoKey] as? String,
      let digestText = infoDictionary[keyDigestInfoKey] as? String,
      let siteUUID = infoDictionary[siteUUIDInfoKey] as? String,
      let purpose = infoDictionary[purposeInfoKey] as? String,
      let generation = UInt64(generationText),
      let key = Self.decodeCanonicalBase64URL(keyText),
      let digest = Self.decodeCanonicalBase64URL(digestText), digest.count == 32,
      Data(SHA256.hash(data: key)) == digest
    else { return nil }
    return try? Self(
      publicKey: key,
      generation: generation,
      siteUUID: siteUUID,
      purpose: purpose
    )
  }

  private static func decodeCanonicalBase64URL(_ value: String) -> Data? {
    guard !value.isEmpty,
      value.utf8.allSatisfy({
        (65...90).contains($0) || (97...122).contains($0)
          || (48...57).contains($0) || $0 == 45 || $0 == 95
      }), value.utf8.count % 4 != 1
    else { return nil }
    let padded =
      value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
      + String(repeating: "=", count: (4 - value.utf8.count % 4) % 4)
    guard let data = Data(base64Encoded: padded),
      data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "") == value
    else { return nil }
    return data
  }
}

/// Exact bounded offline envelope for one Proxenos-signed retained PXRA/v2.
///
/// This codec is deliberately synchronous and performs no transport. The
/// envelope signature is detached over the exact retained PXRA bytes.
struct ProxenosPXRAEnvelopeV1: Equatable, Sendable {
  static let contentType = "application/vnd.mnemosyne.pxrp.v1"
  static let maximumPresentationBytes = 512
  static let maximumEnvelopeBytes = 768
  private static let magic = Data("PXRP/v1".utf8)
  private static let profile: UInt8 = 0x01

  let unsignedPXRA: Data
  let presentation: UnsignedSiteRootConvergenceAssertionV2

  init(
    frame: Data,
    pin: ProxenosPXRAKeyPinV1?,
    expectedSiteUUID: String,
    expectedTargetID: Data,
    expectedAckGeneration: UInt64,
    nowUnixMilliseconds: UInt64
  ) throws {
    guard let pin, pin.siteUUID == expectedSiteUUID else {
      throw PlatformFailure.siteRootAuthorityUnavailable
    }
    guard frame.count >= 7 + 1 + 2 + 1 + 64,
      frame.count <= Self.maximumEnvelopeBytes,
      frame.starts(with: Self.magic), frame[7] == Self.profile
    else { throw PlatformFailure.qrPayloadUnsupported }

    let payloadLength = Int(frame[8]) << 8 | Int(frame[9])
    guard (1...Self.maximumPresentationBytes).contains(payloadLength),
      10 + payloadLength < frame.count
    else { throw PlatformFailure.qrPayloadUnsupported }
    let payloadEnd = 10 + payloadLength
    let payload = frame.subdata(in: 10..<payloadEnd)
    let cose = Data(frame[payloadEnd...])
    let signature = try Self.readDetachedSignature(cose, generation: pin.generation)
    let structure = Self.signatureStructure(
      protected: Self.protectedHeaders(
        generation: pin.generation
      ), payload: payload)
    guard
      let verifier = try? Curve25519.Signing.PublicKey(
        rawRepresentation: pin.publicKey
      ), verifier.isValidSignature(signature, for: structure)
    else { throw PlatformFailure.malformedSignature }

    let parsed = try UnsignedSiteRootConvergenceAssertionV2(
      payload, nowUnixMilliseconds: nowUnixMilliseconds
    )
    guard parsed.siteUUIDText == expectedSiteUUID,
      parsed.targetID == expectedTargetID,
      parsed.ackKeyGeneration == expectedAckGeneration
    else { throw PlatformFailure.siteRootAuthorityUnavailable }
    unsignedPXRA = payload
    presentation = parsed
  }

  private static func protectedHeaders(generation: UInt64) -> Data {
    var generationBytes = Data()
    for shift in stride(from: 56, through: 0, by: -8) {
      generationBytes.append(UInt8(truncatingIfNeeded: generation >> UInt64(shift)))
    }
    return Data([0xa3, 0x01, 0x27, 0x03]) + cborText(contentType)
      + Data([0x04]) + cborBytes(generationBytes)
  }

  private static func signatureStructure(protected: Data, payload: Data) -> Data {
    Data([0x84]) + cborText("Signature1") + cborBytes(protected)
      + Data([0x40]) + cborBytes(payload)
  }

  private static func readDetachedSignature(_ data: Data, generation: UInt64) throws -> Data {
    var reader = CanonicalCBORReader(data)
    guard try reader.byte() == 0x84 else { throw PlatformFailure.qrPayloadUnsupported }
    let protected = try reader.byteString(maximum: 128)
    guard protected == protectedHeaders(generation: generation),
      try reader.byte() == 0xa0, try reader.byte() == 0xf6
    else { throw PlatformFailure.qrPayloadUnsupported }
    let signature = try reader.byteString(maximum: 64)
    guard signature.count == 64 else { throw PlatformFailure.malformedSignature }
    try reader.requireEnd()
    return signature
  }

  private static func cborText(_ value: String) -> Data {
    cborString(major: 3, value: Data(value.utf8))
  }

  private static func cborBytes(_ value: Data) -> Data {
    cborString(major: 2, value: value)
  }

  private static func cborString(major: UInt8, value: Data) -> Data {
    let count = value.count
    let prefix: Data
    if count <= 23 {
      prefix = Data([major << 5 | UInt8(count)])
    } else if count <= 0xff {
      prefix = Data([major << 5 | 24, UInt8(count)])
    } else {
      prefix = Data([major << 5 | 25, UInt8(count >> 8), UInt8(count)])
    }
    return prefix + value
  }
}

/// Rejects signing the same imported envelope twice within one active local
/// continuation. Proxenos remains authoritative for durable replay handling.
struct ProxenosPXRAReplayGuardV1 {
  private var consumedDigests = Set<Data>()

  mutating func consume(_ exactEnvelope: Data) throws {
    guard !exactEnvelope.isEmpty,
      consumedDigests.insert(Data(SHA256.hash(data: exactEnvelope))).inserted
    else { throw PlatformFailure.siteRootAuthorityUnavailable }
  }
}

private struct CanonicalCBORReader {
  private let bytes: [UInt8]
  private var offset = 0

  init(_ data: Data) { bytes = Array(data) }

  mutating func byte() throws -> UInt8 {
    guard offset < bytes.count else { throw PlatformFailure.qrPayloadUnsupported }
    defer { offset += 1 }
    return bytes[offset]
  }

  mutating func byteString(maximum: Int) throws -> Data {
    let initial = try byte()
    guard initial >> 5 == 2 else { throw PlatformFailure.qrPayloadUnsupported }
    let additional = initial & 0x1f
    let count: Int
    switch additional {
    case 0...23: count = Int(additional)
    case 24:
      let value = Int(try byte())
      guard value >= 24 else { throw PlatformFailure.qrPayloadUnsupported }
      count = value
    case 25:
      let value = Int(try byte()) << 8 | Int(try byte())
      guard value > 0xff else { throw PlatformFailure.qrPayloadUnsupported }
      count = value
    default: throw PlatformFailure.qrPayloadUnsupported
    }
    guard count <= maximum, offset + count <= bytes.count else {
      throw PlatformFailure.qrPayloadUnsupported
    }
    defer { offset += count }
    return Data(bytes[offset..<offset + count])
  }

  mutating func requireEnd() throws {
    guard offset == bytes.count else { throw PlatformFailure.qrPayloadUnsupported }
  }
}
