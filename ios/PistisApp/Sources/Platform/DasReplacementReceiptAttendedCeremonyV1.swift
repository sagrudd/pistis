import CryptoKit
import Foundation

/// Closed HTTP and proof profile for the one-use DAS local-authority
/// replacement receipt ceremony. All endpoints and purpose strings are fixed;
/// no QR, browser, caller input or server response can redirect the exchange.
enum DasReplacementReceiptAttendedProfileV1 {
  static let beginSchema = "monas.das-replacement-receipt-begin.v1"
  static let presentationSchema = "monas.das-replacement-receipt-presentation.v1"
  static let submissionSchema = "monas.das-replacement-receipt-submission.v1"
  static let acceptedSchema = "monas.das-replacement-receipt-accepted.v1"
  static let purpose = "das_local_authority_replacement_receipt"
  static let presentationPath = "/api/v1/pistis/das-replacement-receipt/presentation"
  static let submissionPath = "/api/v1/pistis/das-replacement-receipt/submission"
  static let challengeSchema = Data(
    "thesaurophylax.das-replacement-receipt-rewrap.v1\0".utf8
  )
}

/// Exact public/ciphertext presentation relayed from the retained Thesaurophylax
/// ceremony. The decoder is strict because every field is security-sensitive.
struct DasReplacementReceiptPresentationV1: Sendable {
  static let maximumLifetimeSeconds: UInt64 = 300

  let correlation: Data
  let canonicalChallenge: Data
  let hostPublicSEC1: Data
  let existingHostPublicSEC1: Data
  let siteTrustDomainID: String
  let custodyGeneration: String
  let deviceKeyID: String
  let generationPublicSEC1: Data
  let encryptedRecordSHA256: Data
  let revocationGeneration: UInt64
  let delegationSerial: String
  let expiresAtUnixSeconds: UInt64
  let encryptedRecord: Data

  init(data: Data, nowUnixSeconds: UInt64) throws {
    let object = try StrictJSONObject(data: data, maximumBytes: 16_384)
    let keys: Set<String> = [
      "schema", "purpose", "correlation", "canonicalChallenge",
      "hostPublicSec1", "existingHostPublicSec1", "siteTrustDomainId",
      "custodyGeneration", "deviceKeyId", "generationPublicSec1",
      "encryptedRecordSha256", "revocationGeneration", "delegationSerial",
      "expiresAtUnixSeconds", "encryptedRecord", "submissionPath",
    ]
    guard Set(object.values.keys) == keys else {
      throw PlatformFailure.custodyRewrapUnavailable
    }
    let wire: Wire
    do { wire = try JSONDecoder().decode(Wire.self, from: data) } catch {
      throw PlatformFailure.custodyRewrapUnavailable
    }
    guard wire.schema == DasReplacementReceiptAttendedProfileV1.presentationSchema,
      wire.purpose == DasReplacementReceiptAttendedProfileV1.purpose,
      wire.submissionPath == DasReplacementReceiptAttendedProfileV1.submissionPath,
      Self.identifier(wire.siteTrustDomainID),
      Self.identifier(wire.custodyGeneration),
      wire.custodyGeneration.hasPrefix("das-replacement-"),
      Self.identifier(wire.deviceKeyID), Self.identifier(wire.delegationSerial),
      wire.revocationGeneration > 0,
      wire.expiresAtUnixSeconds > nowUnixSeconds,
      wire.expiresAtUnixSeconds - nowUnixSeconds <= Self.maximumLifetimeSeconds,
      let correlation = Self.hex(wire.correlation, exact: 32, nonzero: true),
      let challenge = Self.hex(wire.canonicalChallenge, range: 1...4_096),
      let freshHost = Self.hex(wire.hostPublicSEC1, exact: 33),
      Self.p256Point(freshHost),
      let existingHost = Self.hex(wire.existingHostPublicSEC1, exact: 33),
      Self.p256Point(existingHost), existingHost != freshHost,
      let generationPublic = Self.hex(wire.generationPublicSEC1, exact: 33),
      Self.p256SigningPoint(generationPublic),
      let digest = Self.hex(wire.encryptedRecordSHA256, exact: 32, nonzero: true),
      let encryptedRecord = Self.hex(wire.encryptedRecord, range: 28...4_096),
      Data(SHA256.hash(data: encryptedRecord)) == digest
    else { throw PlatformFailure.custodyRewrapUnavailable }

    self.correlation = correlation
    canonicalChallenge = challenge
    hostPublicSEC1 = freshHost
    existingHostPublicSEC1 = existingHost
    siteTrustDomainID = wire.siteTrustDomainID
    custodyGeneration = wire.custodyGeneration
    deviceKeyID = wire.deviceKeyID
    generationPublicSEC1 = generationPublic
    encryptedRecordSHA256 = digest
    revocationGeneration = wire.revocationGeneration
    delegationSerial = wire.delegationSerial
    expiresAtUnixSeconds = wire.expiresAtUnixSeconds
    self.encryptedRecord = encryptedRecord
    guard try Self.reconstructChallenge(self) == challenge else {
      throw PlatformFailure.custodyRewrapUnavailable
    }
  }

  static func reconstructChallenge(_ value: Self) throws -> Data {
    var output = DasReplacementReceiptAttendedProfileV1.challengeSchema
    for (tag, field) in [
      (UInt8(1), Data([4])),
      (2, Data(value.siteTrustDomainID.utf8)),
      (3, Data(value.custodyGeneration.utf8)),
      (4, Data(value.deviceKeyID.utf8)),
      (5, value.generationPublicSEC1),
      (6, value.encryptedRecordSHA256),
      (7, Data(value.revocationGeneration.bigEndianBytes)),
      (8, Data(value.delegationSerial.utf8)),
      (9, Data(value.expiresAtUnixSeconds.bigEndianBytes)),
      (10, value.hostPublicSEC1),
    ] {
      guard !field.isEmpty, field.count <= Int(UInt16.max) else {
        throw PlatformFailure.custodyRewrapUnavailable
      }
      output.append(tag)
      output.append(contentsOf: UInt16(field.count).bigEndianBytes)
      output.append(field)
    }
    return output
  }

  private struct Wire: Decodable {
    let schema: String
    let purpose: String
    let correlation: String
    let canonicalChallenge: String
    let hostPublicSEC1: String
    let existingHostPublicSEC1: String
    let siteTrustDomainID: String
    let custodyGeneration: String
    let deviceKeyID: String
    let generationPublicSEC1: String
    let encryptedRecordSHA256: String
    let revocationGeneration: UInt64
    let delegationSerial: String
    let expiresAtUnixSeconds: UInt64
    let encryptedRecord: String
    let submissionPath: String

    enum CodingKeys: String, CodingKey {
      case schema, purpose, correlation, canonicalChallenge, delegationSerial
      case hostPublicSEC1 = "hostPublicSec1"
      case existingHostPublicSEC1 = "existingHostPublicSec1"
      case siteTrustDomainID = "siteTrustDomainId"
      case custodyGeneration
      case deviceKeyID = "deviceKeyId"
      case generationPublicSEC1 = "generationPublicSec1"
      case encryptedRecordSHA256 = "encryptedRecordSha256"
      case revocationGeneration, expiresAtUnixSeconds, encryptedRecord, submissionPath
    }
  }

  private static func identifier(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 128
      && value.utf8.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
          || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
      }
  }

  private static func p256Point(_ value: Data) -> Bool {
    value.count == 33 && (value.first == 2 || value.first == 3)
      && (try? P256.KeyAgreement.PublicKey(compressedRepresentation: value)) != nil
  }

  private static func p256SigningPoint(_ value: Data) -> Bool {
    p256Point(value)
      && (try? P256.Signing.PublicKey(compressedRepresentation: value)) != nil
  }

  private static func hex(_ value: String, exact: Int, nonzero: Bool = false) -> Data? {
    guard let decoded = hex(value, range: exact...exact),
      !nonzero || !decoded.allSatisfy({ $0 == 0 })
    else { return nil }
    return decoded
  }

  private static func hex(_ value: String, range: ClosedRange<Int>) -> Data? {
    guard value.count.isMultiple(of: 2), range.contains(value.count / 2),
      value.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) })
    else { return nil }
    var output = Data(capacity: value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
      output.append(byte)
      index = next
    }
    return output.hexadecimal == value ? output : nil
  }
}

struct DasReplacementReceiptBeginV1: Encodable, Sendable {
  let schema = DasReplacementReceiptAttendedProfileV1.beginSchema
}

struct DasReplacementReceiptSubmissionV1: Encodable, Sendable {
  let schema = DasReplacementReceiptAttendedProfileV1.submissionSchema
  let correlation: String
  let canonicalChallenge: String
  let deviceKeyID: String
  let delegationSerial: String
  let siteTrustDomainID: String
  let purpose = DasReplacementReceiptAttendedProfileV1.purpose
  let detachedCOSESign1: String
  let rewrappedCiphertext: String

  enum CodingKeys: String, CodingKey {
    case schema, correlation, canonicalChallenge, delegationSerial, purpose
    case deviceKeyID = "deviceKeyId"
    case siteTrustDomainID = "siteTrustDomainId"
    case detachedCOSESign1 = "detachedCoseSign1"
    case rewrappedCiphertext
  }
}

/// Exact acknowledgement returned only after Monas retained one UDS stream
/// through unlock, signing and successful receipt delivery to waiting DAS.
/// Server-side retirement/activation preflight remains authoritative.
struct DasReplacementReceiptAcceptedV1: Sendable {
  let correlation: Data

  init(data: Data, expectedCorrelation: Data) throws {
    let object = try StrictJSONObject(data: data, maximumBytes: 2_048)
    let keys: Set<String> = ["schema", "correlation", "purpose", "state"]
    guard Set(object.values.keys) == keys else {
      throw PlatformFailure.custodyRewrapUnavailable
    }
    let wire = try JSONDecoder().decode(Wire.self, from: data)
    guard wire.schema == DasReplacementReceiptAttendedProfileV1.acceptedSchema,
      wire.purpose == DasReplacementReceiptAttendedProfileV1.purpose,
      wire.state == "receipt_signed",
      wire.correlation == expectedCorrelation.hexadecimal
    else { throw PlatformFailure.custodyRewrapUnavailable }
    correlation = expectedCorrelation
  }

  private struct Wire: Decodable {
    let schema: String
    let correlation: String
    let purpose: String
    let state: String
  }
}

/// Purpose-four producer using the enrolled Site Root Secure Enclave key. It
/// transiently opens the retained record and reseals its exact P-256 scalar to
/// the fresh server-held peer key under one already-evaluated Face ID context.
final class SecureEnclaveDasReplacementReceiptProducerV1: @unchecked Sendable {
  private static let wrapInfo = Data("mnemosyne:thesaurophylax:portable-wrap:v1".utf8)
  private let signer: SecureEnclaveSigner

  init() throws {
    signer = try SecureEnclaveSigner(
      namespace: "site-root-delegation-v1",
      authenticationReason: "Authorize the DAS local-authority replacement receipt"
    )
  }

  func produce(
    _ presentation: DasReplacementReceiptPresentationV1,
    using ceremony: FaceIDCeremonyContext
  ) throws -> DasReplacementReceiptSubmissionV1 {
    let publicKey = try signer.publicKey(using: ceremony).compressedSEC1
    let keyID = "site-root-" + Data(SHA256.hash(data: publicKey)).hexadecimal
    guard keyID == presentation.deviceKeyID else {
      throw PlatformFailure.custodyRewrapUnavailable
    }
    let protected = try DetachedES256Cose.protectedHeaders(kid: presentation.deviceKeyID)
    let structure = try DetachedES256Cose.signatureStructure(
      protected: protected, payload: presentation.canonicalChallenge
    )
    let signature = try signer.sign(message: structure, using: ceremony)
    let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)

    var oldShared = try signer.deriveECDHSharedSecret(
      peerPublicCompressedSEC1: presentation.existingHostPublicSEC1, using: ceremony
    )
    defer { oldShared.zeroize() }
    let oldAAD = Self.aad(presentation, host: presentation.existingHostPublicSEC1)
    let oldKey = Self.wrapKey(shared: oldShared, aad: oldAAD)
    var scalar = try Self.open(presentation.encryptedRecord, key: oldKey, aad: oldAAD)
    defer { scalar.zeroize() }
    guard scalar.count == 32,
      let signingKey = try? P256.Signing.PrivateKey(rawRepresentation: scalar),
      signingKey.publicKey.compressedRepresentation == presentation.generationPublicSEC1
    else { throw PlatformFailure.custodyRewrapUnavailable }

    var freshShared = try signer.deriveECDHSharedSecret(
      peerPublicCompressedSEC1: presentation.hostPublicSEC1, using: ceremony
    )
    defer { freshShared.zeroize() }
    let freshAAD = Self.aad(presentation, host: presentation.hostPublicSEC1)
    let freshKey = Self.wrapKey(shared: freshShared, aad: freshAAD)
    let ciphertext = try Self.seal(scalar, key: freshKey, aad: freshAAD)
    return DasReplacementReceiptSubmissionV1(
      correlation: presentation.correlation.hexadecimal,
      canonicalChallenge: presentation.canonicalChallenge.hexadecimal,
      deviceKeyID: presentation.deviceKeyID,
      delegationSerial: presentation.delegationSerial,
      siteTrustDomainID: presentation.siteTrustDomainID,
      detachedCOSESign1: cose.hexadecimal,
      rewrappedCiphertext: ciphertext.hexadecimal
    )
  }

  static func aad(_ presentation: DasReplacementReceiptPresentationV1, host: Data) -> Data {
    var material = Data()
    for value in [
      Data(DasReplacementReceiptAttendedProfileV1.purpose.utf8),
      Data(presentation.siteTrustDomainID.utf8),
      Data(presentation.custodyGeneration.utf8),
      Data(presentation.deviceKeyID.utf8), host,
    ] {
      material.append(contentsOf: UInt32(value.count).bigEndianBytes)
      material.append(value)
    }
    return Data(SHA256.hash(data: material))
  }

  static func wrapKey(shared: Data, aad: Data) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: shared), salt: aad,
      info: wrapInfo, outputByteCount: 32
    )
  }

  static func open(_ value: Data, key: SymmetricKey, aad: Data) throws -> Data {
    guard (28...4_096).contains(value.count) else {
      throw PlatformFailure.custodyRewrapUnavailable
    }
    return try AES.GCM.open(AES.GCM.SealedBox(combined: value), using: key, authenticating: aad)
  }

  static func seal(_ value: Data, key: SymmetricKey, aad: Data) throws -> Data {
    guard value.count == 32,
      let combined = try AES.GCM.seal(value, using: key, authenticating: aad).combined,
      combined.count == 60
    else { throw PlatformFailure.custodyRewrapUnavailable }
    return combined
  }
}

extension Data {
  fileprivate var hexadecimal: String { map { String(format: "%02x", $0) }.joined() }

  fileprivate mutating func zeroize() {
    guard !isEmpty else { return }
    resetBytes(in: startIndex..<endIndex)
  }
}

extension FixedWidthInteger {
  fileprivate var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
}
