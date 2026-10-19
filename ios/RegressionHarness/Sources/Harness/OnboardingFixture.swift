import Crypto
import Foundation
import PistisCore

/// Public protocol vectors and software keys only; never a production authority.
@MainActor
public final class OnboardingFixture {
  public static let now = Date(timeIntervalSince1970: 1_700_000_100)
  public let qr: String
  public let configurationDigest: Data
  let deviceKey = P256.Signing.PrivateKey()
  let installationKey = P256.Signing.PrivateKey()
  private let receiptKey: P256.Signing.PrivateKey

  public init() throws {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .appendingPathComponent(
        "../../../../fixtures/protocol-v4/first-device/presentation-positive.json"
      ).standardizedFileURL
    let input = try FileHandle(forReadingFrom: url)
    defer { try? input.close() }
    let bytes = try input.read(upToCount: 16_385) ?? Data()
    guard bytes.count <= 16_384 else { throw OnboardingFailure.fixture }
    let vector = try JSONDecoder().decode(PresentationVector.self, from: bytes)
    qr = vector.qrText
    configurationDigest = try decodeHex(vector.configurationDigestHex)
    // Scalar 2 is the existing public receipt test vector, not a retained key.
    receiptKey = try P256.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0, count: 31) + Data([2]))
    _ = try presentation(qr: qr, digest: configurationDigest, now: Self.now)
  }

  func presentation(qr: String, digest: Data, now: Date) throws
    -> VerifiedFirstDevicePresentation
  {
    try FirstDevicePresentationV4.verify(
      qrText: qr, expectedAppConfigurationDigest: digest, now: now)
  }

  func binding(_ presentation: VerifiedFirstDevicePresentation) throws -> EnrolmentBindingInput {
    let publicKey = deviceKey.publicKey.compressedRepresentation
    return try EnrolmentBindingInput(
      operationID: Data(repeating: 0x10, count: 16), presentation: presentation,
      numericSubject: 123_456_789, devicePublicKey: publicKey,
      deviceKeyID: fixtureKeyID(publicKey), policyGeneration: 7,
      authorityChallenge: Data(repeating: 0x66, count: 32),
      authorityChallengeExpiresAtMilliseconds: 1_700_000_240_000)
  }

  func registration(_ binding: EnrolmentBindingInput) throws -> Data {
    try EnrolledFixture.sign(
      EnrolmentBindingV1.payload(binding), keyID: binding.deviceKeyID, using: deviceKey)
  }

  func receipt(binding: EnrolmentBindingInput, registration: Data, fault: OnboardingFault) throws
    -> Data
  {
    let presentation = binding.presentation
    let publicKey = installationKey.publicKey.compressedRepresentation
    var payload = Data([0xb8, 0x1b])
    func field(_ key: UInt64, _ value: Data) {
      payload += FixtureCBOR.uint(key) + value
    }
    field(0, FixtureCBOR.uint(2))
    field(1, FixtureCBOR.text("pistis.mobile-enrolment-receipt.v2"))
    field(2, FixtureCBOR.uint(1_700_000_090_000))
    field(3, FixtureCBOR.uint(fault == .expiredReceipt ? 1_700_000_095_000 : 1_700_000_290_000))
    field(4, FixtureCBOR.bytes(Data(repeating: 0x71, count: 16)))
    field(5, FixtureCBOR.bytes(presentation.installationID))
    field(6, FixtureCBOR.text(presentation.installationName))
    field(7, FixtureCBOR.text(presentation.audience))
    field(8, FixtureCBOR.bytes(fixtureKeyID(publicKey)))
    field(9, FixtureCBOR.bytes(publicKey))
    field(10, Data([0x26]))
    field(11, FixtureCBOR.bytes(Data(SHA256.hash(data: publicKey))))
    let authorityKeyID = fixtureKeyID(receiptKey.publicKey.compressedRepresentation)
    field(12, FixtureCBOR.bytes(authorityKeyID))
    field(13, FixtureCBOR.bytes(presentation.principalID))
    field(14, FixtureCBOR.bytes(Data(repeating: 0x72, count: 16)))
    field(15, FixtureCBOR.bytes(Data(repeating: 0x73, count: 16)))
    field(
      16,
      FixtureCBOR.bytes(
        fault == .wrongDevice ? Data(repeating: 0xff, count: 32) : binding.deviceKeyID))
    field(17, FixtureCBOR.bytes(binding.devicePublicKey))
    field(18, Data([0x26]))
    field(19, FixtureCBOR.text("secure-enclave-biometry-current-set"))
    field(20, FixtureCBOR.bytes(Data(SHA256.hash(data: registration))))
    field(21, FixtureCBOR.uint(binding.policyGeneration))
    field(22, FixtureCBOR.uint(1))
    field(23, Data([fault == .inactiveReceipt ? 0xf4 : 0xf5]))
    field(24, FixtureCBOR.uint(1_700_000_090_000))
    field(25, Data([0x81]) + FixtureCBOR.text("pistis.example.test"))
    field(
      26,
      Data([0x83]) + FixtureCBOR.text("dasobjectstore")
        + FixtureCBOR.text("jenkins") + FixtureCBOR.text("propylaion"))
    return try EnrolledFixture.sign(
      payload, keyID: authorityKeyID,
      using: fault == .wrongReceiptSigner ? deviceKey : receiptKey)
  }
}

private struct PresentationVector: Decodable {
  let qrText: String
  let configurationDigestHex: String

  enum CodingKeys: String, CodingKey {
    case qrText = "qr_text"
    case configurationDigestHex = "app_configuration_digest_hex"
  }
}

private func fixtureKeyID(_ publicKey: Data) -> Data {
  Data(SHA256.hash(data: Data("pistis:key-id:v1\0".utf8) + publicKey))
}

private func decodeHex(_ text: String) throws -> Data {
  guard text.utf8.count == 64 else { throw OnboardingFailure.fixture }
  var result = Data()
  var index = text.startIndex
  while index < text.endIndex {
    let end = text.index(index, offsetBy: 2)
    guard let byte = UInt8(text[index..<end], radix: 16) else { throw OnboardingFailure.fixture }
    result.append(byte)
    index = end
  }
  return result
}
