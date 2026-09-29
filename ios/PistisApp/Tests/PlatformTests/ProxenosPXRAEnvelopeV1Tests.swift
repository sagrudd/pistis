import CryptoKit
import Foundation
import XCTest

@testable import Pistis

final class ProxenosPXRAEnvelopeV1Tests: XCTestCase {
  func testSharedProxenosVectorIsByteForByteAccepted() throws {
    let fixtureURL = try XCTUnwrap(
      Bundle(for: Self.self).url(
        forResource: "site-root-ack-presentation-offline-v1", withExtension: "json"
      ))
    let fixture = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [String: Any]
    )
    let profile = try XCTUnwrap(fixture["profile"] as? [String: Any])
    let publicKey = try hex(
      XCTUnwrap(profile["synthetic_ed25519_public_key_hex"] as? String)
    )
    let siteUUID = "00112233-4455-6677-8899-aabbccddeeff"
    let info: [String: Any] = [
      ProxenosPXRAKeyPinV1.publicKeyInfoKey: base64URL(publicKey),
      ProxenosPXRAKeyPinV1.keyGenerationInfoKey: "1",
      ProxenosPXRAKeyPinV1.keyDigestInfoKey: base64URL(Data(SHA256.hash(data: publicKey))),
      ProxenosPXRAKeyPinV1.siteUUIDInfoKey: siteUUID,
      ProxenosPXRAKeyPinV1.purposeInfoKey: ProxenosPXRAKeyPinV1.purpose,
    ]
    let pin = try XCTUnwrap(ProxenosPXRAKeyPinV1.fromSignedProfile(info))
    let frame = try hex(XCTUnwrap(fixture["pxrp_file_hex"] as? String))
    let expectedTarget = try hex(XCTUnwrap(profile["target_id_hex"] as? String))

    let envelope = try ProxenosPXRAEnvelopeV1(
      frame: frame, pin: pin, expectedSiteUUID: siteUUID,
      expectedTargetID: expectedTarget, expectedAckGeneration: 1,
      nowUnixMilliseconds: 1_780_000_000_001
    )

    XCTAssertEqual(
      envelope.unsignedPXRA,
      try hex(
        XCTUnwrap(fixture["unsigned_pxra_hex"] as? String)
      ))
    XCTAssertEqual(envelope.presentation.siteUUIDText, siteUUID)
    XCTAssertEqual(envelope.presentation.targetID, expectedTarget)
    XCTAssertEqual(envelope.presentation.ackKeyGeneration, 1)
    XCTAssertEqual(
      Data(SHA256.hash(data: frame)).map { String(format: "%02x", $0) }.joined(),
      fixture["pxrp_file_sha256_hex"] as? String
    )
  }

  func testVerifiedEnvelopeBindsPinSiteTargetGenerationAndExpiry() throws {
    let now: UInt64 = 1_800_000_000_000
    let signer = Curve25519.Signing.PrivateKey()
    let payload = try makePXRA(now: now, expiry: now + 299_000)
    let frame = try makeEnvelope(payload, signer: signer, generation: 7)
    let pin = try ProxenosPXRAKeyPinV1(
      publicKey: signer.publicKey.rawRepresentation, generation: 7,
      siteUUID: siteUUID
    )

    let envelope = try ProxenosPXRAEnvelopeV1(
      frame: frame, pin: pin, expectedSiteUUID: siteUUID,
      expectedTargetID: targetID, expectedAckGeneration: 4,
      nowUnixMilliseconds: now
    )

    XCTAssertEqual(envelope.unsignedPXRA, payload)
    XCTAssertEqual(envelope.presentation.siteUUIDText, siteUUID)
    XCTAssertEqual(envelope.presentation.targetID, targetID)
    XCTAssertEqual(envelope.presentation.ackKeyGeneration, 4)
    XCTAssertLessThanOrEqual(frame.count, ProxenosPXRAEnvelopeV1.maximumEnvelopeBytes)
  }

  func testWrongSigningKeyAndGenerationAreRejected() throws {
    let now: UInt64 = 1_800_000_000_000
    let signer = Curve25519.Signing.PrivateKey()
    let impostor = Curve25519.Signing.PrivateKey()
    let frame = try makeEnvelope(
      makePXRA(now: now, expiry: now + 299_000), signer: signer, generation: 7
    )
    let wrongKey = try ProxenosPXRAKeyPinV1(
      publicKey: impostor.publicKey.rawRepresentation, generation: 7,
      siteUUID: siteUUID
    )
    let wrongGeneration = try ProxenosPXRAKeyPinV1(
      publicKey: signer.publicKey.rawRepresentation, generation: 8,
      siteUUID: siteUUID
    )

    XCTAssertThrowsError(try verify(frame, pin: wrongKey, now: now))
    XCTAssertThrowsError(try verify(frame, pin: wrongGeneration, now: now))
  }

  func testWrongTargetAndExpiredPresentationAreRejected() throws {
    let now: UInt64 = 1_800_000_000_000
    let signer = Curve25519.Signing.PrivateKey()
    let pin = try ProxenosPXRAKeyPinV1(
      publicKey: signer.publicKey.rawRepresentation, generation: 7,
      siteUUID: siteUUID
    )
    let payload = try makePXRA(now: now, expiry: now + 299_000)
    let frame = try makeEnvelope(payload, signer: signer, generation: 7)

    XCTAssertThrowsError(
      try ProxenosPXRAEnvelopeV1(
        frame: frame, pin: pin, expectedSiteUUID: siteUUID,
        expectedTargetID: Data(repeating: 0x2f, count: 32),
        expectedAckGeneration: 4, nowUnixMilliseconds: now
      ))

    let expired = try makeEnvelope(
      makePXRA(now: now - 300_001, expiry: now - 1), signer: signer, generation: 7
    )
    XCTAssertThrowsError(try verify(expired, pin: pin, now: now))
  }

  func testNoPinAndFileSuppliedKeyCannotEnableVerification() throws {
    let now: UInt64 = 1_800_000_000_000
    let signer = Curve25519.Signing.PrivateKey()
    let frame = try makeEnvelope(
      makePXRA(now: now, expiry: now + 299_000), signer: signer, generation: 7
    )
    XCTAssertNil(ProxenosPXRAKeyPinV1.fromSignedProfile([:]))
    XCTAssertNil(
      ProxenosPXRAKeyPinV1.fromSignedProfile([
        ProxenosPXRAKeyPinV1.publicKeyInfoKey: "",
        ProxenosPXRAKeyPinV1.keyGenerationInfoKey: "7",
        ProxenosPXRAKeyPinV1.keyDigestInfoKey: "",
      ]))
    XCTAssertThrowsError(try verify(frame, pin: nil, now: now))

    // Appending a file-supplied public key is trailing data, not a pin.
    XCTAssertThrowsError(
      try verify(
        frame + signer.publicKey.rawRepresentation,
        pin: try .init(
          publicKey: signer.publicKey.rawRepresentation, generation: 7,
          siteUUID: siteUUID
        ), now: now))
  }

  func testOfflineVerifierRejectsTruncationTrailingBytesAndBadMagic() throws {
    let now: UInt64 = 1_800_000_000_000
    let signer = Curve25519.Signing.PrivateKey()
    let pin = try ProxenosPXRAKeyPinV1(
      publicKey: signer.publicKey.rawRepresentation, generation: 7,
      siteUUID: siteUUID
    )
    let frame = try makeEnvelope(
      makePXRA(now: now, expiry: now + 299_000), signer: signer, generation: 7
    )
    for malformed in [
      Data(frame.dropLast()), frame + Data([0]),
      Data("NOTPXRP".utf8) + frame.dropFirst(7),
    ] {
      XCTAssertThrowsError(try verify(malformed, pin: pin, now: now))
    }
  }

  func testReplayGuardAllowsOneImportThenRejectsTheExactSameEnvelope() throws {
    var guardState = ProxenosPXRAReplayGuardV1()
    let exactEnvelope = Data("synthetic PXRP fixture".utf8)
    XCTAssertNoThrow(try guardState.consume(exactEnvelope))
    XCTAssertThrowsError(try guardState.consume(exactEnvelope))
  }

  func testMissingOriginalPXRBAuthorizationStopsBeforeFaceID() async throws {
    let now: UInt64 = 1_800_000_000_000
    let signer = Curve25519.Signing.PrivateKey()
    let ackKey = P256.Signing.PrivateKey()
    let pin = try ProxenosPXRAKeyPinV1(
      publicKey: signer.publicKey.rawRepresentation,
      generation: 7,
      siteUUID: siteUUID
    )
    let frame = try makeEnvelope(
      makePXRA(now: now, expiry: now + 299_000), signer: signer, generation: 7
    )
    let registration = SiteRootConvergenceAckRecordV2(
      siteUUID: siteUUID,
      targetIDB64URL: base64URL(targetID),
      ackPublicKeyB64URL: base64URL(ackKey.publicKey.compressedRepresentation),
      generation: 4
    )

    do {
      _ = try await OfflineSiteRootAcknowledgementV1.sign(
        frame: frame,
        pin: pin,
        registration: registration,
        trustPolicy: .bootstrapLeafSPKI(Data(repeating: 0x51, count: 32)),
        authorizationVerifier: DenyOriginalPXRBVerifier(),
        nowUnixMilliseconds: now,
        authenticate: {
          XCTFail("Face ID must not run without original PXRB evidence")
          throw PlatformFailure.userVerificationCancelled
        }
      )
      XCTFail("Missing PXRB evidence must reject offline signing")
    } catch let failure as PlatformFailure {
      XCTAssertEqual(failure, .siteRootAuthorityUnavailable)
    }
  }

  func testContinuityProbeSignsOnlyItsFreshDomainSeparatedChallenge() throws {
    let privateKey = P256.Signing.PrivateKey()
    let preUpdatePublicKey = privateKey.publicKey.compressedRepresentation
    let probe = try SiteRootAckContinuityProbeV1(
      siteUUID: siteUUID, generation: 4, nonce: Data(repeating: 0x43, count: 32)
    )
    let signature = try probe.sign(
      using: { try privateKey.signature(for: $0).rawRepresentation },
      preUpdatePublicKey: preUpdatePublicKey,
      preUpdateGeneration: 4
    )
    XCTAssertTrue(
      probe.verify(
        signature: signature, preUpdatePublicKey: preUpdatePublicKey,
        preUpdateGeneration: 4
      ))
    XCTAssertFalse(
      probe.verify(
        signature: signature, preUpdatePublicKey: privateKey.publicKey.compressedRepresentation,
        preUpdateGeneration: 5
      ))
    XCTAssertTrue(probe.message.starts(with: SiteRootAckContinuityProbeV1.domain))
    XCTAssertThrowsError(
      try probe.sign(
        using: { _ in try P256.Signing.PrivateKey().signature(for: Data([0])).rawRepresentation },
        preUpdatePublicKey: preUpdatePublicKey,
        preUpdateGeneration: 4
      ))
  }

  func testAppAttestContinuityChallengeIsSeparatelyDomainSeparated() throws {
    let nonce = Data(repeating: 0x37, count: 32)
    let challenge = try SiteRootAppAttestContinuityProbeV1.challenge(
      siteUUID: siteUUID, nonce: nonce
    )
    XCTAssertTrue(challenge.starts(with: SiteRootAppAttestContinuityProbeV1.domain))
    XCTAssertFalse(challenge.starts(with: SiteRootAckContinuityProbeV1.domain))
    XCTAssertThrowsError(
      try SiteRootAppAttestContinuityProbeV1.challenge(
        siteUUID: siteUUID, nonce: Data(repeating: 0, count: 32)
      ))
  }

  private func verify(
    _ frame: Data,
    pin: ProxenosPXRAKeyPinV1?,
    now: UInt64
  ) throws -> ProxenosPXRAEnvelopeV1 {
    try ProxenosPXRAEnvelopeV1(
      frame: frame, pin: pin, expectedSiteUUID: siteUUID,
      expectedTargetID: targetID, expectedAckGeneration: 4,
      nowUnixMilliseconds: now
    )
  }

  func testAppAttestContinuityUsesExistingReferenceWithoutReplacingIt() async throws {
    let keyBytes = Data(repeating: 0x71, count: 32)
    let keyID = keyBytes.base64EncodedString()
    let fakeService = ContinuityAppAttestService()
    let keyStore = ContinuityAppAttestKeyStore(keyID: keyID)
    let client = AppleAppAttestClient(service: fakeService, keyIDStore: keyStore)
    let result = try await SiteRootAppAttestContinuityProbeV1.assertion(
      client: client, siteUUID: siteUUID, preUpdateKeyID: keyID
    )

    XCTAssertEqual(result.keyID, keyID)
    XCTAssertEqual(fakeService.assertionKeyID, keyID)
    XCTAssertEqual(fakeService.assertionHash, Data(SHA256.hash(data: result.challenge)))
    XCTAssertEqual(fakeService.assertionCount, 1)
    XCTAssertEqual(keyStore.savedKeyIDs, 0)
    XCTAssertTrue(result.challenge.starts(with: SiteRootAppAttestContinuityProbeV1.domain))
  }

  private func makeEnvelope(
    _ payload: Data,
    signer: Curve25519.Signing.PrivateKey,
    generation: UInt64
  ) throws -> Data {
    let protected = protectedHeaders(generation: generation)
    let structure =
      Data([0x84]) + cborText("Signature1") + cborBytes(protected)
      + Data([0x40]) + cborBytes(payload)
    let signature = try signer.signature(for: structure)
    let cose =
      Data([0x84]) + cborBytes(protected) + Data([0xa0, 0xf6])
      + cborBytes(signature)
    return Data("PXRP/v1".utf8)
      + Data([
        1, UInt8(payload.count >> 8),
        UInt8(truncatingIfNeeded: payload.count),
      ])
      + payload + cose
  }

  private func makePXRA(now: UInt64, expiry: UInt64) throws -> Data {
    var data = Data("PXRA/v2".utf8) + Data([1])
    data.append(field(0x01, uuid(siteUUID)))
    data.append(field(0x02, targetID))
    data.append(field(0x03, Data([1])))
    data.append(field(0x04, Data(repeating: 0x52, count: 16)))
    data.append(field(0x05, u64(3)))
    data.append(field(0x06, u64(2)))
    data.append(field(0x07, Data(repeating: 0x64, count: 32)))
    data.append(field(0x08, Data([1])))
    data.append(field(0x09, Data()))
    data.append(field(0x0a, u64(now - 1)))
    data.append(field(0x0b, u64(expiry)))
    data.append(field(0x0c, Data(repeating: 0x75, count: 32)))
    data.append(field(0x0d, u64(4)))
    return data
  }

  private func field(_ tag: UInt8, _ value: Data) -> Data {
    Data([tag, UInt8(value.count >> 8), UInt8(truncatingIfNeeded: value.count)]) + value
  }

  private func u64(_ value: UInt64) -> Data {
    Data((0..<8).map { UInt8(truncatingIfNeeded: value >> UInt64(56 - 8 * $0)) })
  }

  private func uuid(_ value: String) -> Data {
    Data(value.replacingOccurrences(of: "-", with: "").chunkedHexBytes)
  }

  private func protectedHeaders(generation: UInt64) -> Data {
    let generationBytes = u64(generation)
    return Data([0xa3, 1, 0x27, 3]) + cborText(ProxenosPXRAEnvelopeV1.contentType)
      + Data([4]) + cborBytes(generationBytes)
  }

  private func cborText(_ text: String) -> Data {
    let value = Data(text.utf8)
    guard value.count > 23 else { return Data([0x60 | UInt8(value.count)]) + value }
    return Data([0x78, UInt8(value.count)]) + value
  }

  private func cborBytes(_ value: Data) -> Data {
    guard value.count <= 23 else { return Data([0x58, UInt8(value.count)]) + value }
    return Data([0x40 | UInt8(value.count)]) + value
  }

  private func hex(_ value: String) throws -> Data {
    let bytes = Array(value.utf8)
    guard bytes.count.isMultiple(of: 2) else { throw PlatformFailure.invalidConfiguration }
    var output = Data()
    for offset in stride(from: 0, to: bytes.count, by: 2) {
      guard let byte = UInt8(String(decoding: bytes[offset..<offset + 2], as: UTF8.self), radix: 16)
      else { throw PlatformFailure.invalidConfiguration }
      output.append(byte)
    }
    return output
  }

  private func base64URL(_ value: Data) -> String {
    value.base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private var siteUUID: String { "10213243-5465-7687-98a9-bacbdcedfe0f" }
  private var targetID: Data { Data(repeating: 0x32, count: 32) }
}

private struct DenyOriginalPXRBVerifier: SiteRootAckOfflineAuthorizationVerifying {
  func verifyOriginalAuthorizationAndMutation(
    for _: UnsignedSiteRootConvergenceAssertionV2
  ) throws -> Bool { false }
}

private final class ContinuityAppAttestService: AppleAppAttestServicing, @unchecked Sendable {
  let isSupported = true
  private(set) var assertionKeyID: String?
  private(set) var assertionHash: Data?
  private(set) var assertionCount = 0

  func generateKey() async throws -> String { throw PlatformFailure.appAttestKeyCreationFailed }

  func attestKey(_: String, clientDataHash _: Data) async throws -> Data {
    throw PlatformFailure.appAttestAttestationFailed
  }

  func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
    assertionKeyID = keyID
    assertionHash = clientDataHash
    assertionCount += 1
    return Data(repeating: 0x4a, count: 64)
  }
}

private final class ContinuityAppAttestKeyStore: AppleAppAttestKeyIDStoring, @unchecked Sendable {
  let keyID: String
  private(set) var savedKeyIDs = 0

  init(keyID: String) { self.keyID = keyID }

  func loadKeyID() -> String? { keyID }

  func saveKeyID(_: String) throws { savedKeyIDs += 1 }
}

extension String {
  fileprivate var chunkedHexBytes: [UInt8] {
    stride(from: 0, to: count, by: 2).compactMap { index in
      let start = self.index(startIndex, offsetBy: index)
      let end = self.index(start, offsetBy: 2)
      return UInt8(self[start..<end], radix: 16)
    }
  }
}
