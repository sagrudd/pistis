import CryptoKit
import XCTest

@testable import Pistis

final class DasReplacementReceiptAttendedCeremonyV1Tests: XCTestCase {
  override func tearDown() {
    DasReplacementURLProtocol.reset()
    super.tearDown()
  }

  func testBeginIsByteExactCanonicalJCS() throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    XCTAssertEqual(
      try encoder.encode(DasReplacementReceiptBeginV1()),
      Data(#"{"schema":"monas.das-replacement-receipt-begin.v1"}"#.utf8)
    )
  }

  func testPresentationAcceptsOnlyExactCanonicalContract() throws {
    let fixture = try Fixture()
    let presentation = try fixture.decode()
    XCTAssertEqual(presentation.correlation, Data(repeating: 1, count: 32))
    XCTAssertEqual(
      presentation.custodyGeneration,
      "pistis-first-device-authority-cd624cfa14a30f79373b20e2b1a1db83"
    )
    XCTAssertEqual(presentation.hostPublicSEC1, fixture.freshPublic)
    XCTAssertEqual(presentation.existingHostPublicSEC1, fixture.existingPublic)
    XCTAssertEqual(
      try DasReplacementReceiptPresentationV1.reconstructChallenge(presentation),
      presentation.canonicalChallenge
    )

    for key in fixture.object.keys {
      var changed = fixture.object
      changed.removeValue(forKey: key)
      XCTAssertThrowsError(try fixture.decode(changed), "accepted missing \(key)")
    }
    var unknown = fixture.object
    unknown["serverHint"] = "forbidden"
    XCTAssertThrowsError(try fixture.decode(unknown))
  }

  func testPresentationDeniesAlternateRoutesPurposeAndNoncanonicalHex() throws {
    let fixture = try Fixture()
    for (key, value) in [
      ("purpose", "das-replacement"),
      ("submissionPath", "/v1/pistis/das-replacement-receipt/submission"),
      ("custodyGeneration", "site root 1"),
    ] {
      var changed = fixture.object
      changed[key] = value
      XCTAssertThrowsError(try fixture.decode(changed), "accepted changed \(key)")
    }
    var uppercase = fixture.object
    uppercase["correlation"] = String(repeating: "AA", count: 32)
    XCTAssertThrowsError(try fixture.decode(uppercase))
  }

  func testPresentationDeniesChallengeDriftDigestDriftAndExpiredLifetime() throws {
    let fixture = try Fixture()
    var challenge = fixture.object
    challenge["canonicalChallenge"] = Data(repeating: 2, count: 64).hex
    XCTAssertThrowsError(try fixture.decode(challenge))

    var digest = fixture.object
    digest["encryptedRecordSha256"] = Data(repeating: 3, count: 32).hex
    XCTAssertThrowsError(try fixture.decode(digest))

    var expired = fixture.object
    expired["expiresAtUnixSeconds"] = UInt64(99)
    XCTAssertThrowsError(try fixture.decode(expired))

    var excessive = fixture.object
    excessive["expiresAtUnixSeconds"] = UInt64(401)
    XCTAssertThrowsError(try fixture.decode(excessive))
  }

  func testSubmissionUsesExactCamelCaseLowerHexFields() throws {
    let submission = DasReplacementReceiptSubmissionV1(
      correlation: Data(repeating: 1, count: 32).hex,
      canonicalChallenge: Data([1, 2]).hex,
      deviceKeyID: "site-root-device-1",
      delegationSerial: "delegation-1",
      siteTrustDomainID: "site-1",
      detachedCOSESign1: Data([3, 4]).hex,
      rewrappedCiphertext: Data([5, 6]).hex
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let encoded = try encoder.encode(submission)
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: encoded)
        as? [String: String]
    )
    XCTAssertEqual(
      Set(object.keys),
      [
        "schema", "correlation", "canonicalChallenge", "deviceKeyId",
        "delegationSerial", "siteTrustDomainId", "purpose",
        "detachedCoseSign1", "rewrappedCiphertext",
      ])
    XCTAssertEqual(object["schema"], DasReplacementReceiptAttendedProfileV1.submissionSchema)
    XCTAssertEqual(object["purpose"], DasReplacementReceiptAttendedProfileV1.purpose)
    XCTAssertEqual(
      String(decoding: encoded, as: UTF8.self),
      #"{"canonicalChallenge":"0102","correlation":"0101010101010101010101010101010101010101010101010101010101010101","delegationSerial":"delegation-1","detachedCoseSign1":"0304","deviceKeyId":"site-root-device-1","purpose":"das_local_authority_replacement_receipt","rewrappedCiphertext":"0506","schema":"monas.das-replacement-receipt-submission.v1","siteTrustDomainId":"site-1"}"#
    )
  }

  func testAcceptanceRequiresReceiptSignedAndExactCorrelation() throws {
    let correlation = Data(repeating: 1, count: 32)
    let valid: [String: Any] = [
      "schema": DasReplacementReceiptAttendedProfileV1.acceptedSchema,
      "correlation": correlation.hex,
      "purpose": DasReplacementReceiptAttendedProfileV1.purpose,
      "state": "receipt_signed",
    ]
    XCTAssertNoThrow(
      try DasReplacementReceiptAcceptedV1(
        data: JSONSerialization.data(withJSONObject: valid),
        expectedCorrelation: correlation
      ))
    for (key, value) in [
      ("state", "accepted"), ("purpose", "other"),
      ("correlation", Data(repeating: 2, count: 32).hex),
    ] {
      var changed = valid
      changed[key] = value
      XCTAssertThrowsError(
        try DasReplacementReceiptAcceptedV1(
          data: JSONSerialization.data(withJSONObject: changed),
          expectedCorrelation: correlation
        ))
    }
  }

  func testPurposeBoundAADDistinguishesOldAndFreshHost() throws {
    let fixture = try Fixture()
    let presentation = try fixture.decode()
    let old = SecureEnclaveDasReplacementReceiptProducerV1.aad(
      presentation, host: presentation.existingHostPublicSEC1
    )
    let fresh = SecureEnclaveDasReplacementReceiptProducerV1.aad(
      presentation, host: presentation.hostPublicSEC1
    )
    XCTAssertNotEqual(old, fresh)
    let key = SymmetricKey(data: Data(repeating: 7, count: 32))
    let scalar = Data(repeating: 8, count: 32)
    let ciphertext = try SecureEnclaveDasReplacementReceiptProducerV1.seal(
      scalar, key: key, aad: fresh
    )
    XCTAssertEqual(
      try SecureEnclaveDasReplacementReceiptProducerV1.open(
        ciphertext, key: key, aad: fresh
      ), scalar
    )
    XCTAssertThrowsError(
      try SecureEnclaveDasReplacementReceiptProducerV1.open(
        ciphertext, key: key, aad: old
      ))
  }

  func testPresentationTransportUsesOnlyFixedCanonicalPost() async throws {
    let fixture = try Fixture()
    DasReplacementURLProtocol.responseData = try JSONSerialization.data(
      withJSONObject: fixture.object
    )
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [DasReplacementURLProtocol.self]
    let transport = try MonasAppAttestTransport(
      authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
      expectedSPKISHA256: Data(repeating: 9, count: 32),
      configuration: configuration
    )
    _ = try await transport.beginDasReplacementReceiptV1(nowUnixSeconds: 100)
    let request = try XCTUnwrap(DasReplacementURLProtocol.receivedRequest)
    XCTAssertEqual(request.httpMethod, "POST")
    XCTAssertEqual(
      request.url?.path,
      DasReplacementReceiptAttendedProfileV1.presentationPath
    )
    XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
    XCTAssertEqual(
      request.httpBody,
      Data(#"{"schema":"monas.das-replacement-receipt-begin.v1"}"#.utf8)
    )
    XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
    XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
  }
}

private struct Fixture {
  let freshPublic: Data
  let existingPublic: Data
  let object: [String: Any]

  init() throws {
    freshPublic = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
    existingPublic = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
    let generationPublic = P256.Signing.PrivateKey().publicKey.compressedRepresentation
    let encryptedRecord = Data(repeating: 0xAB, count: 60)
    let digest = Data(SHA256.hash(data: encryptedRecord))
    let expiresAt = UInt64(200)
    let custodyGeneration =
      "pistis-first-device-authority-cd624cfa14a30f79373b20e2b1a1db83"
    var challenge = DasReplacementReceiptAttendedProfileV1.challengeSchema
    for (tag, field) in [
      (UInt8(1), Data([4])), (2, Data("site-1".utf8)),
      (3, Data(custodyGeneration.utf8)),
      (4, Data("site-root-device-1".utf8)), (5, generationPublic),
      (6, digest), (7, Data(UInt64(1).bytes)),
      (8, Data("delegation-1".utf8)), (9, Data(expiresAt.bytes)),
      (10, freshPublic),
    ] {
      challenge.append(tag)
      challenge.append(contentsOf: UInt16(field.count).bytes)
      challenge.append(field)
    }
    object = [
      "schema": DasReplacementReceiptAttendedProfileV1.presentationSchema,
      "purpose": DasReplacementReceiptAttendedProfileV1.purpose,
      "correlation": Data(repeating: 1, count: 32).hex,
      "canonicalChallenge": challenge.hex,
      "hostPublicSec1": freshPublic.hex,
      "existingHostPublicSec1": existingPublic.hex,
      "siteTrustDomainId": "site-1",
      "custodyGeneration": custodyGeneration,
      "deviceKeyId": "site-root-device-1",
      "generationPublicSec1": generationPublic.hex,
      "encryptedRecordSha256": digest.hex,
      "revocationGeneration": UInt64(1),
      "delegationSerial": "delegation-1",
      "expiresAtUnixSeconds": expiresAt,
      "encryptedRecord": encryptedRecord.hex,
      "submissionPath": DasReplacementReceiptAttendedProfileV1.submissionPath,
    ]
  }

  func decode(_ value: [String: Any]? = nil) throws -> DasReplacementReceiptPresentationV1 {
    try DasReplacementReceiptPresentationV1(
      data: JSONSerialization.data(withJSONObject: value ?? object), nowUnixSeconds: 100
    )
  }
}

extension Data {
  fileprivate var hex: String { map { String(format: "%02x", $0) }.joined() }
}

extension FixedWidthInteger {
  fileprivate var bytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
}

private final class DasReplacementURLProtocol: URLProtocol, @unchecked Sendable {
  private static let lock = NSLock()
  nonisolated(unsafe) static var responseData = Data()
  nonisolated(unsafe) static var receivedRequest: URLRequest?

  override class func canInit(with _: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

  override func startLoading() {
    var captured = request
    if captured.httpBody == nil, let stream = captured.httpBodyStream {
      stream.open()
      defer { stream.close() }
      var body = Data()
      var buffer = [UInt8](repeating: 0, count: 1_024)
      while stream.hasBytesAvailable {
        let count = stream.read(&buffer, maxLength: buffer.count)
        guard count > 0 else { break }
        body.append(buffer, count: count)
      }
      captured.httpBody = body
    }
    Self.lock.lock()
    Self.receivedRequest = captured
    let data = Self.responseData
    Self.lock.unlock()
    let response = HTTPURLResponse(
      url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
      headerFields: [
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
      ]
    )!
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(self, didLoad: data)
    client?.urlProtocolDidFinishLoading(self)
  }

  override func stopLoading() {}

  static func reset() {
    lock.lock()
    defer { lock.unlock() }
    responseData = Data()
    receivedRequest = nil
  }
}
