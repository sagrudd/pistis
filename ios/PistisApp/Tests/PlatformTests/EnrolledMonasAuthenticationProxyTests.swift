import CryptoKit
import Foundation
import PistisCore
import XCTest

@testable import Pistis

/// Offline development proxy for the ordinary Monas login QR on an already
/// enrolled installation. Every hardware result and authority callback here
/// is synthetic and remains inside the XCTest process.
final class EnrolledMonasAuthenticationProxyTests: XCTestCase {
  private let nowMilliseconds: UInt64 = 1_700_000_060_000
  private let installationID = Data(repeating: 0x22, count: 16)

  @MainActor
  func testEnrolledLoginCompletesOneCallbackAndPreservesInstalledState() async throws {
    let fixture = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "propylaion",
      authorisedAudiences: ["propylaion"]
    )
    let store = ProxyEnrollmentStore(fixture.enrollment)
    let before = await store.activeEnrollment()
    let signer = TestOnlySecureEnclave()
    let faceID = TestOnlyFaceID(approved: true)
    let challenge = try await ProductionChallengeVerifier.verify(
      qrText: fixture.qr,
      trustRepository: store,
      expectedExternalIdentityID: fixture.externalIdentityID,
      now: Date(timeIntervalSince1970: Double(nowMilliseconds) / 1_000)
    )
    XCTAssertEqual(challenge.installationID, installationID)
    XCTAssertEqual(challenge.audience, "propylaion")
    XCTAssertEqual(challenge.expiresAtMilliseconds, nowMilliseconds + 60_000)

    XCTAssertTrue(faceID.evaluate())
    let payload = try AuthenticationResponseEncoder.payload(
      challenge: challenge,
      context: fixture.enrollment.responseContext,
      decision: .approved,
      issuedAtMilliseconds: nowMilliseconds,
      userVerifiedAtMilliseconds: nowMilliseconds
    )
    let response = try signer.sign(
      payload: payload,
      deviceKeyID: fixture.enrollment.responseContext.deviceKeyID
    )
    var handoff = TestMonasLoginCallback(
      audience: "propylaion",
      successPath: "/home",
      browserCapability: "test-only-one-use-browser-capability",
      expectedPayload: payload,
      expectedDeviceKeyID: fixture.enrollment.responseContext.deviceKeyID,
      devicePublicKey: signer.publicKey
    )

    try handoff.submit(response, for: challenge, nowMilliseconds: nowMilliseconds)
    XCTAssertEqual(handoff.status, .completed)
    XCTAssertEqual(
      try handoff.finalize(browserCapability: handoff.testCapability),
      TestMonasSession(audience: "propylaion", successPath: "/home")
    )
    XCTAssertThrowsError(try handoff.finalize(browserCapability: handoff.testCapability))
    XCTAssertThrowsError(
      try handoff.submit(response, for: challenge, nowMilliseconds: nowMilliseconds)
    )

    let after = await store.activeEnrollment()
    let installCount = await store.installCount
    let revokeCount = await store.revokeCount
    XCTAssertEqual(after, before)
    XCTAssertEqual(installCount, 0)
    XCTAssertEqual(revokeCount, 0)
    XCTAssertEqual(faceID.promptCount, 1)
  }

  @MainActor
  func testMonasV3SubmitHintUsesProductionVerifierAndRejectsRouteSubstitution() async throws {
    let submitURL = try XCTUnwrap(
      URL(
        string:
          "https://192.168.0.193:8443/auth/pistis/v3/submit?challenge_id=66666666-6666-6666-6666-666666666666"
      )
    )
    let fixture = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "propylaion",
      authorisedAudiences: ["propylaion"],
      submitEndpoint: submitURL.absoluteString
    )
    let store = ProxyEnrollmentStore(fixture.enrollment)
    let challenge = try await ProductionChallengeVerifier.verify(
      qrText: fixture.qr,
      trustRepository: store,
      expectedExternalIdentityID: fixture.externalIdentityID,
      now: Date(timeIntervalSince1970: Double(nowMilliseconds) / 1_000)
    )
    XCTAssertEqual(challenge.endpointHints, [submitURL])
    XCTAssertEqual(challenge.challengeID, Data(repeating: 0x66, count: 16))

    let payload = try AuthenticationResponseEncoder.payload(
      challenge: challenge,
      context: fixture.enrollment.responseContext,
      decision: .approved,
      issuedAtMilliseconds: nowMilliseconds,
      userVerifiedAtMilliseconds: nowMilliseconds
    )
    let signer = TestOnlySecureEnclave()
    let response = try signer.sign(
      payload: payload,
      deviceKeyID: fixture.enrollment.responseContext.deviceKeyID
    )
    var authority = TestMonasLoginCallback(
      audience: "propylaion",
      successPath: "/home",
      browserCapability: "test-only-v3-browser-capability",
      expectedPayload: payload,
      expectedDeviceKeyID: fixture.enrollment.responseContext.deviceKeyID,
      devicePublicKey: signer.publicKey,
      expectedSubmitURL: submitURL
    )

    let substitutedURL = try XCTUnwrap(
      URL(
        string:
          "https://192.168.0.193:8443/auth/pistis/v2/submit?challenge_id=66666666-6666-6666-6666-666666666666"
      )
    )
    XCTAssertThrowsError(
      try authority.submit(
        response,
        for: challenge,
        nowMilliseconds: nowMilliseconds,
        to: substitutedURL
      )
    )
    XCTAssertEqual(authority.status, .pending)

    try authority.submit(
      response,
      for: challenge,
      nowMilliseconds: nowMilliseconds,
      to: submitURL
    )
    XCTAssertEqual(authority.status, .completed)
    XCTAssertEqual(
      try authority.finalize(browserCapability: authority.testCapability),
      TestMonasSession(audience: "propylaion", successPath: "/home")
    )
    XCTAssertThrowsError(try authority.finalize(browserCapability: authority.testCapability))
  }

  func testExpiredAndMisbindingChallengesFailBeforeFaceID() async throws {
    let now = Date(timeIntervalSince1970: Double(nowMilliseconds) / 1_000)
    let expired = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "propylaion",
      authorisedAudiences: ["propylaion"],
      expiresAtMilliseconds: nowMilliseconds
    )
    let wrongInstallation = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "propylaion",
      authorisedAudiences: ["propylaion"],
      challengeInstallationID: Data(repeating: 0x99, count: 16)
    )
    let wrongAudience = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "jenkins",
      authorisedAudiences: ["propylaion"]
    )
    let store = ProxyEnrollmentStore(expired.enrollment)
    let faceID = TestOnlyFaceID(approved: true)

    await assertChallengeRejected(
      expired.qr,
      store: store,
      faceID: faceID,
      now: now,
      expected: .expired
    )
    await assertChallengeRejected(
      wrongInstallation.qr,
      store: store,
      faceID: faceID,
      now: now,
      expected: .unknownInstallation
    )
    await assertChallengeRejected(
      wrongAudience.qr,
      store: store,
      faceID: faceID,
      now: now,
      expected: .wrongAudience
    )
    XCTAssertEqual(faceID.promptCount, 0)
  }

  func testCallbackCannotFinalizePendingOrUseAnotherBrowserCapability() async throws {
    let fixture = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "propylaion",
      authorisedAudiences: ["propylaion"]
    )
    let store = ProxyEnrollmentStore(fixture.enrollment)
    let challenge = try await ProductionChallengeVerifier.verify(
      qrText: fixture.qr,
      trustRepository: store,
      expectedExternalIdentityID: fixture.externalIdentityID,
      now: Date(timeIntervalSince1970: Double(nowMilliseconds) / 1_000)
    )
    let payload = try AuthenticationResponseEncoder.payload(
      challenge: challenge,
      context: fixture.enrollment.responseContext,
      decision: .approved,
      issuedAtMilliseconds: nowMilliseconds,
      userVerifiedAtMilliseconds: nowMilliseconds
    )
    let signer = TestOnlySecureEnclave()
    let response = try signer.sign(
      payload: payload,
      deviceKeyID: fixture.enrollment.responseContext.deviceKeyID
    )
    var handoff = TestMonasLoginCallback(
      audience: "propylaion",
      successPath: "/home",
      browserCapability: "test-only-one-use-browser-capability",
      expectedPayload: payload,
      expectedDeviceKeyID: fixture.enrollment.responseContext.deviceKeyID,
      devicePublicKey: signer.publicKey
    )

    XCTAssertThrowsError(try handoff.finalize(browserCapability: handoff.testCapability))
    XCTAssertEqual(handoff.status, .pending)

    try handoff.submit(response, for: challenge, nowMilliseconds: nowMilliseconds)
    XCTAssertEqual(handoff.status, .completed)
    XCTAssertThrowsError(try handoff.finalize(browserCapability: "wrong-capability"))
    XCTAssertFalse(handoff.finalized)
    XCTAssertEqual(handoff.status, .completed)
    XCTAssertEqual(
      try handoff.finalize(browserCapability: handoff.testCapability),
      TestMonasSession(audience: "propylaion", successPath: "/home")
    )
    XCTAssertTrue(handoff.finalized)
  }

  func testMonasRejectsAValidSignatureFromTheWrongDeviceKey() async throws {
    let fixture = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "propylaion",
      authorisedAudiences: ["propylaion"]
    )
    let store = ProxyEnrollmentStore(fixture.enrollment)
    let now = Date(timeIntervalSince1970: Double(nowMilliseconds) / 1_000)
    let challenge = try await ProductionChallengeVerifier.verify(
      qrText: fixture.qr,
      trustRepository: store,
      expectedExternalIdentityID: fixture.externalIdentityID,
      now: now
    )
    let payload = try AuthenticationResponseEncoder.payload(
      challenge: challenge,
      context: fixture.enrollment.responseContext,
      decision: .approved,
      issuedAtMilliseconds: nowMilliseconds,
      userVerifiedAtMilliseconds: nowMilliseconds
    )
    let enrolledSigner = TestOnlySecureEnclave()
    let wrongSigner = TestOnlySecureEnclave()
    let wrongKeyResponse = try wrongSigner.sign(
      payload: payload,
      deviceKeyID: fixture.enrollment.responseContext.deviceKeyID
    )
    var authority = TestMonasLoginCallback(
      audience: "propylaion",
      successPath: "/home",
      browserCapability: "test-only-one-use-browser-capability",
      expectedPayload: payload,
      expectedDeviceKeyID: fixture.enrollment.responseContext.deviceKeyID,
      devicePublicKey: enrolledSigner.publicKey
    )

    XCTAssertThrowsError(
      try authority.submit(
        wrongKeyResponse,
        for: challenge,
        nowMilliseconds: nowMilliseconds
      )
    )
    XCTAssertEqual(authority.status, .pending)
  }

  func testResponseExpiringBeforeMonasSubmissionIsNotConsumed() async throws {
    let fixture = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "propylaion",
      authorisedAudiences: ["propylaion"],
      expiresAtMilliseconds: nowMilliseconds + 1
    )
    let store = ProxyEnrollmentStore(fixture.enrollment)
    let challenge = try await ProductionChallengeVerifier.verify(
      qrText: fixture.qr,
      trustRepository: store,
      expectedExternalIdentityID: fixture.externalIdentityID,
      now: Date(timeIntervalSince1970: Double(nowMilliseconds) / 1_000)
    )
    let payload = try AuthenticationResponseEncoder.payload(
      challenge: challenge,
      context: fixture.enrollment.responseContext,
      decision: .approved,
      issuedAtMilliseconds: nowMilliseconds,
      userVerifiedAtMilliseconds: nowMilliseconds
    )
    let signer = TestOnlySecureEnclave()
    let response = try signer.sign(
      payload: payload,
      deviceKeyID: fixture.enrollment.responseContext.deviceKeyID
    )
    var authority = TestMonasLoginCallback(
      audience: "propylaion",
      successPath: "/home",
      browserCapability: "test-only-one-use-browser-capability",
      expectedPayload: payload,
      expectedDeviceKeyID: fixture.enrollment.responseContext.deviceKeyID,
      devicePublicKey: signer.publicKey
    )

    XCTAssertThrowsError(
      try authority.submit(
        response,
        for: challenge,
        nowMilliseconds: challenge.expiresAtMilliseconds
      )
    )
    XCTAssertEqual(authority.status, .pending)
  }

  func testFaceIDDenialSkipsModeledMonasSubmission() async throws {
    let fixture = try SimulatorAuthenticationFixture(
      installationID: installationID,
      audience: "propylaion",
      authorisedAudiences: ["propylaion"]
    )
    let store = ProxyEnrollmentStore(fixture.enrollment)
    let challenge = try await ProductionChallengeVerifier.verify(
      qrText: fixture.qr,
      trustRepository: store,
      expectedExternalIdentityID: fixture.externalIdentityID,
      now: Date(timeIntervalSince1970: Double(nowMilliseconds) / 1_000)
    )
    let faceID = TestOnlyFaceID(approved: false)
    let approved = faceID.evaluate()
    let signer = TestOnlySecureEnclave()
    let payload = try AuthenticationResponseEncoder.payload(
      challenge: challenge,
      context: fixture.enrollment.responseContext,
      decision: .approved,
      issuedAtMilliseconds: nowMilliseconds,
      userVerifiedAtMilliseconds: nowMilliseconds
    )
    var handoff = TestMonasLoginCallback(
      audience: "propylaion",
      successPath: "/home",
      browserCapability: "test-only-one-use-browser-capability",
      expectedPayload: payload,
      expectedDeviceKeyID: fixture.enrollment.responseContext.deviceKeyID,
      devicePublicKey: signer.publicKey
    )

    XCTAssertFalse(approved)
    XCTAssertEqual(faceID.promptCount, 1)
    if approved {
      let response = try signer.sign(
        payload: payload,
        deviceKeyID: fixture.enrollment.responseContext.deviceKeyID
      )
      try handoff.submit(response, for: challenge, nowMilliseconds: nowMilliseconds)
    }
    XCTAssertEqual(handoff.submitAttemptCount, 0)
    XCTAssertEqual(handoff.status, .pending)
    XCTAssertThrowsError(
      try handoff.finalize(browserCapability: handoff.testCapability)
    )
  }

  private func assertChallengeRejected(
    _ qr: String,
    store: ProxyEnrollmentStore,
    faceID: TestOnlyFaceID,
    now: Date,
    expected: ProductionCeremonyError
  ) async {
    do {
      _ = try await ProductionChallengeVerifier.verify(
        qrText: qr,
        trustRepository: store,
        expectedExternalIdentityID: Data(repeating: 0x44, count: 16),
        now: now
      )
      _ = faceID.evaluate()
      XCTFail("invalid challenge unexpectedly passed production verification")
    } catch let error as ProductionCeremonyError {
      XCTAssertEqual(error, expected)
    } catch {
      XCTFail("challenge failed with an unexpected error: \(error)")
    }
  }
}

private actor ProxyEnrollmentStore: InstallationTrustStoring {
  private let retained: AuthenticatedEnrollmentOutput
  private(set) var installCount = 0
  private(set) var revokeCount = 0

  init(_ retained: AuthenticatedEnrollmentOutput) {
    self.retained = retained
  }

  func activeEnrollment() -> AuthenticatedEnrollmentOutput? { retained }

  func record(installationID: Data) -> InstallationTrustRecord? {
    retained.trust.installationID == installationID ? retained.trust : nil
  }

  func installAuthenticated(_: AuthenticatedEnrollmentOutput) { installCount += 1 }

  func revoke(installationID _: Data) { revokeCount += 1 }
}

/// Ephemeral software P-256 key used only as a test stand-in for the enrolled
/// Secure Enclave signer. It never reaches a keychain or leaves the test.
private struct TestOnlySecureEnclave {
  private let key = P256.Signing.PrivateKey()
  var publicKey: P256.Signing.PublicKey { key.publicKey }

  func sign(payload: Data, deviceKeyID: Data) throws -> Data {
    let structure = try CoseSign1.signatureStructure(
      keyID: deviceKeyID,
      payload: payload
    )
    let signature = Self.lowS(try key.signature(for: structure).rawRepresentation)
    return try CoseSign1(
      keyID: deviceKeyID,
      payload: payload,
      signature: signature
    ).encoded()
  }

  private static func lowS(_ signature: Data) -> Data {
    let halfOrder = Data([
      0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
      0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
      0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
    ])
    let scalar = signature.suffix(32)
    guard sGreaterThanHalfOrder(scalar, halfOrder: halfOrder) else { return signature }
    let order: [UInt8] = [
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
      0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ]
    let input = Array(scalar)
    var output = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for index in stride(from: 31, through: 0, by: -1) {
      var value = Int(order[index]) - Int(input[index]) - borrow
      if value < 0 {
        value += 256
        borrow = 1
      } else {
        borrow = 0
      }
      output[index] = UInt8(value)
    }
    return signature.prefix(32) + Data(output)
  }

  private static func sGreaterThanHalfOrder(
    _ scalar: Data.SubSequence,
    halfOrder: Data
  ) -> Bool {
    !scalar.lexicographicallyPrecedes(halfOrder) && scalar != halfOrder
  }
}

private final class TestOnlyFaceID {
  private let approved: Bool
  private(set) var promptCount = 0

  init(approved: Bool) { self.approved = approved }

  func evaluate() -> Bool {
    promptCount += 1
    return approved
  }
}

private enum TestMonasCeremonyState: Equatable {
  case pending
  case completed
}

private struct TestMonasSession: Equatable {
  let audience: String
  let successPath: String
}

/// In-memory callback authority for the Monas v3/handoff terminal contract.
/// It accepts one challenge response and finalizes one configured session.
private struct TestMonasLoginCallback {
  let audience: String
  let successPath: String
  private let browserCapability: String
  private let expectedPayload: Data
  private let expectedDeviceKeyID: Data
  private let devicePublicKey: P256.Signing.PublicKey
  private(set) var status: TestMonasCeremonyState = .pending
  private(set) var finalized = false
  private(set) var submitAttemptCount = 0

  var testCapability: String { browserCapability }

  init(
    audience: String,
    successPath: String,
    browserCapability: String,
    expectedPayload: Data,
    expectedDeviceKeyID: Data,
    devicePublicKey: P256.Signing.PublicKey,
    expectedSubmitURL: URL? = nil
  ) {
    self.audience = audience
    self.successPath = successPath
    self.browserCapability = browserCapability
    self.expectedPayload = expectedPayload
    self.expectedDeviceKeyID = expectedDeviceKeyID
    self.devicePublicKey = devicePublicKey
    self.expectedSubmitURL = expectedSubmitURL
  }

  private let expectedSubmitURL: URL?

  mutating func submit(
    _ response: Data,
    for challenge: VerifiedAuthenticationChallenge,
    nowMilliseconds: UInt64,
    to submitURL: URL? = nil
  ) throws {
    submitAttemptCount += 1
    guard status == .pending,
      nowMilliseconds < challenge.expiresAtMilliseconds
    else { throw ProxyFailure.expiredOrConsumed }
    if let expectedSubmitURL, submitURL != expectedSubmitURL {
      throw ProxyFailure.invalidRoute
    }
    let cose = try CoseSign1.decode(response)
    guard cose.keyID == expectedDeviceKeyID,
      cose.payload == expectedPayload,
      devicePublicKey.isValidSignature(
        try P256.Signing.ECDSASignature(rawRepresentation: cose.signature),
        for: cose.signatureStructure()
      )
    else { throw ProxyFailure.invalidResponse }
    status = .completed
  }

  mutating func finalize(browserCapability supplied: String) throws -> TestMonasSession {
    guard status == .completed,
      !finalized,
      supplied == browserCapability,
      audience == "propylaion",
      successPath == "/home"
    else { throw ProxyFailure.callbackUnavailable }
    finalized = true
    return TestMonasSession(audience: audience, successPath: successPath)
  }
}

private enum ProxyFailure: Error {
  case expiredOrConsumed
  case invalidResponse
  case callbackUnavailable
  case invalidRoute
}
