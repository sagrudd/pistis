import Foundation
import Harness
import Testing

@Test @MainActor func requiredPNGImagePipelineFeedsTheRealSwiftVerifier() async throws {
  let executable = fixtureRoundtripExecutable()
  try #require(
    FileManager.default.isExecutableFile(atPath: executable.path),
    "Build the Rust qr_roundtrip example before running the combined harness gate."
  )
  let fixture = try EnrolledFixture()
  let frame = try fixture.qr()
  let decoded = try roundtripFixtureImage(frame, executable: executable)
  var ledger = ModelledLedger()
  let report = await CeremonyRunner.run(
    qr: decoded, fixture: fixture, biometric: .success, ledger: &ledger
  )
  #expect(report.effects.signatures == 1)
  #expect(report.outcome == "modelled_session")
  #expect(report.effects.realNetworkRequests == 0)
  #expect(inspectUntrustedQR(decoded).failure == "enrolment_required")
}
