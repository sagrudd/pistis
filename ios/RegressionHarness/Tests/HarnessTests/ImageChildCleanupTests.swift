import Dispatch
import Foundation
@testable import Harness
import Testing

#if os(Linux)
  import Glibc
#else
  import Darwin
#endif

private enum InjectedPipeFailure: Error { case close }

private func closedInputIgnoringTerminationFixture() throws -> (URL, URL) {
  let directory = FileManager.default.temporaryDirectory
    .appendingPathComponent("pistis-image-child-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
  let executable = directory.appendingPathComponent("closed-input-child.sh")
  // exec via the shebang retains the Process-owned PID; no child subtree is spawned.
  try Data("""
    #!/bin/sh
    trap '' TERM
    exec 0<&-
    printf ready
    while :; do :; done
    """.utf8).write(to: executable)
  try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
  return (directory, executable)
}

private func requireOwnedChildAbsent(_ pid: Int32) {
  errno = 0
  #expect(kill(pid, 0) == -1)
  #expect(errno == ESRCH)
}

@Test func imagePipeWriteFailureKillsAndReapsTheOwnedTermIgnoringChild() throws {
  let (directory, executable) = try closedInputIgnoringTerminationFixture()
  defer { try? FileManager.default.removeItem(at: directory) }
  var pid: Int32 = -1
  let started = ContinuousClock.now
  #expect(throws: (any Error).self) {
    try withOwnedImageChild(executable: executable) { process, input, output, _ in
      pid = process.processIdentifier
      #expect(try output.fileHandleForReading.read(upToCount: 5) == Data("ready".utf8))
      // Deterministically force the same throwing write boundary after launch.
      // The fixture has already closed its stdin and deliberately ignores TERM.
      try input.fileHandleForWriting.close()
      try input.fileHandleForWriting.write(contentsOf: Data("fixture".utf8))
      return "unreachable"
    }
  }
  #expect(pid > 0)
  requireOwnedChildAbsent(pid)
  #expect(started.duration(to: .now) < .seconds(6))
}

@Test func imagePipeCloseFailureAlsoCleansTheOwnedChild() throws {
  let (directory, executable) = try closedInputIgnoringTerminationFixture()
  defer { try? FileManager.default.removeItem(at: directory) }
  var pid: Int32 = -1
  #expect(throws: InjectedPipeFailure.self) {
    try withOwnedImageChild(executable: executable) { process, _, output, _ in
      pid = process.processIdentifier
      #expect(try output.fileHandleForReading.read(upToCount: 5) == Data("ready".utf8))
      throw InjectedPipeFailure.close
    }
  }
  requireOwnedChildAbsent(pid)
}

@Test func imageTimeoutWaitsForTheKilledChildTermination() throws {
  let (directory, executable) = try closedInputIgnoringTerminationFixture()
  defer { try? FileManager.default.removeItem(at: directory) }
  var pid: Int32 = -1
  #expect(throws: ImageRoundtripFailure.self) {
    try withOwnedImageChild(executable: executable) { process, _, output, finished in
      pid = process.processIdentifier
      #expect(try output.fileHandleForReading.read(upToCount: 5) == Data("ready".utf8))
      #expect(finished.wait(timeout: .now() + .milliseconds(50)) == .timedOut)
      throw ImageRoundtripFailure.timeout
    }
  }
  requireOwnedChildAbsent(pid)
}
