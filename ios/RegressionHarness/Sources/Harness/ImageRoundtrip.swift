import Dispatch
import Foundation

#if os(Linux)
  import Glibc
#else
  import Darwin
#endif

/// Runs only the locally built Rust fixture example; no keys leave this process.
public func roundtripFixtureImage(_ qr: String, executable: URL) throws -> String {
  guard qr.utf8.count <= 2331 else { throw ImageRoundtripFailure.input }
  return try withOwnedImageChild(executable: executable) { process, input, output, finished in
    try input.fileHandleForWriting.write(contentsOf: Data(qr.utf8))
    try input.fileHandleForWriting.close()
    guard finished.wait(timeout: .now() + 30) == .success else {
      throw ImageRoundtripFailure.timeout
    }
    guard process.terminationStatus == 0,
      let data = try output.fileHandleForReading.read(upToCount: 2332),
      data.count <= 2331, let text = String(data: data, encoding: .utf8),
      text == qr
    else { throw ImageRoundtripFailure.decode }
    return text
  }
}

// This lease covers every post-launch exit, including pipe write/close/read
// failures. It never targets a process group or a child it did not launch.
func withOwnedImageChild(
  executable: URL,
  perform: (Process, Pipe, Pipe, DispatchSemaphore) throws -> String
) throws -> String {
  let process = Process()
  let input = Pipe()
  let output = Pipe()
  let finished = DispatchSemaphore(value: 0)
  process.executableURL = executable
  process.standardInput = input
  process.standardOutput = output
  process.standardError = FileHandle.nullDevice
  process.terminationHandler = { _ in finished.signal() }
  defer {
    try? input.fileHandleForWriting.close()
    try? output.fileHandleForReading.close()
  }
  try process.run()
  let result: Result<String, any Error>
  do {
    result = .success(try perform(process, input, output, finished))
  } catch {
    result = .failure(error)
  }
  // Closing stdin also gives a cooperating child a chance to finish normally.
  try? input.fileHandleForWriting.close()
  if process.isRunning {
    process.terminate()
    if finished.wait(timeout: .now() + 2) == .timedOut, process.isRunning {
      kill(process.processIdentifier, SIGKILL)
      guard finished.wait(timeout: .now() + 2) == .success, !process.isRunning else {
        // Do not turn an unobserved termination into a child-absence claim.
        throw ImageRoundtripFailure.cleanup
      }
    }
  }
  guard !process.isRunning else { throw ImageRoundtripFailure.cleanup }
  return try result.get()
}

/// Resolve the existing workspace target directory, including an owned external Cargo target.
public func fixtureRoundtripExecutable() -> URL {
  let target = ProcessInfo.processInfo.environment["CARGO_TARGET_DIR"].flatMap { path in
    path.isEmpty ? nil : URL(fileURLWithPath: path, isDirectory: true)
  }
  let workspace = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent("../../../..", isDirectory: true).standardizedFileURL
  return (target ?? workspace.appendingPathComponent("target", isDirectory: true))
    .appendingPathComponent("debug/examples/ios_qr_roundtrip")
}

enum ImageRoundtripFailure: Error { case input, timeout, decode, cleanup }
