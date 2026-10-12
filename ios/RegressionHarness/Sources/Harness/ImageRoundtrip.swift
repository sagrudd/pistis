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
  let process = Process()
  let input = Pipe()
  let output = Pipe()
  let finished = DispatchSemaphore(value: 0)
  process.executableURL = executable
  process.standardInput = input
  process.standardOutput = output
  process.standardError = FileHandle.nullDevice
  process.terminationHandler = { _ in finished.signal() }
  try process.run()
  try input.fileHandleForWriting.write(contentsOf: Data(qr.utf8))
  try input.fileHandleForWriting.close()
  guard finished.wait(timeout: .now() + 30) == .success else {
    if process.isRunning { process.terminate() }
    if finished.wait(timeout: .now() + 2) == .timedOut, process.isRunning {
      kill(process.processIdentifier, SIGKILL)
    }
    throw ImageRoundtripFailure.timeout
  }
  guard process.terminationStatus == 0,
    let data = try output.fileHandleForReading.read(upToCount: 2332),
    data.count <= 2331, let text = String(data: data, encoding: .utf8),
    text == qr
  else { throw ImageRoundtripFailure.decode }
  return text
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

private enum ImageRoundtripFailure: Error { case input, timeout, decode }
