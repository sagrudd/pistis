import SwiftUI
import Foundation
import UniformTypeIdentifiers
import Darwin
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)

/// Explicit offline attendance, with the independently retained installation
/// pin. A file carries the signed request; importing it selects no new trust.
struct IssuerJointRootApprovalView: View {
    @State private var importing = false
    @State private var exporting = false
    @State private var prepared: IssuerJointRootApproval?
    @State private var output: JointRootResponseDocument?
    @State private var operation: Task<Void, Never>?
    @State private var message: String?
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Review issuer permission").font(.title2.bold())
                Text("Import the exact request from your existing installation. Its saved installation identity is checked before approval.")
                Button("Import request") { importing = true }
                    .disabled(operation != nil || prepared != nil)
                if let prepared {
                    Text(prepared.installationName).font(.headline)
                    Text("Approve current issuer status while continuing the existing Root permission. The Root key, grant and expiry stay unchanged.")
                    LabeledContent("Root permission ends", value: date(prepared.attendance.rootGrantExpiry))
                    LabeledContent("Original approval ends", value: date(prepared.attendance.originalExecutionExpiry))
                    LabeledContent("Current-status permission ends", value: date(prepared.attendance.statusGrantExpiry))
                    Text("Only this exact change will be signed with your existing enrolled device key.")
                    Button("Approve with Face ID") {
                        guard operation == nil, output == nil else { return }
                        operation = Task { @MainActor in
                            defer { operation = nil }
                            do { output = JointRootResponseDocument(bytes: try await prepared.approve()); message = "Approval prepared. Save it and return it to the same operation." }
                            catch { prepared.cancel(); message = "The request was not approved. Return to the installation for reconciliation." }
                        }
                    }.buttonStyle(.borderedProminent).disabled(operation != nil || output != nil)
                    if output != nil {
                        Button("Save approval") {
                            operation = Task { @MainActor in
                                defer { operation = nil }
                                do { try await prepared.check(); exporting = true }
                                catch { prepared.cancel(); output = nil; message = "The approval can no longer be delivered." }
                            }
                        }.disabled(operation != nil)
                    }
                    Button("Cancel", role: .cancel) { operation?.cancel(); prepared.cancel(); output = nil }
                }
                if let message { Text(message).accessibilityAddTraits(.updatesFrequently) }
            }.padding()
        }
        .navigationTitle("Issuer permission")
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            operation = Task { @MainActor in
                defer { operation = nil }
                do {
                    let url = try result.get()
                    guard url.isFileURL, url.startAccessingSecurityScopedResource() else { throw CocoaError(.fileReadNoPermission) }
                    defer { url.stopAccessingSecurityScopedResource() }
                    let bytes = try boundedRequest(url)
                    prepared = try await IssuerJointRootApproval.prepare(fileBytes: bytes)
                    message = nil
                } catch { message = "This request could not be verified for your retained installation." }
            }
        }
        .fileExporter(isPresented: $exporting, document: output, contentType: .data,
            defaultFilename: "issuer-permission-approval.bin") { result in
            operation = Task { @MainActor in
                defer { operation = nil }
                do { _ = try result.get(); try await prepared?.check(); message = "Approval saved. The installation must still verify and apply it." }
                catch { prepared?.cancel(); message = "Delivery was not confirmed. Return to the installation for reconciliation." }
            }
        }
        .onDisappear { operation?.cancel(); prepared?.cancel(); output = nil }
    }
    private func boundedRequest(_ url: URL) throws -> Data {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw CocoaError(.fileReadNoPermission) }
        let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? input.close() }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_size > 0, metadata.st_size <= 24_576 else { throw CocoaError(.fileReadCorruptFile) }
        let bytes = try input.read(upToCount: 24_577) ?? Data()
        guard !bytes.isEmpty, bytes.count <= 24_576 else { throw CocoaError(.fileReadTooLarge) }
        return bytes
    }
    private func date(_ seconds: UInt64) -> String {
        Date(timeIntervalSince1970: Double(seconds)).formatted(date: .abbreviated, time: .shortened)
    }
}
private struct JointRootResponseDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let bytes: Data
    init(bytes: Data) { self.bytes = bytes }
    init(configuration: ReadConfiguration) throws {
        guard let bytes = configuration.file.regularFileContents, bytes.count <= 16_384 else { throw CocoaError(.fileReadCorruptFile) }
        self.bytes = bytes
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        guard !bytes.isEmpty, bytes.count <= 16_384 else { throw CocoaError(.fileWriteUnknown) }
        return FileWrapper(regularFileWithContents: bytes)
    }
}
#endif
