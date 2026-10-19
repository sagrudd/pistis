import SwiftUI
import Foundation
import UniformTypeIdentifiers
import Darwin
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)

/// Pending import is comparison DATA, never a URL/trust/session selector.
struct IssuerMacSessionApprovalView: View {
    var expectedInstallation: UUID? = nil
    @State private var importing = false
    @State private var prepared: IssuerMacSessionApproval?
    @State private var operation: Task<Void, Never>?
    @State private var terminal = false
    @State private var message: String?
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Approve the Mac connection").font(.title2.bold())
                Text("Open the current pending record from the Mac. Pistis compares it with the installation and Site already saved on this iPhone. The record cannot change your trusted server or keys.")
                Button("Open pending Mac record") { importing = true }
                    .disabled(operation != nil || prepared != nil || terminal)
                    .accessibilityIdentifier("mac-session-open-pending")
                if let prepared {
                    Text(prepared.installationName).font(.headline)
                    LabeledContent("Site", value: prepared.pending.siteID)
                    LabeledContent("Operation", value: prepared.pending.operationID)
                    DisclosureGroup("Compare pending connection") {
                        Text(String(decoding: prepared.pending.original, as: UTF8.self))
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                    Text("Approve only the operation you started on the Mac. Face ID authenticates this enrolled phone. This does not approve installation, issue keys or complete activation; the Mac must finish its current-purpose checks.")
                    Button("Approve Mac connection with Face ID") {
                        guard operation == nil, !terminal else { return }
                        terminal = true
                        operation = Task { @MainActor in
                            defer { operation = nil }
                            do {
                                try await prepared.approve()
                                message = "The installation confirmed this pending Mac connection. Continue on the Mac."
                            } catch {
                                prepared.cancel()
                                message = "The Mac connection was not confirmed. Do not reuse this record; return to the Mac to check the operation."
                            }
                        }
                    }.buttonStyle(.borderedProminent).disabled(operation != nil || terminal)
                    .accessibilityIdentifier("mac-session-approve")
                    Button("Cancel", role: .cancel) {
                        terminal = true; operation?.cancel(); prepared.cancel()
                        message = "Mac connection approval cancelled."
                    }
                }
                if let message { Text(message).accessibilityAddTraits(.updatesFrequently) }
            }.padding()
        }
        .navigationTitle("Mac connection")
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            guard operation == nil, !terminal else { return }
            operation = Task { @MainActor in
                defer { operation = nil }
                do {
                    let url = try result.get()
                    guard url.isFileURL, url.startAccessingSecurityScopedResource() else { throw CocoaError(.fileReadNoPermission) }
                    defer { url.stopAccessingSecurityScopedResource() }
                    prepared = try await IssuerMacSessionApproval.prepare(fileBytes: boundedPending(url), expectedInstallation: expectedInstallation)
                } catch {
                    terminal = true
                    message = "This pending record does not match your current installation or has expired. No Mac connection was approved."
                }
            }
        }
        .onDisappear { terminal = true; operation?.cancel(); prepared?.cancel() }
    }
    private func boundedPending(_ url: URL) throws -> Data {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw CocoaError(.fileReadNoPermission) }
        let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? input.close() }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_size > 0, metadata.st_size <= 4096 else { throw CocoaError(.fileReadCorruptFile) }
        let bytes = try input.read(upToCount: 4097) ?? Data()
        guard !bytes.isEmpty, bytes.count <= 4096 else { throw CocoaError(.fileReadTooLarge) }
        return bytes
    }
}
#endif
