import SwiftUI
import Foundation
import UniformTypeIdentifiers
import Darwin
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)

/// Explicit review for the fixed native-purpose operation. A public plan is
/// correlation DATA; it does not appoint trust, keys, grants or current owners.
struct IssuerNativePurposeApprovalView: View {
    @State private var importing = false
    @State private var prepared: IssuerNativePurposeApproval?
    @State private var operation: Task<Void, Never>?
    @State private var message: String?
    @State private var terminal = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Review native issuer installation").font(.title2.bold())
                Text("Use the current plan from your installation. Your saved installation identity and existing acknowledgement key are checked before approval.")
                Button("Open installation plan") { importing = true }
                    .disabled(operation != nil || prepared != nil || terminal)
                if let prepared {
                    Text(prepared.installationName).font(.headline)
                    LabeledContent("Site", value: prepared.task.siteLabel)
                    LabeledContent("Source", value: prepared.task.sourceRepository)
                    Text("Create the requested status witness, native Target and issuance purposes with the exact new public keys shown below. This is a separate installation approval.")
                    Text("Recovery is not authorized. If signing or delivery becomes uncertain, this installation stays locked and needs reconciliation.")
                    DisclosureGroup("Review exact keys, purposes and installed source") {
                        Text(prepared.summary).font(.caption.monospaced()).textSelection(.enabled)
                    }
                    Button("Approve installation with Face ID") {
                        guard operation == nil, !terminal else { return }
                        terminal = true
                        operation = Task { @MainActor in
                            defer { operation = nil }
                            do {
                                try await prepared.approve()
                                message = "The installation confirmed this exact native-purpose approval."
                            } catch {
                                prepared.cancel()
                                message = "Approval or delivery was not confirmed. Return to the installation for reconciliation; do not start another initialization."
                            }
                        }
                    }.buttonStyle(.borderedProminent).disabled(operation != nil || terminal)
                    Button("Cancel", role: .cancel) {
                        terminal = true; operation?.cancel(); prepared.cancel()
                        message = "Approval cancelled."
                    }
                }
                if let message { Text(message).accessibilityAddTraits(.updatesFrequently) }
            }.padding()
        }
        .navigationTitle("Native issuer installation")
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            guard operation == nil, !terminal else { return }
            operation = Task { @MainActor in
                defer { operation = nil }
                do {
                    let url = try result.get()
                    guard url.isFileURL, url.startAccessingSecurityScopedResource() else { throw CocoaError(.fileReadNoPermission) }
                    defer { url.stopAccessingSecurityScopedResource() }
                    let plan = try NativeInstallApprovalWire.Plan(canonicalBytes: boundedPlan(url))
                    prepared = try await IssuerNativePurposeApproval.prepareCurrent(plan: plan)
                    message = nil
                } catch {
                    terminal = true
                    message = "This plan could not be prepared for your retained installation. Return to the installation for reconciliation."
                }
            }
        }
        .onDisappear { terminal = true; operation?.cancel(); prepared?.cancel() }
    }
    private func boundedPlan(_ url: URL) throws -> Data {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw CocoaError(.fileReadNoPermission) }
        let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? input.close() }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_size > 0, metadata.st_size <= 512 else { throw CocoaError(.fileReadCorruptFile) }
        let bytes = try input.read(upToCount: 513) ?? Data()
        guard !bytes.isEmpty, bytes.count <= 512 else { throw CocoaError(.fileReadTooLarge) }
        return bytes
    }
}
#endif
