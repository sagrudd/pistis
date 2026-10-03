import CoreTransferable
import Foundation
import SwiftUI
import UniformTypeIdentifiers

/// Owns one import and discards all derived authority on replacement or cancellation.
@MainActor
final class SiteX509OfflineCustodyCoordinatorV2: ObservableObject {
    @Published private(set) var importedID: UUID?
    @Published private(set) var validated: SiteX509OfflineCustodyV2?
    @Published private(set) var responseBytes: Data?
    @Published private(set) var producing = false
    @Published private(set) var failed = false
    private var importedBytes: Data?
    private var operationID = UUID()

    func accept(_ bytes: Data) {
        cancel()
        guard !bytes.isEmpty, bytes.count <= SiteX509OfflineCustodyV2.maximumFileBytes else {
            failed = true
            return
        }
        importedBytes = bytes
        importedID = UUID()
    }

    func validate(role: SiteX509AttendedUnlockRoleV2, independentDigest: String) {
        guard !producing else { return }
        validated = nil
        responseBytes = nil
        failed = false
        operationID = UUID()
        do {
            guard let importedBytes else { throw PlatformFailure.custodyRewrapUnavailable }
            validated = try SiteX509OfflineCustodyV2(
                data: importedBytes,
                expectedRole: role,
                independentDigestHex: independentDigest,
                registration: SiteRootConvergenceAckStoreV2().current(),
                nowUnixSeconds: UInt64(Date().timeIntervalSince1970)
            )
        } catch { failed = true }
    }

    func invalidate() {
        operationID = UUID()
        validated = nil
        responseBytes = nil
        failed = false
    }

    func approve() async {
        guard !producing, responseBytes == nil, let value = validated else { return }
        let currentID = operationID
        producing = true
        failed = false
        defer { producing = false }
        do {
            let response = try await value.response {
                guard self.operationID == currentID, self.validated != nil else {
                    throw PlatformFailure.operationCancelled
                }
            }
            guard operationID == currentID, validated != nil else { return }
            responseBytes = response
        } catch {
            guard operationID == currentID else { return }
            responseBytes = nil
            validated = nil
            failed = true
        }
    }

    func cancel() {
        invalidate()
        importedBytes = nil
        importedID = nil
    }
}

private struct CustodyResponseDocumentV2: Transferable {
    let bytes: Data
    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .json) { $0.bytes }
            .suggestedFileName("pistis-site-x509-custody-response.json")
    }
}

struct SiteX509OfflineCustodyReviewViewV2: View {
    @ObservedObject var coordinator: SiteX509OfflineCustodyCoordinatorV2
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var expectedRole = SiteX509AttendedUnlockRoleV2.root
    @State private var independentDigest = ""

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                    MnSectionHeading(
                        "Review Site X.509 custody",
                        orientation: "Enter the challenge hash obtained separately from your authenticated host session."
                    )
                    Picker("Expected authority", selection: $expectedRole) {
                        Text("Root").tag(SiteX509AttendedUnlockRoleV2.root)
                        Text("Issuer").tag(SiteX509AttendedUnlockRoleV2.issuer)
                    }
                    .pickerStyle(.segmented)
                    .disabled(coordinator.producing)
                    TextField("Independent SHA-256 (64 hexadecimal characters)", text: $independentDigest)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.system(.body, design: .monospaced))
                        .disabled(coordinator.producing)
                    MnPrimaryButton("Validate challenge", systemImage: "checkmark.shield") {
                        coordinator.validate(role: expectedRole, independentDigest: independentDigest)
                    }
                    .disabled(coordinator.producing)

                    if let value = coordinator.validated {
                        MnPanel {
                            VStack(alignment: .leading, spacing: MnSpacing.x3) {
                                MnEvidenceRow(label: "Authority", value: value.presentation.role.rawValue)
                                MnEvidenceRow(label: "Site", value: value.presentation.siteTrustDomain, monospaced: true)
                                MnEvidenceRow(label: "Generation", value: value.presentation.keyGeneration, monospaced: true)
                                MnEvidenceRow(label: "Fresh recipient", value: value.presentation.freshHostPublicSEC1.map { String(format: "%02x", $0) }.joined(), monospaced: true)
                                MnEvidenceRow(label: "Expires", value: Date(timeIntervalSince1970: Double(value.presentation.expiresAtUnixSeconds)).formatted())
                            }
                        }
                        if coordinator.responseBytes == nil, !coordinator.producing {
                            MnPrimaryButton("Create response with Face ID", systemImage: "faceid") {
                                Task { await coordinator.approve() }
                            }
                        }
                    }
                    if coordinator.producing { ProgressView("Waiting for Face ID…") }
                    if coordinator.failed {
                        MnStatusLabel(text: "Custody review unavailable. Check the independent hash, current enrolment and challenge expiry.", kind: .danger)
                    }
                    if let bytes = coordinator.responseBytes {
                        MnStatusLabel(text: "Response file prepared", kind: .success)
                        ShareLink(
                            item: CustodyResponseDocumentV2(bytes: bytes),
                            preview: SharePreview("Site X.509 custody response")
                        ) { Label("Share response file", systemImage: "square.and.arrow.up") }
                    }
                    Text("Return the sensitive encrypted response to the same host attempt. Export does not confirm acceptance or signing readiness.")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(MnSpacing.x4)
            }
            .mnScreenBackground()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { coordinator.cancel(); dismiss() }
                }
            }
        }
        .onChange(of: expectedRole) { _, _ in coordinator.invalidate() }
        .onChange(of: independentDigest) { _, _ in coordinator.invalidate() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { coordinator.cancel(); dismiss() }
        }
        .onDisappear { coordinator.cancel() }
        .interactiveDismissDisabled(coordinator.producing)
    }
}
