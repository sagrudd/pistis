import SwiftUI
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)

/// Presentation only. Its private prepared object must come from the genuine
/// owner ingress; a readiness response or a confirmation flag cannot create it.
struct IssuerSiteRootReviewView: View {
    let prepared: IssuerSiteRootPreparedHandoff
    let ceremony: IssuerSiteRootCeremony
    @Environment(\.dismiss) private var dismiss
    @State private var operation: Task<Void, Never>?
    @State private var outcome: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(prepared.readiness.mode == .admission ? "Review issuer root admission" : "Review current issuer check")
                    .font(.title2.bold())
                Text(prepared.summary).textSelection(.enabled)
                Text(prepared.readiness.mode == .admission
                    ? "Approve this exact root admission with one Site Root signature."
                    : "Approve one current issuer check: two signatures, before and after the protected read.")
                if let outcome { Text(outcome).accessibilityAddTraits(.updatesFrequently) }
                Button("Approve with Face ID") {
                    guard operation == nil else { return }
                    operation = Task { @MainActor in
                        do {
                            try await ceremony.confirm(prepared)
                            outcome = "Phone ceremony accepted. This screen grants no server authority."
                        } catch {
                            outcome = "The ceremony was not confirmed. Start again through the current owner."
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(operation != nil)
                Button("Cancel", role: .cancel) { operation?.cancel(); dismiss() }
            }.padding()
        }
        .onDisappear { operation?.cancel() }
    }
}
#endif
