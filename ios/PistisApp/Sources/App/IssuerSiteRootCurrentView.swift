import SwiftUI
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)

/// Explicit entry into the fixed own-session/current-permission preparation.
/// No prepared owner, key, token or authority DTO is accepted from navigation.
struct IssuerSiteRootCurrentView: View {
    @State private var work: Task<Void, Never>?
    @State private var prepared: IssuerSiteRootPreparedHandoff?
    @State private var ceremony: IssuerSiteRootCeremony?
    @State private var message: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Current issuer check").font(.title2.bold())
            Text("Prepare one check using this phone's current enrollment and existing Site Root key.")
            if let message { Text(message).accessibilityAddTraits(.updatesFrequently) }
            if let prepared, let ceremony {
                IssuerSiteRootReviewView(prepared: prepared, ceremony: ceremony)
            } else {
                Button("Prepare current check") {
                    guard work == nil else { return }
                    work = Task { @MainActor in
                        defer { work = nil }
                        do {
                            let current = try await IssuerSiteRootCeremony.prepareCurrentPair()
                            try Task.checkCancellation()
                            prepared = current.1; ceremony = current.0
                        } catch { message = "The current issuer check is unavailable. No permission was approved." }
                    }
                }.disabled(work != nil)
            }
        }.padding()
        .onDisappear { prepared?.cancel(); work?.cancel(); prepared = nil; ceremony = nil }
    }
}
#endif
