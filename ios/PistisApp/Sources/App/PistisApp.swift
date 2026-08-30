import SwiftUI

/// Keeps the app's protected transport aligned with the selected, signed
/// installation after first-device enrolment. The generic release starts on
/// the fixed broker; once an authenticated enrolment is retained, this store
/// switches to the exact origin and TLS pin supplied by that receipt.
@MainActor
final class SiteRootTransportStore: ObservableObject {
    @Published private(set) var transport: any MonasSiteRootCeremonyTransport
    @Published private(set) var revision = 0
    private var boundOrigin: String?
    private var boundSPKI: Data?

    init() {
        transport = ProductionMonasSiteRootTransportFactory.make()
    }

    func refresh() async {
        guard let enrollment = try? await InstallationTrustKeychain.shared.activeEnrollment(),
              let bound = ProductionMonasSiteRootTransportFactory.make(
                  verifiedEnrollment: enrollment
              )
        else { return }
        guard boundOrigin != enrollment.httpsOrigin
                || boundSPKI != enrollment.tlsSPKISHA256
        else { return }
        boundOrigin = enrollment.httpsOrigin
        boundSPKI = enrollment.tlsSPKISHA256
        transport = bound
        revision &+= 1
    }
}

@main
struct PistisApp: App {
    @StateObject private var siteRootTransportStore = SiteRootTransportStore()

    var body: some Scene {
        WindowGroup {
            AppContainerView(siteRootTransportStore: siteRootTransportStore)
                // ADR 0007 deliberately defines no unreviewed dark palette.
                .preferredColorScheme(.light)
        }
    }
}

private struct AppContainerView: View {
    @AppStorage(PistisOnboardingState.completedKey)
    private var hasCompletedOnboarding = false
    @ObservedObject var siteRootTransportStore: SiteRootTransportStore

    var body: some View {
        Group {
            if hasCompletedOnboarding {
                RootTabView(siteRootTransport: siteRootTransportStore.transport) {
                    hasCompletedOnboarding = false
                }
            } else {
                OnboardingView {
                    hasCompletedOnboarding = true
                }
            }
        }
        .id(siteRootTransportStore.revision)
        .task {
            await siteRootTransportStore.refresh()
        }
        .onReceive(
            NotificationCenter.default.publisher(
                for: InstallationTrustKeychain.enrollmentDidChangeNotification
            )
        ) { _ in
            Task { await siteRootTransportStore.refresh() }
        }
    }
}
