import SwiftUI

@main
struct PistisApp: App {
    private let siteRootTransport = ProductionMonasSiteRootTransportFactory.make()

    var body: some Scene {
        WindowGroup {
            AppContainerView(siteRootTransport: siteRootTransport)
                // ADR 0007 deliberately defines no unreviewed dark palette.
                .preferredColorScheme(.light)
        }
    }
}

private struct AppContainerView: View {
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    let siteRootTransport: any MonasSiteRootCeremonyTransport

    var body: some View {
        if hasCompletedOnboarding {
            RootTabView(siteRootTransport: siteRootTransport)
        } else {
            OnboardingView {
                hasCompletedOnboarding = true
            }
        }
    }
}
