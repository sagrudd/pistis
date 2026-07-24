import SwiftUI

@main
struct PistisApp: App {
    var body: some Scene {
        WindowGroup {
            AppContainerView()
                // ADR 0007 deliberately defines no unreviewed dark palette.
                .preferredColorScheme(.light)
        }
    }
}

private struct AppContainerView: View {
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false

    var body: some View {
        if hasCompletedOnboarding {
            RootTabView()
        } else {
            OnboardingView {
                hasCompletedOnboarding = true
            }
        }
    }
}
