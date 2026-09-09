import SwiftUI

/// Keeps the app's protected transport aligned with the selected, signed
/// installation after first-device enrolment. The generic release starts on
/// the fixed broker; once an authenticated enrolment is retained, this store
/// switches to the exact origin and TLS pin supplied by that receipt.
@MainActor
final class SiteRootTransportStore: ObservableObject {
    @Published private(set) var transport: any MonasSiteRootCeremonyTransport
    @Published private(set) var revision = 0
    private var boundEnrollment: AuthenticatedEnrollmentOutput?
    private var refreshGeneration: UInt64 = 0
    private let initialTransport: any MonasSiteRootCeremonyTransport
    private let loadEnrollment: () async throws -> AuthenticatedEnrollmentOutput?

    init(loadEnrollment: (() async throws -> AuthenticatedEnrollmentOutput?)? = nil) {
        self.loadEnrollment = loadEnrollment ?? {
            try await InstallationTrustKeychain.shared.activeEnrollment()
        }
        initialTransport = ProductionMonasSiteRootTransportFactory.make()
        transport = initialTransport
    }

    func refresh() async {
        refreshGeneration &+= 1
        let generation = refreshGeneration
        let loaded = try? await loadEnrollment()
        guard generation == refreshGeneration else { return }
        guard let enrollment = loaded,
              let bound = ProductionMonasSiteRootTransportFactory.make(
                  verifiedEnrollment: enrollment
              )
        else {
            guard boundEnrollment != nil else { return }
            boundEnrollment = nil
            // Preserve only the original reviewed build profile (the fixed
            // broker in a generic build), never a stale selected enrolment.
            transport = initialTransport
            revision &+= 1
            return
        }
        guard boundEnrollment != enrollment else { return }
        boundEnrollment = enrollment
        transport = bound
        revision &+= 1
    }

    func scenePhaseChanged(_ phase: ScenePhase) async {
        guard phase == .active else {
            refreshGeneration &+= 1
            return
        }
        await refresh()
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
    @Environment(\.scenePhase) private var scenePhase
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
        .onChange(of: scenePhase) { _, phase in
            Task { await siteRootTransportStore.scenePhaseChanged(phase) }
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
