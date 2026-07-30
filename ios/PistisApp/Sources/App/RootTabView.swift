import SwiftUI

struct RootTabView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var enrollment = EnrollmentProjectionStore()

    var body: some View {
        TabView {
            NavigationStack {
                IdentitiesView(
                    identities: projection.identities,
                    loadFailure: enrollment.state == .failed
                )
            }
            .tabItem {
                Label("Identities", systemImage: "person.text.rectangle")
            }

            NavigationStack {
                InstallationsView(
                    installations: projection.installations,
                    loadFailure: enrollment.state == .failed
                )
            }
            .tabItem {
                Label("Installations", systemImage: "building.2")
            }

            NavigationStack {
                ScanView()
            }
            .tabItem {
                Label("Scan", systemImage: "qrcode.viewfinder")
            }

            NavigationStack {
                HistoryView(
                    events: projection.history,
                    loadFailure: enrollment.state == .failed
                )
            }
            .tabItem {
                Label("History", systemImage: "clock.arrow.circlepath")
            }

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
        }
        .tint(MnColor.action)
        .task {
            await enrollment.refresh()
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            Task { await enrollment.refresh() }
        }
        .onReceive(
            NotificationCenter.default.publisher(
                for: InstallationTrustKeychain.enrollmentDidChangeNotification
            )
        ) { _ in
            Task { await enrollment.refresh() }
        }
    }

    private var projection: EnrollmentProjection {
        if case let .loaded(projection) = enrollment.state {
            return projection
        }
        return .empty
    }
}
