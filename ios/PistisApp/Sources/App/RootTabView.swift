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
                    loadFailure: enrollment.state == .failed,
                    forgetExpired: forgetExpired
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

    private func forgetExpired(_ installationID: UUID) async throws {
        let identifier = installationID.data
        guard let stored = try await InstallationTrustKeychain.shared
            .enrollmentInventoryRecord(),
              stored.trust.installationID == identifier,
              InstallationTrustKeychain.allowsLocalForget(
                  active: stored.trust.active,
                  expiresAt: stored.trust.expiresAt,
                  now: Date()
              )
        else { throw PlatformFailure.invalidConfiguration }

        if let event = EnrollmentProjection(enrollment: stored).history.first {
            try LocalHistoryRepository.shared.record(event)
        }
        let signer = try SecureEnclaveSigner(
            namespace: hexadecimal(identifier),
            authenticationReason: "Forget this expired Pistis installation"
        )
        try signer.deleteLocalKey()
        try await InstallationTrustKeychain.shared.forgetExpired(
            installationID: identifier
        )
        try LocalHistoryRepository.shared.record(
            HistoryEvent(
                id: UUID(),
                action: "Local installation record forgotten",
                installation: stored.trust.displayName,
                occurredAt: Date().formatted(date: .abbreviated, time: .standard),
                decision: "Completed locally",
                signature: "No authority action requested",
                transfer: "No server state changed",
                verification: "Expired trust and local device key removed"
            )
        )
        await enrollment.refresh()
    }

    private func hexadecimal(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

private extension UUID {
    var data: Data {
        let value = uuid
        return Data([
            value.0, value.1, value.2, value.3,
            value.4, value.5, value.6, value.7,
            value.8, value.9, value.10, value.11,
            value.12, value.13, value.14, value.15,
        ])
    }
}
