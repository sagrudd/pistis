import SwiftUI

struct RootTabView: View {
    var body: some View {
        TabView {
            NavigationStack {
                IdentitiesView(identities: [])
            }
            .tabItem {
                Label("Identities", systemImage: "person.text.rectangle")
            }

            NavigationStack {
                InstallationsView(installations: [])
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
                HistoryView(events: [])
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
    }
}
