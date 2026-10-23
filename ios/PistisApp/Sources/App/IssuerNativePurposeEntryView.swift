import SwiftUI

#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
/// Deliberate navigation only. Trust and signing remain in the existing
/// bounded file-import and current-enrolment approval operation.
struct IssuerNativePurposeEntryView: View {
    var body: some View {
        List {
            Section {
                Text("Native issuer setup").font(.headline)
                Text("Review the installation plan provided by your organisation. Pistis checks it against the installation already saved on this iPhone before presenting the requested keys and purposes.")
                Text("You will need your existing installation identity and acknowledgement key. Approval requires a separate Face ID confirmation after reviewing the complete request.")
            }
            Section {
                Label("Installation plan setup unavailable", systemImage: "exclamationmark.circle")
                Text("Installation-plan approval remains unavailable. Approving a pending Mac connection is a separate authentication action and does not complete installation.")
            }
            Section {
                NavigationLink("Approve a pending Mac connection") { IssuerMacSessionApprovalView() }
                    .accessibilityIdentifier("native-issuer-mac-session")
                NavigationLink("Review an installation plan") {
                    IssuerNativePurposeApprovalView()
                }
                .accessibilityIdentifier("native-purpose-review-plan")
            } footer: {
                Text("Choose a plan file in the next screen. Use the installation's reconciliation process if approval or delivery is uncertain; recovery and reinitialisation are not authorised by this request.")
            }
        }
        .navigationTitle("Native issuer setup")
    }
}
#endif
