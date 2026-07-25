import SwiftUI

struct OnboardingView: View {
    let continueAction: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x6) {
                MnProvenance()
                MnSectionHeading(
                    "Evidence-led approvals",
                    orientation: "Pistis keeps device identity, human intent, signature production, transfer, and server verification as separate facts."
                )
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        Label("Device signing keys are intended to remain in the Secure Enclave.", systemImage: "lock.shield")
                        Label("Every signature requires local user verification.", systemImage: "faceid")
                        Label("GitHub may use Keeper through the normal iOS passkey sheet.", systemImage: "person.badge.key")
                    }
                    .font(.body)
                }
                MnStatusLabel(
                    text: "Development source: native device and distribution gates not yet verified",
                    kind: .warning
                )
                MnPrimaryButton("Continue to Pistis", action: continueAction)
            }
            .padding(MnMetrics.screenGutter)
        }
        .mnScreenBackground()
    }
}
