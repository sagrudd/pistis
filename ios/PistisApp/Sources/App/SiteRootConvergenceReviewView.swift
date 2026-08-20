import SwiftUI

struct SiteRootConvergenceReviewView: View {
    let review: SiteRootConvergenceReview
    @ObservedObject var coordinator: SiteRootConvergenceCoordinator
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x6) {
                    MnSectionHeading(title, orientation: orientation)
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            LabeledContent("Site", value: review.site)
                            LabeledContent("Expires", value: review.expiresAt.formatted())
                            detailRows
                        }
                    }
                    MnPanel {
                        Text("One fresh Face ID ceremony authorises only these exact bytes. Cancelling or any mismatch stops safely; Pistis does not re-enrol a device or fall back to a password.")
                            .font(.footnote)
                    }
                    phaseContent
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Site Root convergence")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(isBusy)
                }
            }
            .mnScreenBackground()
        }
    }

    @ViewBuilder private var detailRows: some View {
        switch review.kind {
        case let .bundleReceiptProvision(generation):
            LabeledContent("Receipt key generation", value: String(generation))
        case let .siteX509Provision(generation):
            LabeledContent("X.509 generation", value: String(generation))
            LabeledContent("Roles", value: "Site root and issuer")
        case let .acknowledgement(action, root, trust):
            LabeledContent("Action", value: action.label)
            LabeledContent("Site root generation", value: String(root))
            LabeledContent("Trust revision", value: String(trust))
        }
    }

    @ViewBuilder private var phaseContent: some View {
        switch coordinator.phase {
        case .review:
            MnPrimaryButton(buttonTitle, systemImage: "faceid") {
                Task { await coordinator.approve() }
            }
        case .authenticating, .submitting, .unlockingBundleReceipt:
            HStack(spacing: MnSpacing.x3) {
                ProgressView()
                Text(phaseLabel)
            }
        case .completed:
            MnPanel {
                VStack(alignment: .leading, spacing: MnSpacing.x3) {
                    MnStatusLabel(text: "Verified and accepted", kind: .success)
                    MnPrimaryButton("Done", systemImage: "checkmark") { dismiss() }
                }
            }
        case let .failed(failure):
            MnPanel {
                VStack(alignment: .leading, spacing: MnSpacing.x3) {
                    MnStatusLabel(text: "Stopped safely", kind: .danger)
                    Text(failure.safeUserMessage)
                    MnPrimaryButton("Close", systemImage: "xmark") { dismiss() }
                }
            }
        default: EmptyView()
        }
    }

    private var title: String {
        switch review.kind {
        case .bundleReceiptProvision: "Provision Site Root receipt custody"
        case .siteX509Provision: "Provision Site X.509 custody"
        case .acknowledgement: "Approve signed HTTPS convergence"
        }
    }

    private var orientation: String {
        switch review.kind {
        case .bundleReceiptProvision:
            "Create the distinct one-use receipt signing generation in protected custody."
        case .siteX509Provision:
            "Approve one atomic transaction for distinct fresh root and issuer keys."
        case .acknowledgement:
            "Register the protected acknowledgement key and sign this exact Site Root result."
        }
    }

    private var buttonTitle: String {
        switch review.kind {
        case .bundleReceiptProvision: "Provision with Face ID"
        case .siteX509Provision: "Approve both roles with Face ID"
        case .acknowledgement: "Approve with Face ID"
        }
    }

    private var isBusy: Bool {
        coordinator.phase == .authenticating || coordinator.phase == .submitting
            || coordinator.phase == .unlockingBundleReceipt
    }

    private var phaseLabel: String {
        switch coordinator.phase {
        case .authenticating: "Waiting for Face ID"
        case .unlockingBundleReceipt: "Unlocking the Site Root receipt authority"
        default: "Submitting exact proof"
        }
    }
}

private extension UnsignedSiteRootConvergenceAssertionV2.Action {
    var label: String {
        switch self { case .install: "Install"; case .replace: "Replace"; case .remove: "Remove" }
    }
}
