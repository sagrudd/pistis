import SwiftUI

struct SiteRootConvergenceReviewView: View {
    let review: SiteRootConvergenceReview
    @ObservedObject var coordinator: SiteRootConvergenceCoordinator
    var scanReceiptUnlock: (() -> Void)? = nil
    var scanReceiptAcknowledgement: (() -> Void)? = nil
    var finishReceiptAcknowledgement: (() -> Void)? = nil
    let scanFinalIdentityQR: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var siteX509StageStartedAt = Date()
    @State private var slowAcknowledgementStage: SiteRootAcknowledgementStage?

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
            .interactiveDismissDisabled(isBusy && isAcknowledgement)
            .mnScreenBackground()
        }
    }

    @ViewBuilder private var detailRows: some View {
        switch review.kind {
        case let .bundleReceiptUnlock(generation):
            LabeledContent("Receipt key generation", value: generation)
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
        case let .acknowledgementProgress(stage):
            MnPanel {
                VStack(alignment: .leading, spacing: MnSpacing.x3) {
                    HStack(spacing: MnSpacing.x3) {
                        ProgressView().accessibilityHidden(true)
                        Text(stage.title)
                    }
                    Text(stage.detail).font(.footnote)
                    if slowAcknowledgementStage == stage {
                        Text(stage.slowGuidance).font(.footnote)
                    }
                }
                .task(id: stage) {
                    do {
                        try await Task.sleep(for: .seconds(15))
                        if !Task.isCancelled { slowAcknowledgementStage = stage }
                    } catch {
                        // A later phase owns its own delay.
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(.updatesFrequently)
            }
        case let .siteX509Progress(stage):
            TimelineView(.periodic(from: Date(), by: 1)) { context in
                VStack(alignment: .leading, spacing: MnSpacing.x2) {
                    HStack(spacing: MnSpacing.x3) {
                        ProgressView().accessibilityHidden(true)
                        Text(stage.label)
                    }
                    if context.date.timeIntervalSince(siteX509StageStartedAt) >= 2 {
                        Text("Still waiting in this step. Keep Pistis open.")
                            .font(.footnote)
                    }
                }
                .accessibilityElement(children: .combine)
            }
            .id(stage.supportStage)
            .onAppear { siteX509StageStartedAt = Date() }
        case .authenticating, .submitting, .unlockingBundleReceipt:
            HStack(spacing: MnSpacing.x3) {
                ProgressView()
                Text(phaseLabel)
            }
        case .awaitingFinalIdentityQR:
            MnPanel {
                VStack(alignment: .leading, spacing: MnSpacing.x3) {
                    MnStatusLabel(text: "Custody verified", kind: .success)
                    Text("When the install page shows the identity QR, scan it to register your administrator (3/5).")
                    MnPrimaryButton(FreshInstallQRStep.scanNext, systemImage: "qrcode.viewfinder") {
                        scanFinalIdentityQR()
                        dismiss()
                    }
                }
            }
        case .completed:
            MnPanel {
                VStack(alignment: .leading, spacing: MnSpacing.x3) {
                    MnStatusLabel(text: "Verified and accepted", kind: .success)
                    if let scanReceiptAcknowledgement {
                        Text("Receipt key approved. When the install window shows the acknowledgement QR, scan it to confirm installation.")
                        MnPrimaryButton(FreshInstallQRStep.scanNext, systemImage: "qrcode.viewfinder") {
                            scanReceiptAcknowledgement()
                            dismiss()
                        }
                    } else {
                        if finishReceiptAcknowledgement != nil {
                            Text("Approval sent. Keep the install window open until Monas confirms setup and shows the login address.")
                        }
                        MnPrimaryButton(
                            finishReceiptAcknowledgement == nil ? "Done" : "Continue setup",
                            systemImage: "checkmark"
                        ) {
                            dismiss()
                            finishReceiptAcknowledgement?()
                        }
                    }
                }
            }
        case let .failed(failure):
            MnPanel {
                VStack(alignment: .leading, spacing: MnSpacing.x3) {
                    MnStatusLabel(text: "Stopped safely", kind: .danger)
                    Text(failure.safeUserMessage)
                    if let code = coordinator.supportCode {
                        Text(code).font(.footnote.monospaced()).textSelection(.enabled)
                    }
                    if coordinator.canRetryBrokerCustody {
                        MnPrimaryButton("Retry Monas connection", systemImage: "arrow.clockwise") {
                            Task { await coordinator.retryBrokerCustody() }
                        }
                    }
                    if coordinator.mayScanReceiptUnlock, let scanReceiptUnlock {
                        Text("The receipt key was approved. Wait for the install window to show its unlock QR, then scan it to finish step 4/5.")
                        MnPrimaryButton(FreshInstallQRStep.scanNext, systemImage: "qrcode.viewfinder") {
                            scanReceiptUnlock()
                            dismiss()
                        }
                    } else {
                        MnPrimaryButton("Close", systemImage: "xmark") { dismiss() }
                    }
                }
            }
        default: EmptyView()
        }
    }

    private var title: String {
        switch review.kind {
        case .bundleReceiptUnlock: scanReceiptAcknowledgement != nil ? FreshInstallQRStep.approveReceiptKey.heading : "Unlock Site Root receipt signer"
        case .bundleReceiptProvision: scanReceiptAcknowledgement != nil ? FreshInstallQRStep.approveReceiptKey.heading : "Approve the receipt key"
        case .siteX509Provision: coordinator.selectedTransportRoute == .broker ? FreshInstallQRStep.approveCertificates.heading : "Provision Site X.509 custody"
        case .acknowledgement: finishReceiptAcknowledgement != nil ? FreshInstallQRStep.confirmInstallation.heading : "Approve signed HTTPS convergence"
        }
    }

    private var orientation: String {
        switch review.kind {
        case .bundleReceiptUnlock:
            "Unlock the existing receipt signer without provisioning or replacing its key."
        case .bundleReceiptProvision:
            "Create the distinct one-use receipt signing generation in protected custody."
        case .siteX509Provision:
            "Approve one atomic transaction for distinct fresh root and issuer keys."
        case .acknowledgement:
            "Confirm that this iPhone trusts the installation shown in the install window."
        }
    }

    private var buttonTitle: String {
        switch review.kind {
        case .bundleReceiptUnlock: "Unlock with Face ID"
        case .bundleReceiptProvision: "Provision with Face ID"
        case .siteX509Provision: "Approve both roles with Face ID"
        case .acknowledgement: "Approve with Face ID"
        }
    }

    private var isBusy: Bool {
        coordinator.phase == .authenticating || coordinator.phase == .submitting
            || coordinator.phase == .unlockingBundleReceipt
            || {
                switch coordinator.phase {
                case .acknowledgementProgress, .siteX509Progress: true
                default: false
                }
            }()
    }

    private var isAcknowledgement: Bool {
        if case .acknowledgement = review.kind { return true }
        return false
    }

    private var phaseLabel: String {
        switch coordinator.phase {
        case .authenticating: "Waiting for Face ID"
        case let .siteX509Progress(stage): stage.label
        case .unlockingBundleReceipt: "Unlocking the Site Root receipt authority"
        default: "Submitting exact proof"
        }
    }
}

private extension SiteRootAcknowledgementStage {
    var title: String {
        switch self {
        case .preparing: "Preparing approval"
        case .awaitingFaceID: "Waiting for Face ID"
        case .signing: "Signing the acknowledgement"
        case .waitingForMonas: "Waiting for Monas"
        }
    }

    var slowGuidance: String {
        switch self {
        case .preparing:
            "The installation check is taking longer than expected. Keep this screen open."
        case .awaitingFaceID:
            "Pistis has not received a Face ID result. If the prompt has not appeared, keep this screen open without starting another approval."
        case .signing:
            "Signing is still in progress. Keep this screen open without starting another approval."
        case .waitingForMonas:
            "Pistis has not received confirmation from Monas. Keep this screen open without submitting again."
        }
    }

    var detail: String {
        switch self {
        case .preparing: "Pistis is checking this installation before requesting Face ID."
        case .awaitingFaceID: "Follow the Face ID prompt to approve this exact acknowledgement."
        case .signing: "Face ID accepted. Keep Pistis open while it signs the acknowledgement."
        case .waitingForMonas: "Pistis is submitting the signed acknowledgement. Keep this screen open until Monas confirms."
        }
    }
}

extension SiteX509BrokerApprovalStageV1 {
    var label: String {
        switch self {
        case .reservingApproval:
            "Reserving this one-use Site X.509 approval"
        case .awaitingFaceID:
            "Waiting for Face ID"
        case .signingInitialProof:
            "Face ID accepted · signing the Site X.509 approval"
        case .submittingInitialProof:
            "Face ID accepted · submitting the Site X.509 approval"
        case .custodyChallenge: "Connecting to the retained custody authority"
        case .custodyAssertion: "Verifying this iPhone with App Attest"
        case .custodyRotation: "Completing authority custody"
        case let .awaitingContinuation(phase):
            "Face ID accepted · waiting for \(phase.userLabel)"
        case let .authorizingContinuation(phase):
            "Authorising \(phase.userLabel)"
        case let .submittingContinuation(phase):
            "Submitting \(phase.userLabel)"
        }
    }
}

private extension SiteX509BrokerContinuationPhaseV1 {
    var userLabel: String {
        switch self {
        case .rootUnlock: "Site Root custody unlock"
        case .issuerUnlock: "Site issuer custody unlock"
        case .ackRegistration: "host acknowledgement setup"
        case .leafApproval: "initial certificate approval"
        }
    }
}

private extension UnsignedSiteRootConvergenceAssertionV2.Action {
    var label: String {
        switch self { case .install: "Install"; case .replace: "Replace"; case .remove: "Remove" }
    }
}
