import SwiftUI

/// Displays an unverified proposal claim while historical readiness remains unknown.
/// No approval or operation control is exposed: the accepted D-064 request schema,
/// purpose issuer, and authenticated readiness receipt are not available here.
struct HistoricalUnknownSuccessorReviewV1: View {
    let proposal: HistoricalUnknownSuccessorPresentationV1

    var body: some View {
        VStack(alignment: .leading, spacing: MnSpacing.x4) {
            MnSectionHeading(
                "Review proposed successor",
                orientation: "Historical readiness must be established by authenticated evidence before any operation is authorised."
            )
            MnPanel {
                VStack(alignment: .leading, spacing: MnSpacing.x3) {
                    MnStatusLabel(text: "Historical readiness: UNKNOWN", kind: .warning)
                    LabeledContent("Claimed Site", value: proposal.site)
                    LabeledContent("Claimed vault", value: proposal.vaultIdentity)
                    LabeledContent(
                        "Consumed → proposed generation",
                        value: "\(proposal.consumedGeneration) → \(proposal.proposedGeneration)"
                    )
                    LabeledContent("Fresh host key SHA-256", value: proposal.freshHostKeyDigest)
                    LabeledContent("Unverified purpose claim", value: proposal.purposeClaim)
                    LabeledContent("Unverified request claim", value: proposal.requestIDClaim)
                    LabeledContent("Unverified contract revision", value: proposal.contractRevisionClaim)
                }
            }
            Text("This proposal is read-only. No accepted D-064 request schema or purpose issuer is available; the displayed values are claims only. No historical readiness was inferred, no credential was opened, and no successor was reserved or delivered.")
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityIdentifier("historical-unknown-successor-review")
    }
}
