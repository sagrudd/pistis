import SwiftUI

/// Display only: the caller must bind confirmation to the same live attempt.
struct AttendedRecoveryComparisonView: View {
    let site: String
    let attempt: String
    let expiresAt: Date
    let comparison: Data
    let onMatch: () -> Void
    let onCancel: () -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = try? AttendedRecoveryComparison.format(comparison)
            VStack(alignment: .leading, spacing: 16) {
                Text("Compare recovery details")
                    .font(.headline)
                Text("Check that the site, attempt and all four groups match the Alma terminal.")
                LabeledContent("Site", value: site)
                LabeledContent("Attempt", value: attempt)
                LabeledContent("Expires", value: AttendedRecoveryComparison.expiry(expiresAt))
                Text(code ?? "Unavailable")
                    .font(.title2.monospaced())
                    .textSelection(.enabled)
                    .accessibilityLabel("Comparison code")
                    .accessibilityValue(code ?? "Unavailable")
                Button("The details match", action: onMatch)
                    .buttonStyle(.borderedProminent)
                    .disabled(code == nil || context.date >= expiresAt)
                Button("Cancel", role: .cancel, action: onCancel)
            }
        }
    }
}
