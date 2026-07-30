import SwiftUI

struct DestructiveConfirmationSlider: View {
    let label: String
    let confirmationLabel: String
    let action: () async throws -> Void

    @State private var position = 0.0
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: MnSpacing.x3) {
            Text(label)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(MnColor.danger)
            Slider(
                value: $position,
                in: 0 ... 1,
                onEditingChanged: { editing in
                    guard !editing else { return }
                    if position >= 0.95 {
                        confirm()
                    } else {
                        position = 0
                    }
                }
            )
            .tint(MnColor.danger)
            .disabled(busy)
            .accessibilityLabel(label)
            .accessibilityValue(position >= 0.95 ? "Ready to confirm" : "Not confirmed")
            .accessibilityHint("Adjust to the end to confirm this destructive action")

            Button(confirmationLabel, role: .destructive) {
                confirm()
            }
            .disabled(busy)
            .accessibilityHint("Accessible alternative to the confirmation slider")

            if busy {
                ProgressView("Removing local material")
            }
            if let failure {
                MnStatusLabel(text: failure, kind: .danger)
            }
        }
    }

    private func confirm() {
        guard !busy else { return }
        busy = true
        failure = nil
        Task {
            do {
                try await action()
            } catch {
                failure = "Local record was not removed"
            }
            position = 0
            busy = false
        }
    }
}
