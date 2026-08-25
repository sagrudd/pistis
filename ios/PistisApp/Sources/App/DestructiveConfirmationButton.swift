import SwiftUI

struct DestructiveConfirmationButton: View {
    let label: String
    let confirmationTitle: String
    let confirmationMessage: String
    let confirmationLabel: String
    let failureTitle: String
    let failureMessage: String
    let action: () async throws -> Void

    @State private var isConfirming = false
    @State private var busy = false
    @State private var showsFailure = false

    init(
        label: String,
        confirmationTitle: String,
        confirmationMessage: String,
        confirmationLabel: String? = nil,
        failureTitle: String = "Local record was not removed",
        failureMessage: String = "Nothing was deleted. Unlock this device and try again.",
        action: @escaping () async throws -> Void
    ) {
        self.label = label
        self.confirmationTitle = confirmationTitle
        self.confirmationMessage = confirmationMessage
        self.confirmationLabel = confirmationLabel ?? label
        self.failureTitle = failureTitle
        self.failureMessage = failureMessage
        self.action = action
    }

    var body: some View {
        Button(role: .destructive) {
            isConfirming = true
        } label: {
            Group {
                if busy {
                    ProgressView()
                } else {
                    Text(label)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .font(.headline)
            .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
        }
        .buttonStyle(.borderedProminent)
        .tint(MnColor.danger)
        .disabled(busy)
        .alert(confirmationTitle, isPresented: $isConfirming) {
            Button(confirmationLabel, role: .destructive) {
                confirm()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(confirmationMessage)
        }
        .alert(failureTitle, isPresented: $showsFailure) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(failureMessage)
        }
    }

    private func confirm() {
        guard !busy else { return }
        busy = true
        Task {
            do {
                try await action()
            } catch {
                showsFailure = true
            }
            busy = false
        }
    }
}
