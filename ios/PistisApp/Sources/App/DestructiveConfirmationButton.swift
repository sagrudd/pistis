import SwiftUI

struct DestructiveConfirmationButton: View {
    let label: String
    let confirmationTitle: String
    let confirmationMessage: String
    let action: () async throws -> Void

    @State private var isConfirming = false
    @State private var busy = false
    @State private var showsFailure = false

    var body: some View {
        Button(role: .destructive) {
            isConfirming = true
        } label: {
            if busy {
                ProgressView()
                    .frame(maxWidth: .infinity)
            } else {
                Text(label)
                    .frame(maxWidth: .infinity)
            }
        }
        .buttonStyle(.bordered)
        .disabled(busy)
        .confirmationDialog(
            confirmationTitle,
            isPresented: $isConfirming,
            titleVisibility: .visible
        ) {
            Button(label, role: .destructive) {
                confirm()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(confirmationMessage)
        }
        .alert("Local record was not removed", isPresented: $showsFailure) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Nothing was deleted. Unlock this device and try again.")
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
