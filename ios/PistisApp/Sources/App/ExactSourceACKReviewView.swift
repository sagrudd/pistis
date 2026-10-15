import SwiftUI
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
struct ExactSourceACKReviewView: View {
    let kind: ExactSourceACKBody.Kind
    @State private var prepared: ExactSourceACKCeremony?
    @State private var pending: ExactSourceACKPendingReview?
    @State private var operation: Task<Void, Never>?
    @State private var message: String?
    @State private var terminal = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(kind == .enrollment ? "Review source issuer enrollment" : "Review source qualification").font(.title2)
                if let prepared {
                    Text(prepared.summary).textSelection(.enabled)
                    Button("Approve these exact details with Face ID") {
                        guard operation == nil, !terminal else { return }
                        terminal = true
                        operation = Task { @MainActor in
                            do { try await prepared.confirm(); message = "Approval retained by the current authority." }
                            catch { message = "Approval stopped. Start again through the current authority." }
                            operation = nil
                        }
                    }.disabled(terminal || operation != nil)
                } else {
                    Text("Load the current request from your enrolled authority, review all details, then choose whether to approve.")
                    Button("Load current request") {
                        guard operation == nil, !terminal else { return }
                        operation = Task { @MainActor in
                            do {
                                if let pending { prepared = try await ExactSourceACKCeremony.resumeCurrent(pending) }
                                else { prepared = try await ExactSourceACKCeremony.prepareCurrent(kind: kind) }
                                pending = nil
                            }
                            catch ExactSourceACKPreparationError.witnessesPending(let current) {
                                pending = current
                                message = "The review subject is ready. Complete the required owner records, then load it again before it expires."
                            }
                            catch { message = "No current request is available for this enrolled device."; terminal = true }
                            operation = nil
                        }
                    }.disabled(operation != nil || terminal)
                }
                if operation != nil { ProgressView() }
                if let message { Text(message).accessibilityAddTraits(.updatesFrequently) }
            }.padding()
        }.onDisappear { prepared?.cancel(); pending?.cancel(); pending = nil; operation?.cancel(); terminal = true }
    }
}
#endif
