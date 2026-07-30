import SwiftUI

struct HistoryView: View {
    let events: [HistoryEvent]
    let loadFailure: Bool

    var body: some View {
        List(events) { event in
            NavigationLink {
                HistoryDetailView(event: event)
            } label: {
                VStack(alignment: .leading, spacing: MnSpacing.x2) {
                    ViewThatFits {
                        HStack(alignment: .firstTextBaseline) {
                            Text(event.action)
                                .font(.headline)
                            Spacer()
                            Text(event.occurredAt)
                                .font(.caption)
                        }
                        VStack(alignment: .leading, spacing: MnSpacing.x1) {
                            Text(event.action)
                                .font(.headline)
                            Text(event.occurredAt)
                                .font(.caption)
                        }
                    }
                    Text(event.installation)
                        .font(.subheadline)
                    MnStatusLabel(
                        text: event.decision,
                        kind: successful(event.decision) ? .success : .danger
                    )
                }
                .padding(.vertical, MnSpacing.x2)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                "\(event.action), \(event.installation), \(event.decision), \(event.occurredAt)"
            )
            .accessibilityHint("Shows locally observed event details")
            .listRowBackground(MnColor.raised)
        }
        .scrollContentBackground(.hidden)
        .navigationTitle("History")
        .safeAreaInset(edge: .top) {
            Text("This device’s observations, not the installation’s authoritative audit record.")
                .font(.subheadline)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, MnMetrics.screenGutter)
                .padding(.vertical, MnSpacing.x2)
                .background(MnColor.canvas)
        }
        .overlay {
            if loadFailure {
                MnEmptyState(
                    title: "Local history unavailable",
                    explanation: "Pistis could not safely read the protected enrolment record. Unlock this device and try again.",
                    actionTitle: nil
                )
                .padding(MnMetrics.screenGutter)
            } else if events.isEmpty {
                MnEmptyState(
                    title: "No local history",
                    explanation: "Approvals and denials observed on this device will appear here. This is not the authoritative audit record.",
                    actionTitle: nil
                )
                .padding(MnMetrics.screenGutter)
            }
        }
        .mnScreenBackground()
    }

    private func successful(_ outcome: String) -> Bool {
        outcome == "Approved" || outcome == "Verified"
    }
}

private struct HistoryDetailView: View {
    let event: HistoryEvent

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnStatusLabel(
                    text: "Outcome: \(event.decision)",
                    kind: successful(event.decision) ? .success : .danger
                )
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        MnEvidenceRow(label: "Installation", value: event.installation)
                        Divider()
                        MnEvidenceRow(label: "Observed", value: event.occurredAt)
                        Divider()
                        MnEvidenceRow(label: "Device signature", value: event.signature)
                        Divider()
                        MnEvidenceRow(label: "Transfer", value: event.transfer)
                        Divider()
                        MnEvidenceRow(label: "Installation verification", value: event.verification)
                    }
                }
                Text("This local history is informational. Consult the installation audit record for authoritative evidence.")
                    .font(.footnote)
                    .foregroundStyle(MnColor.textPrimary)
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle(event.action)
        .mnScreenBackground()
    }

    private func successful(_ outcome: String) -> Bool {
        outcome == "Approved" || outcome == "Verified"
    }
}
