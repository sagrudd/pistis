import SwiftUI

struct IdentitiesView: View {
    let identities: [IdentitySummary]
    @State private var githubReadiness = GitHubEnrolmentReadiness.current()

    var body: some View {
        ScrollView {
            LazyVStack(spacing: MnSpacing.x3) {
                MnSectionHeading(
                    "External identities",
                    orientation: "Review the accounts that establish who you are during enrolment."
                )
                .padding(.bottom, MnSpacing.x1)

                if identities.isEmpty {
                    MnEmptyState(
                        title: "No enrolled identities",
                        explanation: "Provider enrolment requires a configured GitHub App and has not run on this device.",
                        actionTitle: nil
                    )
                }

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x3) {
                        MnStatusLabel(
                            text: "GitHub enrolment unavailable",
                            kind: .warning
                        )
                        Text(githubReadiness.configurationLabel)
                            .font(.headline)
                        if case let .unavailable(reason) = githubReadiness.state {
                            Text(reason)
                                .font(.body)
                        }
                        Label(
                            githubReadiness.identityRule,
                            systemImage: "person.text.rectangle"
                        )
                        Label(
                            githubReadiness.credentialRule,
                            systemImage: "lock.shield"
                        )
                        Text(
                            "An email address or mutable GitHub login is not accepted as the stable provider identity."
                        )
                        .font(.footnote)
                        Button("Enrol with GitHub") {}
                            .buttonStyle(.borderedProminent)
                            .tint(MnColor.action)
                            .disabled(true)
                            .accessibilityHint(
                                "Requires the reviewed Device Flow and Prosopikon enrolment ports"
                            )
                    }
                }

                ForEach(identities) { identity in
                    NavigationLink(value: identity) {
                        MnPanel {
                            HStack(alignment: .top, spacing: MnSpacing.x3) {
                                Image(systemName: identity.provider == "GitHub" ? "chevron.left.forwardslash.chevron.right" : "person.crop.circle")
                                    .font(.title2)
                                    .foregroundStyle(MnColor.action)
                                    .frame(width: MnMetrics.minimumTarget, height: MnMetrics.minimumTarget)
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: MnSpacing.x2) {
                                    Text(identity.displayName)
                                        .font(.headline)
                                    Text(identity.provider)
                                        .font(.subheadline)
                                    Text(identity.stableSubject)
                                        .font(.caption)
                                        .foregroundStyle(MnColor.textPrimary)
                                    MnStatusLabel(text: identity.status, kind: .success)
                                }
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .foregroundStyle(.secondary)
                                    .accessibilityHidden(true)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("\(identity.provider), \(identity.displayName), \(identity.status)")
                    .accessibilityHint("Shows identity evidence")
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle("Identities")
        .navigationDestination(for: IdentitySummary.self) { identity in
            IdentityDetailView(identity: identity)
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                } label: {
                    Label("Enrolment not configured", systemImage: "plus")
                        .frame(minWidth: MnMetrics.minimumTarget, minHeight: MnMetrics.minimumTarget)
                }
                .disabled(true)
                .accessibilityHint("Requires a configured GitHub App")
            }
        }
        .mnScreenBackground()
    }
}

private struct IdentityDetailView: View {
    let identity: IdentitySummary

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnStatusLabel(text: identity.status, kind: .success)
                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        MnEvidenceRow(label: "Provider", value: identity.provider)
                        Divider()
                        MnEvidenceRow(label: "Display name", value: identity.displayName)
                        Divider()
                        MnEvidenceRow(label: "Stable provider identity", value: identity.stableSubject)
                    }
                }
                Text("Provider display names may change. Pistis binds the stable provider identity shown above.")
                    .font(.footnote)
                    .foregroundStyle(MnColor.textPrimary)
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle(identity.displayName)
        .mnScreenBackground()
    }
}
