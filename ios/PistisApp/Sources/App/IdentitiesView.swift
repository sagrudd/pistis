import SwiftUI

struct IdentitiesView: View {
    let identities: [IdentitySummary]
    @State private var githubReadiness = GitHubEnrolmentReadiness.current()
    @StateObject private var githubFlow = GitHubEvaluationFlow()
    @Environment(\.openURL) private var openURL

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
                        MnStatusLabel(text: githubFlow.status, kind: githubFlow.proof == nil ? .warning : .success)
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
                        if let prompt = githubFlow.prompt {
                            Text(prompt.userCode)
                                .font(.system(.title2, design: .monospaced).weight(.bold))
                                .textSelection(.enabled)
                                .accessibilityLabel("GitHub code \(prompt.userCode)")
                            Button("Open GitHub") {
                                openURL(prompt.verificationURI) { accepted in
                                    guard accepted else {
                                        githubFlow.browserOpenFailed()
                                        return
                                    }
                                    Task { await githubFlow.browserDidOpen() }
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(MnColor.action)
                            Button("I approved this code") {
                                Task { await githubFlow.resumeVerification() }
                            }
                            .buttonStyle(.bordered)
                            .disabled(!githubFlow.mayResume)
                        } else if let proof = githubFlow.proof {
                            MnEvidenceRow(
                                label: "Verified GitHub account",
                                value: proof.displayLogin ?? "Account \(proof.numericSubject)"
                            )
                            MnEvidenceRow(
                                label: "Stable numeric subject",
                                value: String(proof.numericSubject)
                            )
                            Text(
                                "Development evaluation complete. This proves the live GitHub Device Flow, but does not yet install Prosopikon authority trust on this phone."
                            )
                            .font(.footnote)
                            Button("Run again") { githubFlow.reset() }
                                .buttonStyle(.bordered)
                        } else {
                            Button("Verify with GitHub") {
                                Task { await githubFlow.start() }
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(MnColor.action)
                            .disabled(!githubReadiness.state.mayStart || githubFlow.busy)
                            .accessibilityHint("Starts the reviewed GitHub Device Flow")
                        }
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

@MainActor
private final class GitHubEvaluationFlow: ObservableObject {
    @Published private(set) var prompt: GitHubDeviceAuthorizationPrompt?
    @Published private(set) var proof: GitHubStableIdentityProof?
    @Published private(set) var status = "Ready for GitHub verification"
    @Published private(set) var busy = false
    @Published private(set) var mayResume = false

    private var coordinator: GitHubDeviceFlowCoordinator?

    func start() async {
        guard !busy,
              let configuration = GitHubEnrolmentReadiness.configuration()
        else { return }
        busy = true
        proof = nil
        mayResume = false
        status = "Requesting one-time GitHub code"
        do {
            let client = try GitHubDeviceFlowClient(
                configuration: configuration,
                transport: URLSessionGitHubDeviceFlowTransport()
            )
            let coordinator = GitHubDeviceFlowCoordinator(client: client)
            self.coordinator = coordinator
            prompt = try await coordinator.start()
            status = "Open GitHub and approve the displayed code"
        } catch {
            fail(error)
        }
        busy = false
    }

    func browserDidOpen() async {
        guard let coordinator else { return }
        do {
            try await coordinator.systemBrowserDidOpen()
            mayResume = true
            status = "Return after GitHub accepts the code"
        } catch {
            fail(error)
        }
    }

    func resumeVerification() async {
        guard !busy, mayResume, let coordinator else { return }
        busy = true
        mayResume = false
        status = "Waiting for GitHub confirmation"
        do {
            proof = try await coordinator.resumeVerification()
            prompt = nil
            status = "GitHub identity verified"
        } catch {
            fail(error)
        }
        busy = false
    }

    func browserOpenFailed() {
        status = "GitHub could not be opened"
    }

    func reset() {
        Task { await coordinator?.cancel() }
        coordinator = nil
        prompt = nil
        proof = nil
        busy = false
        mayResume = false
        status = "Ready for GitHub verification"
    }

    private func fail(_ error: Error) {
        coordinator = nil
        prompt = nil
        proof = nil
        mayResume = false
        status = "GitHub verification failed: \(String(describing: error))"
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
