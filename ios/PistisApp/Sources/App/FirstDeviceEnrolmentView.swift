import CryptoKit
import Security
import SwiftUI
import PistisCore

/// Attended first-device enrolment through a scanned, authority-signed
/// presentation. Provider credentials remain behind the fixed server routes.
struct FirstDeviceEnrolmentView: View {
    @StateObject private var flow = FirstDeviceEnrolmentFlow()
    @Environment(\.openURL) private var openURL

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                MnSectionHeading(
                    "First device",
                    orientation: "Scan the protected CLI presentation, then approve the one-time GitHub code."
                )
                MnStatusLabel(
                    text: flow.status,
                    kind: flow.failure == nil ? .warning : .danger
                )

                if flow.presentation == nil {
                    QRScannerCameraView(onResult: flow.handleScan)
                        .frame(minHeight: 320)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    Text(
                        "The signed invitation, server origin, application configuration and expiry are verified before Pistis contacts the server."
                    )
                    .font(.footnote)
                } else {
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnEvidenceRow(
                                label: "Installation",
                                value: flow.presentation?.installationName ?? ""
                            )
                            MnEvidenceRow(
                                label: "Authority",
                                value: flow.presentation?.httpsOrigin.host ?? ""
                            )
                            if let prompt = flow.prompt {
                                Text(prompt.userCode)
                                    .font(.system(.title2, design: .monospaced).weight(.bold))
                                    .textSelection(.enabled)
                                    .accessibilityLabel("GitHub code \(prompt.userCode)")
                                Button("Open GitHub") {
                                    openURL(prompt.verificationURI) { accepted in
                                        flow.browserOpenResult(accepted)
                                    }
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(MnColor.action)
                                Button("I approved this code") {
                                    Task { await flow.checkVerification() }
                                }
                                .buttonStyle(.bordered)
                                .disabled(flow.busy)
                            } else if let subject = flow.verifiedSubject {
                                MnEvidenceRow(
                                    label: "Verified GitHub account",
                                    value: flow.displayLogin ?? "Account \(subject)"
                                )
                                MnEvidenceRow(
                                    label: "Stable numeric subject",
                                    value: String(subject)
                                )
                                Text(
                                    "Provider verification is complete. Trust is not installed until the reviewed receipt-key bundle and authority receipt verifier are available."
                                )
                                .font(.footnote)
                            } else {
                                Button("Begin secure enrolment") {
                                    Task { await flow.begin() }
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(MnColor.action)
                                .disabled(flow.busy)
                            }
                        }
                    }
                    Button("Cancel and discard") {
                        Task { await flow.cancel() }
                    }
                    .buttonStyle(.bordered)
                }
            }
            .padding(MnMetrics.screenGutter)
        }
        .navigationTitle("Enrol first device")
        .mnScreenBackground()
    }
}

@MainActor
private final class FirstDeviceEnrolmentFlow: ObservableObject {
    @Published private(set) var presentation: VerifiedFirstDevicePresentation?
    @Published private(set) var prompt: GitHubDeviceAuthorizationPrompt?
    @Published private(set) var verifiedSubject: UInt64?
    @Published private(set) var displayLogin: String?
    @Published private(set) var status = "Ready to scan"
    @Published private(set) var failure: PlatformFailure?
    @Published private(set) var busy = false

    private var transport: ServerDrivenEnrolmentTransport?
    private var handle: ProviderVerificationHandle?

    func handleScan(_ result: Result<ScannedQRPayload, PlatformFailure>) {
        guard presentation == nil else { return }
        do {
            let payload = try result.get()
            let verified = try FirstDevicePresentationV3.verify(
                qrText: payload.text,
                expectedAppConfigurationDigest:
                    GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest,
                now: Date()
            )
            presentation = verified
            transport = ServerDrivenEnrolmentTransport(presentation: verified)
            status = "Signed presentation verified"
            failure = nil
        } catch {
            fail(error)
        }
    }

    func begin() async {
        guard !busy, let presentation, let transport else { return }
        busy = true
        defer { busy = false }
        do {
            let signer = try SecureEnclaveSigner(
                namespace: presentation.installationID.hexadecimal,
                authenticationReason: "Create this Pistis device identity"
            )
            let publicKey = try signer.create()
            let keyID = Data(SHA256.hash(
                data: Data("pistis:key-id:v1\0".utf8)
                    + publicKey.compressedSEC1
            ))
            let operationID = try secureRandom(count: 16)
            let handle = try await transport.begin(
                operationID: operationID,
                deviceKeyID: keyID,
                devicePublicKey: publicKey.compressedSEC1,
                keyAssurance: "secure-enclave-biometry-current-set"
            )
            self.handle = handle
            prompt = handle.prompt
            status = "Open GitHub and approve the displayed code"
            failure = nil
        } catch {
            fail(error)
        }
    }

    func browserOpenResult(_ accepted: Bool) {
        status = accepted
            ? "Return after GitHub accepts the code"
            : "GitHub could not be opened"
    }

    func checkVerification() async {
        guard !busy, let transport, let handle else { return }
        busy = true
        defer { busy = false }
        do {
            switch try await transport.status(handle) {
            case let .pending(pollAfter):
                status = "GitHub approval is pending; retry in \(pollAfter / 1_000) seconds"
            case let .verified(subject, login, _, _, _):
                verifiedSubject = subject
                displayLogin = login
                prompt = nil
                status = "GitHub identity verified; receipt binding is pending"
            case .denied:
                status = "GitHub denied this request"
            case .cancelled:
                status = "Enrolment was cancelled"
            case .expired:
                status = "The enrolment request expired"
            case .consumed:
                status = "This enrolment request was already consumed"
            }
        } catch {
            fail(error)
        }
    }

    func cancel() async {
        if let transport, let handle {
            try? await transport.cancel(handle)
        }
        presentation = nil
        transport = nil
        self.handle = nil
        prompt = nil
        verifiedSubject = nil
        displayLogin = nil
        failure = nil
        status = "Ready to scan"
    }

    private func secureRandom(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(
            kSecRandomDefault,
            bytes.count,
            &bytes
        ) == errSecSuccess else {
            throw PlatformFailure.randomnessUnavailable
        }
        return Data(bytes)
    }

    private func fail(_ error: Error) {
        let safe = (error as? PlatformFailure) ?? .productionEnvelopeUnavailable
        failure = safe
        status = safe.safeUserMessage
    }
}

private extension Data {
    var hexadecimal: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
