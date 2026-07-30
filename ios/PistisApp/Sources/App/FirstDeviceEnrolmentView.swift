import CryptoKit
import Security
import SwiftUI
import PistisCore

/// Attended first-device enrolment through a scanned, authority-signed
/// presentation. Provider credentials remain behind the fixed server routes.
struct FirstDeviceEnrolmentView: View {
    @StateObject private var flow = FirstDeviceEnrolmentFlow()
    @Environment(\.openURL) private var openURL
    @State private var trustWordOne = ""
    @State private var trustWordTwo = ""
    @State private var trustWordThree = ""

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
                            if !flow.hostTrustConfirmed {
                                Text("Do you really trust this host?")
                                    .font(.headline)
                                Text(
                                    "Type the three words shown beside the QR on the host. Pistis will not contact the host until all three match."
                                )
                                .font(.footnote)
                                HStack {
                                    trustWordField("Word 1", text: $trustWordOne)
                                    trustWordField("Word 2", text: $trustWordTwo)
                                    trustWordField("Word 3", text: $trustWordThree)
                                }
                                MnEvidenceRow(
                                    label: "Certificate key",
                                    value: flow.presentation?.tlsSPKISHA256
                                        .hexadecimal ?? ""
                                )
                                Button("Trust this host") {
                                    flow.confirmHostTrust(words: [
                                        trustWordOne,
                                        trustWordTwo,
                                        trustWordThree,
                                    ])
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(MnColor.action)
                            } else if let prompt = flow.prompt {
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
                                    flow.enrolmentComplete
                                        ? "The purpose-separated authority receipt and exact device binding were verified before installation trust was stored."
                                        : "Check this immutable GitHub identity before allowing Face ID to create the device registration."
                                )
                                .font(.footnote)
                                if !flow.enrolmentComplete {
                                    Button("Confirm account and enrol with Face ID") {
                                        Task { await flow.confirmVerifiedAccount() }
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .tint(MnColor.action)
                                    .disabled(flow.busy)
                                }
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

    private func trustWordField(
        _ label: String,
        text: Binding<String>
    ) -> some View {
        TextField(label, text: text)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .textFieldStyle(.roundedBorder)
            .accessibilityLabel(label)
    }
}

@MainActor
private final class FirstDeviceEnrolmentFlow: ObservableObject {
    @Published private(set) var presentation: VerifiedFirstDevicePresentation?
    @Published private(set) var prompt: GitHubDeviceAuthorizationPrompt?
    @Published private(set) var verifiedSubject: UInt64?
    @Published private(set) var displayLogin: String?
    @Published private(set) var enrolmentComplete = false
    @Published private(set) var hostTrustConfirmed = false
    @Published private(set) var status = "Ready to scan"
    @Published private(set) var failure: PlatformFailure?
    @Published private(set) var busy = false

    private var transport: ServerDrivenEnrolmentTransport?
    private var handle: ProviderVerificationHandle?
    private var devicePublicKey: Data?
    private var deviceKeyID: Data?
    private var pendingRegistration: Data?
    private var beginRetry = EnrolmentBeginRetryState()
    private var approvalGate = AttendedEnrolmentGate()

    func handleScan(_ result: Result<ScannedQRPayload, PlatformFailure>) {
        guard presentation == nil else { return }
        do {
            let payload = try result.get()
            let verified = try FirstDevicePresentationV4.verify(
                qrText: payload.text,
                expectedAppConfigurationDigest:
                    GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest,
                now: Date()
            )
            presentation = verified
            status = "Compare the three host verification words"
            failure = nil
        } catch {
            fail(error)
        }
    }

    func confirmHostTrust(words: [String]) {
        guard !hostTrustConfirmed, let presentation, words.count == 3 else {
            return
        }
        let entered = words.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        guard entered == presentation.trustWords else {
            failure = .invalidConfiguration
            status = "Verification words do not match. Do not trust this host."
            return
        }
        do {
            transport = try ServerDrivenEnrolmentTransport(
                presentation: presentation
            )
            hostTrustConfirmed = true
            failure = nil
            status = "Host trust confirmed; no network request has been sent"
        } catch {
            fail(error)
        }
    }

    func begin() async {
        guard !busy, hostTrustConfirmed, let presentation, let transport else {
            return
        }
        busy = true
        defer { busy = false }
        var retainExactAttempt = false
        do {
            guard try await !InstallationTrustKeychain.shared
                .hasStoredEnrollment()
            else { throw PlatformFailure.existingEnrolmentMustBeRemoved }
            let signer = try SecureEnclaveSigner(
                namespace: presentation.installationID.hexadecimal,
                authenticationReason: "Create this Pistis device identity"
            )
            let publicKey = try signer.create()
            let keyID = Data(SHA256.hash(
                data: Data("pistis:key-id:v1\0".utf8)
                    + publicKey.compressedSEC1
            ))
            let operationID = try beginRetry.operationID {
                try secureRandom(count: 16)
            }
            devicePublicKey = publicKey.compressedSEC1
            deviceKeyID = keyID
            // From this point the authority may durably accept the request
            // even if the response is lost or rejected locally. Preserve the
            // exact operation ID and device key for an idempotent retry.
            retainExactAttempt = true
            let handle = try await transport.begin(
                operationID: operationID,
                deviceKeyID: keyID,
                devicePublicKey: publicKey.compressedSEC1,
                keyAssurance: "secure-enclave-biometry-current-set"
            )
            self.handle = handle
            beginRetry.markAccepted()
            prompt = handle.prompt
            status = "Open GitHub and approve the displayed code"
            failure = nil
        } catch {
            if retainExactAttempt {
                fail(PlatformFailure.enrolmentBeginRetryRequired)
            } else {
                await discardUnenrolledKey(after: .beginFailure)
                fail(error)
            }
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
            case let .verified(
                subject,
                login,
                policyGeneration,
                authorityChallenge,
                challengeExpiry
            ):
                let approval = VerifiedProviderApproval(
                    subject: subject,
                    login: login,
                    policyGeneration: policyGeneration,
                    authorityChallenge: authorityChallenge,
                    challengeExpiry: challengeExpiry
                )
                approvalGate.recordProviderVerification(approval)
                verifiedSubject = subject
                displayLogin = login
                prompt = nil
                status = "Review the verified GitHub account before enrolling"
            case .denied:
                status = "GitHub denied this request"
                await discardUnenrolledKey(after: .denied)
            case .cancelled:
                status = "Enrolment was cancelled"
                await discardUnenrolledKey(after: .cancelled)
            case .expired:
                status = "The enrolment request expired"
                await discardUnenrolledKey(after: .expired)
            case .consumed:
                status = "Enrolment was consumed; retain this key and recover the receipt"
            }
        } catch {
            fail(error)
        }
    }

    func confirmVerifiedAccount() async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        var mayRetry = true
        do {
            let approval = try approvalGate.takeForExplicitConfirmation()
            let now = Date()
            let nowMilliseconds = UInt64(now.timeIntervalSince1970 * 1_000)
            guard nowMilliseconds < approval.challengeExpiry else {
                mayRetry = false
                approvalGate.reset()
                await discardUnenrolledKey(after: .expired)
                throw PlatformFailure.invalidConfiguration
            }
            try await completeEnrolment(
                subject: approval.subject,
                policyGeneration: approval.policyGeneration,
                authorityChallenge: approval.authorityChallenge,
                challengeExpiry: approval.challengeExpiry
            )
            approvalGate.markInstalled()
            enrolmentComplete = true
            status = "Device enrolled and authority receipt verified"
        } catch {
            if mayRetry {
                approvalGate.restoreAfterFailedConfirmation()
            } else {
                verifiedSubject = nil
                displayLogin = nil
            }
            fail(error)
        }
    }

    func cancel() async {
        if let transport, let handle {
            try? await transport.cancel(handle)
        }
        await discardUnenrolledKey(after: .cancelled)
        presentation = nil
        transport = nil
        self.handle = nil
        prompt = nil
        verifiedSubject = nil
        displayLogin = nil
        enrolmentComplete = false
        hostTrustConfirmed = false
        pendingRegistration = nil
        beginRetry.reset()
        approvalGate = AttendedEnrolmentGate()
        failure = nil
        status = "Ready to scan"
    }

    private func completeEnrolment(
        subject: UInt64,
        policyGeneration: UInt64,
        authorityChallenge: Data,
        challengeExpiry: UInt64
    ) async throws {
        guard let presentation, let transport, let handle,
              let devicePublicKey, let deviceKeyID
        else { throw PlatformFailure.invalidConfiguration }
        let binding = try EnrolmentBindingInput(
            operationID: handle.operationID,
            presentation: presentation,
            numericSubject: subject,
            devicePublicKey: devicePublicKey,
            deviceKeyID: deviceKeyID,
            policyGeneration: policyGeneration,
            authorityChallenge: authorityChallenge,
            authorityChallengeExpiresAtMilliseconds: challengeExpiry
        )
        let signer = try SecureEnclaveSigner(
            namespace: presentation.installationID.hexadecimal,
            authenticationReason: "Bind this device to the Pistis authority"
        )
        let envelope = try SecureEnclaveProductionEnvelope(
            signer: signer,
            deviceKeyID: deviceKeyID
        )
        let registration: Data
        if let pendingRegistration {
            registration = pendingRegistration
        } else {
            registration = try await envelope.produceEnvelope(
                canonicalPayload: EnrolmentBindingV1.payload(binding)
            )
            // Exact authority replay is intentionally idempotent; retain the
            // exact randomized ECDSA envelope until its receipt is installed.
            self.pendingRegistration = registration
        }
        let receipt = try await transport.confirm(
            handle,
            deviceRegistrationCOSE: registration,
            binding: binding
        )
        let output = try AuthenticatedEnrollmentOutput(
            trust: InstallationTrustRecord(
                installationID: receipt.installationID,
                displayName: receipt.installationName,
                audience: receipt.audience,
                authorisedProductAudiences: receipt.authorisedProductAudiences,
                userID: receipt.userID,
                externalIdentityID: receipt.externalIdentityID,
                fingerprint: receipt.fingerprint,
                installationKeyID: receipt.installationKeyID,
                installationPublicKey: receipt.installationPublicKey,
                authorityKeyID: receipt.authorityKeyID,
                authorityReceipt: receipt.exactReceiptCOSE,
                policyGeneration: receipt.policyGeneration,
                revocationGeneration: receipt.revocationGeneration,
                expiresAt: receipt.expiresAt,
                active: true
            ),
            responseContext: DeviceResponseContext(
                deviceID: receipt.deviceID,
                deviceKeyID: receipt.deviceKeyID,
                userID: receipt.userID,
                externalIdentityID: receipt.externalIdentityID
            ),
            allowedHosts: receipt.allowedHTTPSHosts
        )
        try await InstallationTrustKeychain.shared.installAuthenticated(output)
        pendingRegistration = nil
    }

    private func discardUnenrolledKey(
        after outcome: IncompleteEnrolmentKeyOutcome
    ) async {
        let hasStoredEnrollment = (try? await InstallationTrustKeychain.shared
            .hasStoredEnrollment()) == true
        guard UnenrolledKeyLifecycle.shouldDiscard(
            after: outcome,
            hasStoredEnrollment: hasStoredEnrollment
        ),
              let presentation,
              let signer = try? SecureEnclaveSigner(
                  namespace: presentation.installationID.hexadecimal,
                  authenticationReason: "Discard incomplete Pistis enrolment"
              )
        else { return }
        try? signer.discardUnenrolledKey()
        devicePublicKey = nil
        deviceKeyID = nil
        pendingRegistration = nil
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

struct VerifiedProviderApproval: Equatable {
    let subject: UInt64
    let login: String?
    let policyGeneration: UInt64
    let authorityChallenge: Data
    let challengeExpiry: UInt64
}

struct EnrolmentBeginRetryState {
    private(set) var retainedOperationID: Data?

    mutating func operationID(
        generate: () throws -> Data
    ) throws -> Data {
        if let retainedOperationID {
            return retainedOperationID
        }
        let generated = try generate()
        guard generated.count == 16,
              !generated.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.invalidConfiguration }
        retainedOperationID = generated
        return generated
    }

    mutating func markAccepted() {
        retainedOperationID = nil
    }

    mutating func reset() {
        retainedOperationID = nil
    }
}

struct AttendedEnrolmentGate {
    enum State: Equatable {
        case awaitingProvider
        case awaitingExplicitConfirmation(VerifiedProviderApproval)
        case confirming(VerifiedProviderApproval)
        case installed
    }

    private(set) var state: State = .awaitingProvider

    mutating func recordProviderVerification(
        _ approval: VerifiedProviderApproval
    ) {
        state = .awaitingExplicitConfirmation(approval)
    }

    mutating func takeForExplicitConfirmation() throws
        -> VerifiedProviderApproval
    {
        guard case let .awaitingExplicitConfirmation(approval) = state else {
            throw PlatformFailure.invalidConfiguration
        }
        state = .confirming(approval)
        return approval
    }

    mutating func markInstalled() {
        guard case .confirming = state else { return }
        state = .installed
    }

    mutating func restoreAfterFailedConfirmation() {
        guard case let .confirming(approval) = state else { return }
        state = .awaitingExplicitConfirmation(approval)
    }

    mutating func reset() {
        state = .awaitingProvider
    }
}

private extension Data {
    var hexadecimal: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
