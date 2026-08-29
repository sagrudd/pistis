import SwiftUI
import CoreImage.CIFilterBuiltins
import CoreTransferable
import UniformTypeIdentifiers
#if canImport(UIKit)
import UIKit
#endif
import PistisCore

/// The generic scanner's bounded discriminator for the two `PISTIS1` uses.
///
/// First-device presentations are verified before they are handed to the
/// enrolment view. Ordinary authentication frames continue to the existing
/// production ceremony, and malformed or expired enrolment frames therefore
/// cannot be upgraded into a different route.
enum GenericScanRoute: Equatable {
    case firstDeviceEnrolment
    case invalidFirstDevicePresentation
    case ordinaryAuthentication

    static func classify(_ text: String, now: Date = Date()) -> Self {
        guard text.hasPrefix("PISTIS1:") else { return .ordinaryAuthentication }
        do {
            _ = try FirstDevicePresentationV4.verify(
                qrText: text,
                expectedAppConfigurationDigest:
                    GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest,
                now: now
            )
            return .firstDeviceEnrolment
        } catch {
            // Both first-device and ordinary authentication use the same
            // PISTIS1 transport prefix. Only a payload which is neither a
            // verified first-device presentation nor a valid ordinary
            // authentication challenge is a malformed first-device route.
            do {
                _ = try ProductionQRV2.decodeChallenge(text)
                return .ordinaryAuthentication
            } catch {
                // Older ordinary-authentication fixtures use the same
                // transport with its legacy checksum. Preserve that route by
                // recognising its authenticated outer-frame shape; the
                // ordinary ceremony still performs the complete verification.
                if isOrdinaryAuthenticationFrame(text) {
                    return .ordinaryAuthentication
                }
                return .invalidFirstDevicePresentation
            }
        }
    }

    private static func isOrdinaryAuthenticationFrame(_ text: String) -> Bool {
        guard let separator = text.lastIndex(of: "."),
              text.hasPrefix("PISTIS1:")
        else { return false }
        let bodyStart = text.index(text.startIndex, offsetBy: 8)
        let body = String(text[bodyStart ..< separator])
        var padded = body.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        guard let frame = Data(base64Encoded: padded) else { return false }
        if frame.first == 0xa3 {
            return true
        }
        // The original ordinary-authentication frame is a four-entry map
        // whose first two pairs are version 1/kind 1. First-device frames use
        // version 4/kind 3 and therefore cannot satisfy this shape.
        return frame.starts(with: [0xa4, 0x00, 0x01, 0x01, 0x01, 0x02])
    }
}

/// Pure routing for the JSON families admitted by the generic scanner.
/// Every selected coordinator still performs its own strict protocol parse.
enum MonasJSONScanRoute: Equatable {
    case siteOriginRelocation
    case siteRootConvergence
    case mtgsRecovery
    case siteRootDelegation

    static func classify(_ text: String) -> Self {
        if text.contains(SiteOriginRelocationProfileV1.presentationSchema) {
            return .siteOriginRelocation
        }
        if text.contains(SiteRootConvergenceProfileV2.x509ContinuationRecoverySchema)
            || text.contains(SiteRootConvergenceProfileV2.x509BrokerProvisionSchema)
            || text.contains(SiteRootConvergenceProfileV2.x509ProvisionSchema)
            || text.contains(SiteRootConvergenceProfileV2.provisionSchema)
            || text.contains(SiteRootConvergenceProfileV2.ackSchema)
        {
            return .siteRootConvergence
        }
        if text.contains("\"schema\":\"")
            && text.contains(MTGSRecoveryPresentationV1.schema)
        {
            return .mtgsRecovery
        }
        return .siteRootDelegation
    }
}

private struct FirstDeviceScanRequest: Identifiable {
    let id = UUID()
    let qrText: String
}

struct ScanView: View {
    @StateObject private var ceremony = ProductionCeremonyCoordinator()
    @StateObject private var siteRootCeremony: SiteRootDelegationCoordinator
    @StateObject private var mtgsRecovery: MTGSRecoveryCoordinator
    @StateObject private var siteRootConvergence: SiteRootConvergenceCoordinator
    @StateObject private var siteOriginRelocation: SiteOriginRelocationCoordinator
    @StateObject private var siteX509Offline = SiteX509FirstProvisionOfflineCoordinator()
    @StateObject private var appAttestReplacement = AppAttestKeyReplacementCoordinatorV1()
    private let siteRootTransport: any MonasSiteRootCeremonyTransport
    private let appAttestReplacementTransport: MonasAppAttestTransport?
    private let expectedSiteRootAuthorityHost: String?
    private let showInstallations: () -> Void
    private let prepareOrdinaryLogin: () async throws -> Void
    private let ordinaryLoginCompleted: () -> Void
    @State private var scanning = true
    @State private var importingOfflinePresentation = false
    @State private var importingAppAttestReplacement = false
    @State private var firstDeviceScanRequest: FirstDeviceScanRequest?
    @State private var scanFailure: PlatformFailure?
    @State private var readiness = PasswordlessReadiness.checking

    init(
        siteRootTransport: any MonasSiteRootCeremonyTransport,
        expectedSiteRootAuthorityHost: String? = nil,
        authorityCustodyMode: FirstAuthorityCustodyModeV2 = .rotation,
        showInstallations: @escaping () -> Void = {},
        prepareOrdinaryLogin: @escaping () async throws -> Void = {},
        ordinaryLoginCompleted: @escaping () -> Void = {}
    ) {
        self.siteRootTransport = siteRootTransport
        self.expectedSiteRootAuthorityHost = expectedSiteRootAuthorityHost
        self.showInstallations = showInstallations
        self.prepareOrdinaryLogin = prepareOrdinaryLogin
        self.ordinaryLoginCompleted = ordinaryLoginCompleted
        if let pinned = siteRootTransport as? MonasSiteRootDelegationTransport {
            appAttestReplacementTransport = try? pinned.appAttestTransport()
        } else {
            appAttestReplacementTransport = nil
        }
        _siteRootCeremony = StateObject(
            wrappedValue: SiteRootDelegationCoordinator(
                transport: siteRootTransport, authorityCustodyMode: authorityCustodyMode
            )
        )
        let recoveryService: any MTGSRecoveryExecuting
        if let pinned = siteRootTransport as? MonasSiteRootDelegationTransport,
           let production = try? ProductionMTGSRecoveryService(siteRootTransport: pinned)
        {
            recoveryService = production
        } else {
            recoveryService = UnavailableMTGSRecoveryService()
        }
        _mtgsRecovery = StateObject(wrappedValue: MTGSRecoveryCoordinator(
            authorityOrigin: siteRootTransport.genesisAuthorityOrigin,
            service: recoveryService
        ))
        let convergenceTransport: (any MonasSiteRootConvergenceSubmitting)?
        let brokerConvergenceTransport = try? MonasSiteX509FirstProvisionBrokerTransport()
        let convergenceAuthorityOrigin: URL?
        if let pinned = siteRootTransport as? MonasSiteRootDelegationTransport {
            convergenceTransport = try? pinned.siteRootConvergenceTransport()
            convergenceAuthorityOrigin = pinned.genesisAuthorityOrigin
        } else {
            // The fixed install broker is the only allowed first-phase
            // transport before the customer appliance has a Site Root
            // authority profile. Direct authority phases remain unavailable.
            convergenceTransport = brokerConvergenceTransport
            convergenceAuthorityOrigin = nil
        }
        _siteRootConvergence = StateObject(wrappedValue: SiteRootConvergenceCoordinator(
            transport: convergenceTransport,
            brokerTransport: brokerConvergenceTransport,
            authorityOrigin: convergenceAuthorityOrigin
        ))
        _siteOriginRelocation = StateObject(wrappedValue: SiteOriginRelocationCoordinator(
            authorityTransport: siteRootTransport as? MonasSiteRootDelegationTransport
        ))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MnSpacing.x6) {
                MnSectionHeading(
                    "Scan a Pistis or Monas request",
                    orientation: "Point the camera at a supported QR code. Captured frames are not saved."
                )

                ZStack {
                    RoundedRectangle(cornerRadius: MnRadius.large)
                        .fill(MnColor.textPrimary)
                        .aspectRatio(1, contentMode: .fit)
                    if scanning {
                        QRScannerCameraView(
                            profile: .pistisAuthenticationOrMonasSiteRoot,
                            onResult: handleScan
                        )
                            .clipShape(RoundedRectangle(cornerRadius: MnRadius.large))
                            .aspectRatio(1, contentMode: .fill)
                        Image(systemName: "viewfinder")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 160, height: 160)
                            .foregroundStyle(MnColor.onBrand)
                            .accessibilityHidden(true)
                    } else {
                        Image(systemName: "qrcode.viewfinder")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 112, height: 112)
                            .foregroundStyle(MnColor.onBrand)
                            .accessibilityHidden(true)
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(scanning ? "Scanning for a supported QR code" : "Pistis camera unavailable")

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x2) {
                        MnStatusLabel(
                            text: statusText,
                            kind: statusKind
                        )
                        Text("Only bounded Pistis v2 and Monas Site Root v1 envelopes are acquired. Each reaches its own mandatory protocol validator before facts are shown.")
                            .font(.footnote)
                            .foregroundStyle(MnColor.textPrimary)
                            .background(MnColor.raised)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Button {
                    importingOfflinePresentation = true
                } label: {
                    Label("Import first Site HTTPS challenge", systemImage: "doc.badge.plus")
                }
                .font(.headline)
                .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
                .buttonStyle(.borderedProminent)
                .tint(MnColor.action)
                .foregroundStyle(MnColor.onBrand)

                Button {
                    importingAppAttestReplacement = true
                } label: {
                    Label("Import App Attest replacement file", systemImage: "key.horizontal")
                }
                .font(.headline)
                .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
                .buttonStyle(.bordered)
                .disabled(appAttestReplacementTransport == nil)

                MnPanel {
                    VStack(alignment: .leading, spacing: MnSpacing.x4) {
                        MnStatusLabel(
                            text: readiness.approvalEnabled
                                ? "Passwordless approval ready"
                                : "Passwordless approval unavailable",
                            kind: readiness.approvalEnabled ? .success : .warning
                        )
                        ForEach(readiness.items) { item in
                            ReadinessRow(item: item)
                        }
                        if !readiness.approvalEnabled {
                            Text("Approve remains disabled until every capability and trust check is ready.")
                                .font(.footnote.weight(.semibold))
                                .foregroundStyle(MnColor.textPrimary)
                                .background(MnColor.raised)
                        }
                    }
                }

                if let scanFailure {
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnStatusLabel(text: "Scan failed", kind: .danger)
                            Text(scanFailure.safeUserMessage)
                                .foregroundStyle(MnColor.textPrimary)
                                .background(MnColor.raised)
                            if scanFailure == .cameraPermissionDenied {
                                Button("Open Settings") { openCameraSettings() }
                                    .font(.headline)
                                    .frame(minHeight: MnMetrics.minimumTarget)
                            }
                        }
                    }
                }

            }
            .padding(MnMetrics.screenGutter)
            .padding(.bottom, MnSpacing.x8 * 3)
        }
        .navigationTitle("Scan")
        .mnScreenBackground()
        .task {
            appAttestReplacement.restoreRetainedSubmission()
            readiness = await PasswordlessReadinessProbe.current()
        }
        .onAppear { startScanning() }
        .onDisappear { stopScanning() }
        .onChange(of: ceremony.phase) { _, phase in
            guard case let .terminal(status) = phase,
                  status.state == .completed
            else { return }
            ceremony.reset()
            ordinaryLoginCompleted()
        }
        .sheet(item: reviewBinding) { request in
            ApprovalView(request: request, coordinator: ceremony)
        }
        .sheet(item: siteRootReviewBinding) { review in
            SiteRootDelegationReviewView(
                review: review,
                coordinator: siteRootCeremony,
                showInstallations: showInstallations
            )
        }
        .sheet(item: mtgsRecoveryReviewBinding) { review in
            MTGSRecoveryReviewView(review: review, coordinator: mtgsRecovery)
        }
        .sheet(item: siteRootConvergenceReviewBinding) { review in
            SiteRootConvergenceReviewView(review: review, coordinator: siteRootConvergence)
        }
        .sheet(item: siteOriginRelocationReviewBinding) { review in
            SiteOriginRelocationReviewView(review: review, coordinator: siteOriginRelocation)
        }
        .sheet(item: siteX509OfflineReviewBinding) { review in
            SiteX509FirstProvisionOfflineReviewView(review: review, coordinator: siteX509Offline)
        }
        .sheet(item: appAttestReplacementReviewBinding) { review in
            AppAttestKeyReplacementReviewView(
                review: review,
                coordinator: appAttestReplacement,
                transport: appAttestReplacementTransport
            )
        }
        .sheet(item: $firstDeviceScanRequest) { request in
            FirstDeviceEnrolmentView(initialQRText: request.qrText)
        }
        .fileImporter(
            isPresented: $importingOfflinePresentation,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            handleOfflinePresentationFile(result)
        }
        .fileImporter(
            isPresented: $importingAppAttestReplacement,
            allowedContentTypes: [.json, .data],
            allowsMultipleSelection: false
        ) { result in
            handleAppAttestReplacementFile(result)
        }
    }

    @MainActor
    private func handleScan(_ result: Result<ScannedQRPayload, PlatformFailure>) {
        scanning = false
        switch result {
        case let .success(payload):
            scanFailure = nil
            if payload.text.hasPrefix(SiteX509FirstProvisionOfflineProfileV2.presentationQRPrefix) {
                siteX509Offline.accept(qrText: payload.text)
                if case .failed = siteX509Offline.phase {
                    scanFailure = siteX509Offline.failure ?? .productionEnvelopeUnavailable
                }
                return
            }
            if payload.text.hasPrefix("{") {
                switch MonasJSONScanRoute.classify(payload.text) {
                case .siteOriginRelocation:
                    siteOriginRelocation.accept(qrText: payload.text)
                    if case .failed = siteOriginRelocation.phase {
                        scanFailure = .siteRootAuthorityUnavailable
                    }
                    return
                case .siteRootConvergence:
                    siteRootConvergence.accept(qrText: payload.text)
                    if case let .failed(failure) = siteRootConvergence.phase {
                        scanFailure = failure
                    }
                    return
                case .mtgsRecovery:
                    mtgsRecovery.accept(qrText: payload.text)
                    if case let .failed(failure) = mtgsRecovery.phase {
                        scanFailure = failure
                    }
                    return
                case .siteRootDelegation:
                    siteRootCeremony.accept(qrText: payload.text)
                    if let review = siteRootCeremony.presentedReview,
                       let pinned = siteRootTransport as? MonasSiteRootDelegationTransport,
                       !pinned.isConfiguredAuthorityHost(review.destination)
                    {
                        siteRootCeremony.reject(.siteRootAuthorityUnavailable)
                        scanFailure = .siteRootAuthorityUnavailable
                        return
                    }
                    if case let .failed(failure) = siteRootCeremony.phase {
                        scanFailure = failure
                    }
                    return
                }
            }
            switch GenericScanRoute.classify(payload.text) {
            case .firstDeviceEnrolment:
                firstDeviceScanRequest = FirstDeviceScanRequest(qrText: payload.text)
                return
            case .invalidFirstDevicePresentation:
                scanFailure = .invalidFirstDevicePresentation
                return
            case .ordinaryAuthentication:
                break
            }
            Task {
                await ceremony.accept(qrText: payload.text)
                if case let .failed(failure) = ceremony.phase {
                    scanFailure = failure
                    return
                }
                await ceremony.approveVerifiedLoginIntent(
                    prepareCustody: prepareOrdinaryLogin
                )
                if case let .failed(failure) = ceremony.phase {
                    scanFailure = failure
                }
            }
        case let .failure(failure):
            guard failure != .operationCancelled else { return }
            scanFailure = failure
        }
    }

    private func startScanning() {
        ceremony.reset()
        scanFailure = nil
        scanning = true
    }

    private func stopScanning() {
        scanning = false
    }

    private func openCameraSettings() {
#if canImport(UIKit)
        guard let settings = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(settings)
#endif
    }

    @MainActor
    private func handleOfflinePresentationFile(_ result: Result<[URL], Error>) {
        guard case let .success(urls) = result, urls.count == 1 else {
            scanFailure = .qrPayloadUnsupported
            return
        }
        let url = urls[0]
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let values = try url.resourceValues(forKeys: [
                .fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey,
            ])
            guard values.isRegularFile == true, values.isSymbolicLink != true,
                  let size = values.fileSize, size > 0,
                  size <= SiteX509FirstProvisionOfflineProfileV2.maximumPresentationFileBytes
            else { throw PlatformFailure.qrPayloadUnsupported }
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let bytes = try handle.read(
                upToCount: SiteX509FirstProvisionOfflineProfileV2.maximumPresentationFileBytes + 1
            ) ?? Data()
            guard bytes.count == size else { throw PlatformFailure.qrPayloadUnsupported }
            scanning = false
            siteX509Offline.accept(fileBytes: bytes)
            if case .failed = siteX509Offline.phase {
                scanFailure = siteX509Offline.failure ?? .productionEnvelopeUnavailable
            } else {
                scanFailure = nil
            }
        } catch {
            scanFailure = .qrPayloadUnsupported
        }
    }

    @MainActor
    private func handleAppAttestReplacementFile(_ result: Result<[URL], Error>) {
        guard appAttestReplacementTransport != nil,
              case let .success(urls) = result, urls.count == 1
        else {
            scanFailure = .productionEnvelopeUnavailable
            return
        }
        let url = urls[0]
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let values = try url.resourceValues(forKeys: [
                .fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey,
            ])
            guard values.isRegularFile == true, values.isSymbolicLink != true,
                  let size = values.fileSize, size > 0,
                  size <= AppAttestKeyReplacementOfflineProfileV1.maximumJSONBytes
            else { throw PlatformFailure.productionEnvelopeUnavailable }
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let bytes = try handle.read(
                upToCount: AppAttestKeyReplacementOfflineProfileV1.maximumJSONBytes + 1
            ) ?? Data()
            guard bytes.count == size else {
                throw PlatformFailure.productionEnvelopeUnavailable
            }
            scanning = false
            appAttestReplacement.accept(fileBytes: bytes)
            if case .failed = appAttestReplacement.phase {
                scanFailure = .productionEnvelopeUnavailable
            } else {
                scanFailure = nil
            }
        } catch {
            scanFailure = .productionEnvelopeUnavailable
        }
    }

    private func resetSiteRoot() {
        siteRootCeremony.reset()
    }

    private var reviewBinding: Binding<ApprovalRequest?> {
        Binding {
            ceremony.presentedRequest
        } set: { value in
            if value == nil {
                ceremony.reset()
                startScanning()
            }
        }
    }

    private var siteRootReviewBinding: Binding<SiteRootDelegationReview?> {
        Binding {
            siteRootCeremony.presentedReview
        } set: { value in
            if value == nil {
                resetSiteRoot()
                startScanning()
            }
        }
    }

    private var mtgsRecoveryReviewBinding: Binding<MTGSRecoveryReview?> {
        Binding {
            mtgsRecovery.presentedReview
        } set: { value in
            if value == nil {
                mtgsRecovery.reset()
                startScanning()
            }
        }
    }

    private var siteRootConvergenceReviewBinding: Binding<SiteRootConvergenceReview?> {
        Binding {
            siteRootConvergence.presentedReview
        } set: { value in
            if value == nil {
                siteRootConvergence.reset()
                startScanning()
            }
        }
    }

    private var siteOriginRelocationReviewBinding: Binding<SiteOriginRelocationReview?> {
        Binding {
            siteOriginRelocation.presentedReview
        } set: { value in
            if value == nil { siteOriginRelocation.reset(); startScanning() }
        }
    }

    private var siteX509OfflineReviewBinding: Binding<SiteX509FirstProvisionOfflineReview?> {
        Binding {
            siteX509Offline.presentedReview
        } set: { value in
            if value == nil { siteX509Offline.reset(); startScanning() }
        }
    }

    private var appAttestReplacementReviewBinding: Binding<AppAttestKeyReplacementReviewV1?> {
        Binding {
            appAttestReplacement.presentedReview
        } set: { value in
            if value == nil { appAttestReplacement.reset(); startScanning() }
        }
    }

    private var statusText: String {
        switch ceremony.phase {
        case .verifying: "Verifying enrolled installation"
        case .review: "Verified request ready for review"
        case .preparing: "Preparing verified sign-in"
        default: scanning ? "Camera active" : "Ready to scan"
        }
    }

    private var statusKind: MnStatusKind {
        switch ceremony.phase {
        case .review: .success
        case .verifying, .preparing: .warning
        default: .neutral
        }
    }

}

private struct SiteX509FirstProvisionOfflineReviewView: View {
    let review: SiteX509FirstProvisionOfflineReview
    @ObservedObject var coordinator: SiteX509FirstProvisionOfflineCoordinator
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                    MnSectionHeading(
                        "Approve first Site HTTPS",
                        orientation: "Verify the Site, enrolled device, managed target and every private-IP service before Face ID."
                    )
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnEvidenceRow(label: "Site", value: review.site); Divider()
                            MnEvidenceRow(label: "Generations", value: review.generations); Divider()
                            MnEvidenceRow(label: "Enrolled device", value: review.enrolledDevice); Divider()
                            MnEvidenceRow(label: "Managed target", value: review.target); Divider()
                            MnEvidenceRow(label: "Services and private IPs", value: review.services); Divider()
                            MnEvidenceRow(label: "Expires", value: review.expiry)
                        }
                    }
                    switch coordinator.phase {
                    case .review:
                        MnPrimaryButton("Approve with Face ID", systemImage: "faceid") {
                            Task { await coordinator.approve() }
                        }
                    case .approving:
                        ProgressView("Creating Site-root approval and App Attest proof…")
                    case .completed:
                        if let text = coordinator.responseQRText,
                           let image = Self.qrImage(text) {
                            MnStatusLabel(text: "Return this one-use response to Monas", kind: .success)
                            Image(uiImage: image).interpolation(.none).resizable()
                                .scaledToFit().accessibilityLabel("One-use Site HTTPS approval QR")
                            ShareLink(item: text) { Label("Share response file text", systemImage: "square.and.arrow.up") }
                            Button("Done") { dismiss() }.font(.headline)
                        }
                    case .failed:
                        MnStatusLabel(text: "Approval stopped safely", kind: .danger)
                        Text(coordinator.failure?.safeUserMessage
                             ?? "No authority, trust exception or replacement enrolment was created.")
                    case .idle: EmptyView()
                    }
                }.padding(MnMetrics.screenGutter)
            }
            .navigationTitle("First Site HTTPS")
            .mnScreenBackground()
        }
        .interactiveDismissDisabled(coordinator.phase == .approving)
    }

    private static func qrImage(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8); filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let context = CIContext()
        guard let cg = context.createCGImage(output.transformed(by: .init(scaleX: 8, y: 8)), from: output.extent.applying(.init(scaleX: 8, y: 8))) else { return nil }
        return UIImage(cgImage: cg)
    }
}

private struct AppAttestReplacementResponseDocument: Transferable {
    let bytes: Data

    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .json) { document in
            document.bytes
        }
        .suggestedFileName("pistis-app-attest-key-replacement-response.json")
    }
}

private struct AppAttestKeyReplacementReviewView: View {
    let review: AppAttestKeyReplacementReviewV1
    @ObservedObject var coordinator: AppAttestKeyReplacementCoordinatorV1
    let transport: MonasAppAttestTransport?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                    MnSectionHeading(
                        "Replace unavailable App Attest key",
                        orientation: "Verify the protected Site and old server key before Face ID stages one fresh candidate."
                    )
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnEvidenceRow(label: "Site", value: review.site)
                            Divider()
                            MnEvidenceRow(label: "Installation and device", value: review.device)
                            Divider()
                            MnEvidenceRow(label: "Protected old key", value: review.currentKey, monospaced: true)
                            Divider()
                            MnEvidenceRow(label: "Generation", value: review.authority)
                            Divider()
                            MnEvidenceRow(label: "Expires", value: review.expiry)
                        }
                    }
                    Text("This file-first recovery may stage a candidate when this iPhone's local key differs. It cannot promote that key until the fixed pinned Monas route authenticates an exact accepted result.")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)

                    switch coordinator.phase {
                    case .review:
                        MnPrimaryButton("Approve replacement with Face ID", systemImage: "faceid") {
                            Task { await coordinator.approve() }
                        }
                    case .producing:
                        ProgressView("Waiting for Face ID and App Attest…")
                    case .responseReady:
                        if let bytes = coordinator.responseFileBytes {
                            MnStatusLabel(text: "Replacement response ready", kind: .success)
                            ShareLink(
                                item: AppAttestReplacementResponseDocument(bytes: bytes),
                                preview: SharePreview("App Attest replacement response")
                            ) {
                                Label("Share response file", systemImage: "square.and.arrow.up")
                            }
                            if let transport {
                                MnPrimaryButton("Submit securely to Monas", systemImage: "lock.shield") {
                                    Task { await coordinator.submitAndCommit(using: transport) }
                                }
                            }
                        }
                    case .submitting:
                        ProgressView("Waiting for authenticated Monas acceptance…")
                    case .accepted:
                        MnStatusLabel(text: "Replacement accepted and committed", kind: .success)
                        Button("Done") { coordinator.reset(); dismiss() }
                            .font(.headline)
                    case .failed:
                        MnStatusLabel(text: "Replacement stopped safely", kind: .danger)
                        Text("The current local key and any retained recovery record remain fail-closed.")
                        Button("Close") { dismiss() }.font(.headline)
                    case .idle:
                        EmptyView()
                    }
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("App Attest replacement")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(coordinator.phase == .producing || coordinator.phase == .submitting)
                }
            }
            .mnScreenBackground()
        }
        .interactiveDismissDisabled(
            coordinator.phase == .producing || coordinator.phase == .submitting
        )
    }
}

private struct SiteOriginRelocationReviewView: View {
    let review: SiteOriginRelocationReview
    @ObservedObject var coordinator: SiteOriginRelocationCoordinator
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                    MnSectionHeading(
                        "Move this Site authority",
                        orientation: "Verify both private-IP HTTPS origins before Face ID authorises one forward-only move."
                    )
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnEvidenceRow(label: "Site identity", value: review.siteIdentity)
                            Divider()
                            MnEvidenceRow(label: "Current origin", value: review.sourceOrigin)
                            Divider()
                            MnEvidenceRow(label: "Proposed origin", value: review.targetOrigin)
                            Divider()
                            MnEvidenceRow(label: "Generations", value: review.generations)
                        }
                    }
                    Text(review.warning).font(.headline).foregroundStyle(MnColor.danger)
                    switch coordinator.phase {
                    case .review:
                        MnPrimaryButton("Approve move with Face ID", systemImage: "faceid") {
                            Task { await coordinator.approve() }
                        }
                        Button("Cancel prepared move") { Task { await coordinator.cancel() } }
                            .font(.headline).foregroundStyle(MnColor.danger)
                    case .approving:
                        ProgressView("Waiting for Face ID and App Attest…")
                    case .reconciling:
                        ProgressView("Reconciling authoritative Monas status…")
                    case .completed:
                        MnStatusLabel(text: "Site authority move approved", kind: .success)
                        Button("Done") { dismiss() }.font(.headline)
                    case .cancelled:
                        MnStatusLabel(text: "Prepared move cancelled", kind: .neutral)
                        Button("Done") { dismiss() }.font(.headline)
                    case .failed:
                        MnStatusLabel(text: "Move stopped safely", kind: .danger)
                        Text("No trust exception, replacement enrolment or repeated approval was attempted.")
                    case .idle: EmptyView()
                    }
                }.padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Site authority move")
            .mnScreenBackground()
        }
        .interactiveDismissDisabled(coordinator.phase == .approving || coordinator.phase == .reconciling)
    }
}

private struct MTGSRecoveryReviewView: View {
    let review: MTGSRecoveryReview
    @ObservedObject var coordinator: MTGSRecoveryCoordinator
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                    MnSectionHeading(
                        "Recover retained Site Trust setup",
                        orientation: "Confirm the fixed authority before Face ID authorises one fresh App Attest assertion."
                    )
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x3) {
                            MnEvidenceRow(label: "Authority", value: review.destination)
                            Divider()
                            MnEvidenceRow(label: "Site Trust domain", value: review.siteTrustDomain)
                            Divider()
                            MnEvidenceRow(label: "Recovery reference", value: review.reference)
                        }
                    }
                    switch coordinator.phase {
                    case .review:
                        MnPrimaryButton("Approve recovery with Face ID", systemImage: "faceid") {
                            Task { await coordinator.approve() }
                        }
                        Button("Deny") { coordinator.reset(); dismiss() }
                            .font(.headline)
                            .foregroundStyle(MnColor.danger)
                            .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
                    case .attending:
                        MnStatusLabel(text: "Waiting for Face ID and device assertion", kind: .warning)
                    case .submitted:
                        MnStatusLabel(text: "Recovery assertion accepted by Monas", kind: .success)
                        Button("Done") { coordinator.reset(); dismiss() }
                    case let .failed(failure):
                        MnStatusLabel(text: "Recovery not completed", kind: .danger)
                        Text(failure.safeUserMessage)
                        Button("Close") { coordinator.reset(); dismiss() }
                    case .idle:
                        EmptyView()
                    }
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Site Trust recovery")
            .mnScreenBackground()
        }
    }
}

private struct ReadinessRow: View {
    let item: ReadinessItem

    var body: some View {
        HStack(alignment: .top, spacing: MnSpacing.x3) {
            Image(systemName: symbol)
                .foregroundStyle(color)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: MnSpacing.x1) {
                Text(item.title)
                    .font(.subheadline.weight(.semibold))
                Text(item.detail)
                    .font(.footnote)
                    .foregroundStyle(MnColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(item.title): \(stateLabel). \(item.detail)")
    }

    private var symbol: String {
        switch item.state {
        case .ready: "checkmark.circle.fill"
        case .actionRequired: "exclamationmark.circle.fill"
        case .unavailable: "xmark.octagon.fill"
        case .checking: "ellipsis.circle.fill"
        }
    }

    private var color: Color {
        switch item.state {
        case .ready: MnColor.success
        case .actionRequired: MnColor.warning
        case .unavailable: MnColor.danger
        case .checking: MnColor.textPrimary
        }
    }

    private var stateLabel: String {
        switch item.state {
        case .ready: "Ready"
        case .actionRequired: "Action required"
        case .unavailable: "Unavailable"
        case .checking: "Checking"
        }
    }
}

private struct SiteRootDelegationReviewView: View {
    let review: SiteRootDelegationReview
    @ObservedObject var coordinator: SiteRootDelegationCoordinator
    let showInstallations: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                    MnSectionHeading(
                        review.isFirstDevice
                            ? "Register first Site Root device"
                            : "Review Site Root delegation",
                        orientation: review.isFirstDevice
                            ? "Face ID creates or uses this iPhone’s protected Site Root key. Monas then issues one exact, short-lived delegation."
                            : "Face ID signs one exact, short-lived Monas delegation. It does not grant authority on its own."
                    )

                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x4) {
                            MnEvidenceRow(label: "Delegation", value: review.reference, monospaced: true)
                            Divider()
                            MnEvidenceRow(label: "Device key", value: review.deviceKeyFingerprint, monospaced: true)
                            Divider()
                            MnEvidenceRow(label: "Monas destination", value: review.destination)
                        }
                    }

                    Text(review.isFirstDevice
                        ? "Only redacted public facts are shown. Pistis submits a typed public key and Apple App Attest registration to Monas’s fixed pinned authority. It does not export private material, use a software fallback, or create browser or local authority."
                        : "Only redacted public facts are shown. Pistis will use the separate Secure Enclave Site Root key and will not export private material, use a software fallback, or claim Apple attestation.")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)

                    switch coordinator.phase {
                    case .review:
                        MnPrimaryButton(
                            review.isFirstDevice
                                ? "Register with Face ID"
                                : "Sign with Face ID",
                            systemImage: "faceid"
                        ) {
                            Task { await coordinator.approve() }
                        }
                        Button("Deny") {
                            coordinator.cancel()
                            dismiss()
                        }
                        .font(.headline)
                        .foregroundStyle(MnColor.danger)
                        .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
                    case .registeringFirstDevice:
                        if let progress = coordinator.firstDeviceProgress {
                            SiteRootFirstDeviceProgressView(progress: progress)
                        } else {
                            MnStatusLabel(text: "Registering protected first device", kind: .warning)
                        }
                    case .signing:
                        MnStatusLabel(text: "Waiting for Face ID", kind: .warning)
                    case .attesting:
                        MnStatusLabel(text: "Submitting device assertion", kind: .warning)
                    case .rewrappingCustody:
                        MnStatusLabel(text: "Waiting for custody Face ID", kind: .warning)
                    case .unlockingX509Root:
                        MnStatusLabel(text: "Waiting for Site X.509 root Face ID", kind: .warning)
                    case .unlockingX509Issuer:
                        MnStatusLabel(text: "Waiting for Site X.509 issuer Face ID", kind: .warning)
                    case .approvingInitialX509Leaves:
                        MnStatusLabel(text: "Waiting for HTTPS certificate approval", kind: .warning)
                    case .signingDasReplacementReceipt:
                        MnStatusLabel(
                            text: "Signing DAS authority replacement receipt",
                            kind: .warning
                        )
                    case let .submitted(completion):
                        MnSectionHeading(
                            completion.heading,
                            orientation: completion.orientation
                        )
                        MnStatusLabel(text: "Verified by Monas", kind: .success)
                        MnPanel {
                            VStack(alignment: .leading, spacing: MnSpacing.x4) {
                                MnEvidenceRow(label: "Site Root proof", value: "Accepted")
                                Divider()
                                MnEvidenceRow(label: completion.evidenceLabel, value: completion.evidenceValue)
                                Divider()
                                MnEvidenceRow(label: "Local history", value: "Recorded")
                            }
                        }
                        Text(completion.detail)
                            .font(.footnote)
                        MnPrimaryButton(completion.actionTitle) {
                            coordinator.reset()
                            dismiss()
                            showInstallations()
                        }
                    case let .failed(failure):
                        MnStatusLabel(text: "Site Root ceremony stopped safely", kind: .danger)
                        if let progress = coordinator.firstDeviceProgress {
                            SiteRootFirstDeviceProgressView(progress: progress, terminal: true)
                        }
                        Text(failure.safeUserMessage)
                        MnPrimaryButton("Done") {
                            coordinator.reset()
                            dismiss()
                        }
                    case .idle:
                        EmptyView()
                    }
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Site Root")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if !coordinator.phase.isSubmitted {
                        Button("Cancel") {
                            coordinator.cancel()
                            dismiss()
                        }
                        .frame(minHeight: MnMetrics.minimumTarget)
                    }
                }
            }
            .mnScreenBackground()
        }
    }
}

private struct SiteRootFirstDeviceProgressView: View {
    let progress: SiteRootFirstDeviceProgress
    var terminal = false

    var body: some View {
        TimelineView(.periodic(from: Date(), by: 1)) { context in
            MnPanel {
                VStack(alignment: .leading, spacing: MnSpacing.x2) {
                    HStack(alignment: .firstTextBaseline, spacing: MnSpacing.x2) {
                        MnStatusLabel(
                            text: terminal
                                ? "Stopped at \(progress.stage.title)"
                                : progress.stage.title,
                            kind: terminal ? .danger : .warning
                        )
                        Spacer(minLength: 0)
                        if !terminal {
                            ProgressView()
                                .controlSize(.small)
                                .accessibilityLabel("Operation in progress")
                        }
                    }
                    Text(progress.stage.detail)
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(
                        "\(progress.elapsedDescription(at: context.date)) · "
                            + progress.stageElapsedDescription(at: context.date)
                    )
                        .font(.caption)
                        .foregroundStyle(MnColor.textPrimary)
                        .monospacedDigit()
                }
            }
        }
    }
}

extension SiteRootDelegationCoordinator.Completion {
    var heading: String {
        switch self {
        case .siteTrustEstablished: "Site Trust established"
        case .sessionEstablished: "Site Root ceremony complete"
        }
    }

    var orientation: String {
        switch self {
        case .siteTrustEstablished:
            "Monas accepted this first-device proof and created Site Trust and custody. This installation is recorded as setup in progress; identity enrolment is the next ceremony."
        case .sessionEstablished:
            "Monas accepted the Site Root proof and Pistis submitted the custody rewrap through the fixed authority route. A redacted local observation is now in History."
        }
    }

    var evidenceLabel: String {
        switch self {
        case .siteTrustEstablished: "Setup state"
        case .sessionEstablished: "Custody rewrap"
        }
    }

    var evidenceValue: String {
        switch self {
        case .siteTrustEstablished: "Setup in progress"
        case .sessionEstablished: "Submitted"
        }
    }

    var detail: String {
        switch self {
        case .siteTrustEstablished:
            "The installation’s Monas audit remains authoritative. Pistis stores only a redacted setup observation and cannot authenticate or approve work until identity enrolment completes."
        case .sessionEstablished:
            "The installation’s Monas audit remains the authoritative record. Pistis stores only this redacted device observation."
        }
    }

    var actionTitle: String {
        switch self {
        case .siteTrustEstablished: "View setup progress"
        case .sessionEstablished: "View installation"
        }
    }
}

private extension SiteRootDelegationCoordinator.Phase {
    var isSubmitted: Bool {
        if case .submitted = self { return true }
        return false
    }
}

struct ApprovalView: View {
    let request: ApprovalRequest
    @ObservedObject var coordinator: ProductionCeremonyCoordinator
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if let result = resultPresentation {
                    ApprovalResultView(
                        result: result,
                        failureStage: coordinator.failureStage
                    ) {
                        coordinator.reset()
                        dismiss()
                    }
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: MnSpacing.x4) {
                            MnSectionHeading(request.action, orientation: request.subject)

                            MnStatusLabel(text: request.trustState, kind: .success)

                            MnPanel {
                                VStack(alignment: .leading, spacing: MnSpacing.x4) {
                                    MnEvidenceRow(
                                        label: "Installation",
                                        value: request.installation
                                    )
                                    Divider()
                                    MnEvidenceRow(label: "Local user", value: request.localUser)
                                    Divider()
                                    MnEvidenceRow(
                                        label: "External identity",
                                        value: request.externalIdentity
                                    )
                                    Divider()
                                    MnEvidenceRow(
                                        label: "Installation fingerprint",
                                        value: request.fingerprint,
                                        monospaced: true
                                    )
                                    Divider()
                                    MnEvidenceRow(label: "Expires in", value: request.expiry)
                                    Divider()
                                    MnEvidenceRow(label: "Request route", value: request.route)
                                }
                            }

                            Text("Approving asks iOS to verify you before Pistis produces a device signature. Approval alone does not mean the installation accepted it.")
                                .font(.footnote)
                                .fixedSize(horizontal: false, vertical: true)

                            VStack(spacing: MnSpacing.x3) {
                                MnPrimaryButton(
                                    "Approve and verify",
                                    systemImage: "checkmark.shield"
                                ) {
                                    Task { await coordinator.decide(.approved) }
                                }
                                Button("Deny") {
                                    Task { await coordinator.decide(.denied) }
                                }
                                .font(.headline)
                                .foregroundStyle(MnColor.danger)
                                .frame(
                                    maxWidth: .infinity,
                                    minHeight: MnMetrics.minimumTarget
                                )
                            }
                        }
                        .padding(MnMetrics.screenGutter)
                    }
                    .navigationTitle("Review request")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { dismiss() }
                                .frame(minHeight: MnMetrics.minimumTarget)
                        }
                    }
                }
            }
            .mnScreenBackground()
        }
        .interactiveDismissDisabled(decisionIsInFlight)
    }

    private var decisionIsInFlight: Bool {
        switch coordinator.phase {
        case .preparing, .submitting: true
        default: false
        }
    }

    private var resultPresentation: ApprovalPresentation? {
        switch coordinator.phase {
        case .preparing: .preparing
        case let .submitting(decision): .submitting(decision)
        case let .terminal(status): .terminal(status)
        case let .failed(failure): .failed(failure)
        default: nil
        }
    }
}

private enum ApprovalPresentation: Identifiable {
    case preparing
    case submitting(AuthenticationDecision)
    case terminal(AuthoritativeCeremonyStatus)
    case failed(PlatformFailure)

    var id: String {
        switch self {
        case .preparing: "preparing"
        case let .submitting(decision): "submitting-\(decision.rawValue)"
        case let .terminal(status): "terminal-\(status.state.rawValue)"
        case .failed: "failed"
        }
    }
}

private struct ApprovalResultView: View {
    let result: ApprovalPresentation
    let failureStage: ProductionCeremonyStage?
    let done: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: MnSpacing.x6) {
                    MnSectionHeading(
                        title,
                        orientation: orientation
                    )
                    MnPanel {
                        VStack(alignment: .leading, spacing: MnSpacing.x4) {
                            MnStatusLabel(
                                text: statusText,
                                kind: statusKind
                            )
                            if case .failed = result, let failureStage {
                                MnEvidenceRow(
                                    label: "Stopped at",
                                    value: failureStage.rawValue.capitalized
                                )
                            }
                        }
                    }
                    if isTerminal {
                        MnPrimaryButton("Done", action: done)
                    } else {
                        ProgressView()
                            .accessibilityLabel("Waiting for the installation authority")
                    }
                }
                .padding(MnMetrics.screenGutter)
            }
            .navigationTitle("Result")
            .navigationBarTitleDisplayMode(.inline)
            .mnScreenBackground()
        }
    }

    private var title: String {
        switch result {
        case .preparing: "Preparing sign-in"
        case .submitting: "Recording decision"
        case let .terminal(status): status.state == .completed
            ? "Authentication accepted" : "Authority result"
        case .failed: "Authentication failed"
        }
    }

    private var orientation: String {
        switch result {
        case .preparing:
            "The signed request is verified. Pistis is checking retained authority custody before Face ID."
        case .submitting:
            "Face ID, device signature, delivery, and authority verification are in progress."
        case let .terminal(status):
            "The installation authority returned \(status.state.rawValue)."
        case let .failed(failure):
            failure.safeUserMessage
        }
    }

    private var statusText: String {
        switch result {
        case .preparing: "Verified QR accepted as sign-in intent"
        case let .submitting(decision): "Human decision: \(decision.rawValue)"
        case let .terminal(status): "Authority state: \(status.state.rawValue)"
        case .failed: "No authoritative completion was recorded"
        }
    }

    private var statusKind: MnStatusKind {
        switch result {
        case .preparing, .submitting: .warning
        case let .terminal(status): status.state == .completed ? .success : .danger
        case .failed: .danger
        }
    }

    private var isTerminal: Bool {
        switch result {
        case .preparing, .submitting: false
        case .terminal, .failed: true
        }
    }
}
