import SwiftUI
import UniformTypeIdentifiers

/// User-attended, local-only PXRP/v1 import and PXRA/v2 export.
struct OfflineSiteRootAcknowledgementView: View {
  private let authorizationVerifier: (any SiteRootAckOfflineAuthorizationVerifying)?
  @State private var importing = false
  @State private var exporting = false
  @State private var importedFrame: Data?
  @State private var verified: ProxenosPXRAEnvelopeV1?
  @State private var registration: SiteRootConvergenceAckRecordV2?
  @State private var acknowledgement: Data?
  @State private var errorMessage: String?
  @State private var replayGuard = ProxenosPXRAReplayGuardV1()
  @State private var isSigning = false

  init(
    authorizationVerifier: (any SiteRootAckOfflineAuthorizationVerifying)? = nil
  ) {
    self.authorizationVerifier = authorizationVerifier
  }

  private var pin: ProxenosPXRAKeyPinV1? {
    ProxenosPXRAKeyPinV1.fromSignedProfile(Bundle.main.infoDictionary ?? [:])
  }

  var body: some View {
    List {
      Section("Offline Site Root acknowledgement") {
        Text(
          "Import a signed PXRP/v1 presentation, review its exact Site Root result, then use the already registered acknowledgement key to export one PXRA/v2 response. This route makes no network request."
        )
        .fixedSize(horizontal: false, vertical: true)
        if pin == nil {
          Label(
            "This release has no independently verified Proxenos presentation key. Offline signing is unavailable.",
            systemImage: "lock.slash"
          )
          .foregroundStyle(MnColor.textPrimary)
          .accessibilityIdentifier("offline-pxra-no-proxenos-pin")
        }
        Button {
          importing = true
        } label: {
          Label("Import signed PXRP presentation", systemImage: "doc.badge.plus")
        }
        .disabled(pin == nil || isSigning)
      }

      if let verified {
        Section("Verified presentation") {
          LabeledContent("Site", value: verified.presentation.siteUUIDText)
          LabeledContent("Action", value: verified.presentation.action.offlineLabel)
          LabeledContent(
            "Root fingerprint",
            value: verified.presentation.rootFingerprint.prefix(8)
              .map { String(format: "%02x", $0) }.joined() + "…"
          )
          LabeledContent(
            "Root generation", value: String(verified.presentation.rootGeneration)
          )
          LabeledContent(
            "Expires",
            value: Date(
              timeIntervalSince1970: TimeInterval(
                verified.presentation.expiresAtUnixMilliseconds / 1_000
              )
            ).formatted()
          )
          Text(
            "Only these exact retained bytes can be signed. If expiry passes during review, the operation stops and requires a fresh Proxenos presentation."
          )
          .font(.footnote)
          .fixedSize(horizontal: false, vertical: true)
          if authorizationVerifier == nil {
            Text(
              "This build cannot independently verify the original signed PXRB authorization and recorded native mutation. Signing remains unavailable until that evidence source is integrated and reviewed."
            )
            .font(.footnote)
            .fixedSize(horizontal: false, vertical: true)
          }
          if acknowledgement == nil {
            if authorizationVerifier != nil {
              Button {
                Task { await signOfflineAcknowledgement() }
              } label: {
                Label("Sign with Face ID", systemImage: "faceid")
              }
              .disabled(isSigning)
            } else {
              Label("Signing unavailable", systemImage: "lock.slash")
            }
          }
        }
      }

      if let acknowledgement {
        Section("Response ready") {
          Text(
            "The exact PXRA/v2 response is held in memory for export. It has not been submitted."
          )
          .fixedSize(horizontal: false, vertical: true)
          Button {
            exporting = true
          } label: {
            Label("Export signed PXRA response", systemImage: "square.and.arrow.up")
          }
          .disabled(acknowledgement.isEmpty)
        }
      }

      if isSigning {
        Section { ProgressView("Verifying the retained ACK key") }
      }
      if let errorMessage {
        Section("Stopped safely") {
          Text(errorMessage).fixedSize(horizontal: false, vertical: true)
        }
      }
    }
    .scrollContentBackground(.hidden)
    .navigationTitle("Offline Site Root ACK")
    .mnScreenBackground()
    .fileImporter(
      isPresented: $importing,
      allowedContentTypes: [.data],
      allowsMultipleSelection: false,
      onCompletion: receivePresentation
    )
    .fileExporter(
      isPresented: $exporting,
      document: OfflinePXRAFileDocument(data: acknowledgement ?? Data()),
      contentType: .data,
      defaultFilename: "pistis-site-root-ack.pxra",
      onCompletion: { result in
        if case .failure = result {
          errorMessage =
            "The response was not exported. You may export the retained response again."
        }
      }
    )
  }

  private func receivePresentation(_ result: Result<[URL], Error>) {
    do {
      guard case .success(let urls) = result, urls.count == 1 else {
        throw PlatformFailure.qrPayloadUnsupported
      }
      let url = urls[0]
      let scoped = url.startAccessingSecurityScopedResource()
      defer { if scoped { url.stopAccessingSecurityScopedResource() } }
      let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
      guard attributes[.type] as? FileAttributeType != .typeSymbolicLink,
        attributes[.type] as? FileAttributeType == .typeRegular,
        let fileSize = attributes[.size] as? NSNumber,
        fileSize.intValue > 0,
        fileSize.intValue <= ProxenosPXRAEnvelopeV1.maximumEnvelopeBytes
      else { throw PlatformFailure.qrPayloadUnsupported }
      let bytes = try Data(contentsOf: url, options: .mappedIfSafe)
      let currentRegistration = try SiteRootConvergenceAckStoreV2().current()
      let now = try currentUnixMilliseconds()
      let parsed = try OfflineSiteRootAcknowledgementV1.verify(
        frame: bytes,
        pin: pin,
        registration: currentRegistration,
        nowUnixMilliseconds: now
      )
      importedFrame = bytes
      registration = currentRegistration
      verified = parsed
      acknowledgement = nil
      errorMessage = nil
    } catch let failure as PlatformFailure {
      errorMessage = failure.safeUserMessage
    } catch {
      errorMessage = PlatformFailure.qrPayloadUnsupported.safeUserMessage
    }
  }

  @MainActor
  private func signOfflineAcknowledgement() async {
    guard let importedFrame, let registration,
      let authorizationVerifier
    else { return }
    isSigning = true
    defer { isSigning = false }
    do {
      try replayGuard.consume(importedFrame)
      let config = try MonasSiteRootAuthorityConfiguration(
        infoDictionary: Bundle.main.infoDictionary ?? [:]
      )
      let signed = try await OfflineSiteRootAcknowledgementV1.sign(
        frame: importedFrame,
        pin: pin,
        registration: registration,
        trustPolicy: config.trustPolicy,
        authorizationVerifier: authorizationVerifier,
        nowUnixMilliseconds: try currentUnixMilliseconds()
      )
      acknowledgement = signed
      errorMessage = nil
    } catch let failure as PlatformFailure {
      errorMessage = failure.safeUserMessage
    } catch {
      errorMessage = PlatformFailure.siteRootAuthorityUnavailable.safeUserMessage
    }
  }

  private func currentUnixMilliseconds() throws -> UInt64 {
    let time = Date().timeIntervalSince1970 * 1_000
    guard time >= 0, time <= TimeInterval(UInt64.max) else {
      throw PlatformFailure.invalidConfiguration
    }
    return UInt64(time)
  }
}

extension UnsignedSiteRootConvergenceAssertionV2.Action {
  fileprivate var offlineLabel: String {
    switch self {
    case .install: "Install"
    case .replace: "Replace"
    case .remove: "Remove"
    }
  }
}

private struct OfflinePXRAFileDocument: FileDocument {
  static var readableContentTypes: [UTType] { [.data] }
  let data: Data

  init(data: Data) { self.data = data }

  init(configuration: ReadConfiguration) throws {
    guard let data = configuration.file.regularFileContents,
      !data.isEmpty,
      data.count <= ProxenosPXRAEnvelopeV1.maximumEnvelopeBytes
    else { throw PlatformFailure.qrPayloadUnsupported }
    self.data = data
  }

  func fileWrapper(configuration _: WriteConfiguration) throws -> FileWrapper {
    FileWrapper(regularFileWithContents: data)
  }
}
