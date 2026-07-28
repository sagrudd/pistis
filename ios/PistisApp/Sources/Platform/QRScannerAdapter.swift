import Foundation

struct ScannedQRPayload: Equatable, Sendable {
    let text: String
}

#if canImport(AVFoundation) && canImport(UIKit)
import AVFoundation
import UIKit

/// Transient, bounded QR acquisition. Captured frames are never retained or logged.
final class QRScannerAdapter: NSObject, AVCaptureMetadataOutputObjectsDelegate,
    @unchecked Sendable
{
    typealias Handler = @Sendable (Result<ScannedQRPayload, PlatformFailure>) -> Void

    private let maximumBytes: Int
    private let captureQueue = DispatchQueue(label: "org.mnemosyne.pistis.qr-capture")
    private let session = AVCaptureSession()
    private var handler: Handler?
    private var backgroundObserver: NSObjectProtocol?

    init(maximumBytes: Int = 2_331) throws {
        guard (1 ... 2_331).contains(maximumBytes) else {
            throw PlatformFailure.invalidConfiguration
        }
        self.maximumBytes = maximumBytes
        super.init()
    }

    /// Create the non-retaining camera preview for this scanner session.
    ///
    /// The layer displays camera pixels only; no sample-buffer output or photo
    /// capture output is installed.
    func makePreviewLayer() -> AVCaptureVideoPreviewLayer {
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        return layer
    }

    func start(handler: @escaping Handler) async throws {
        guard self.handler == nil else { throw PlatformFailure.invalidConfiguration }
        let authorized: Bool
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            authorized = true
        case .notDetermined:
            authorized = await AVCaptureDevice.requestAccess(for: .video)
        default:
            authorized = false
        }
        guard authorized else { throw PlatformFailure.cameraPermissionDenied }

        self.handler = handler
        backgroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.cancel()
        }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            captureQueue.async { [weak self] in
                guard let self else {
                    continuation.resume(throwing: PlatformFailure.operationCancelled)
                    return
                }
                do {
                    try self.configureIfNeeded()
                    self.session.startRunning()
                    continuation.resume()
                } catch {
                    self.clearHandler()
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func cancel() {
        captureQueue.async { [weak self] in
            guard let self else { return }
            if self.session.isRunning { self.session.stopRunning() }
            self.finish(.failure(.operationCancelled))
        }
    }

    func metadataOutput(
        _: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from _: AVCaptureConnection
    ) {
        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              object.type == .qr,
              let value = object.stringValue
        else {
            return
        }
        let byteCount = value.lengthOfBytes(using: .utf8)
        guard byteCount <= maximumBytes else {
            finish(.failure(.qrPayloadTooLarge))
            return
        }
        guard value.hasPrefix("PISTIS1:") else {
            finish(.failure(.qrPayloadUnsupported))
            return
        }
        finish(.success(ScannedQRPayload(text: value)))
    }

    private func configureIfNeeded() throws {
        guard session.inputs.isEmpty, session.outputs.isEmpty else { return }
        guard let camera = AVCaptureDevice.default(for: .video) else {
            throw PlatformFailure.cameraUnavailable
        }
        let input = try AVCaptureDeviceInput(device: camera)
        let output = AVCaptureMetadataOutput()
        guard session.canAddInput(input), session.canAddOutput(output) else {
            throw PlatformFailure.cameraUnavailable
        }
        session.beginConfiguration()
        session.addInput(input)
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: captureQueue)
        output.metadataObjectTypes = [.qr]
        session.commitConfiguration()
    }

    private func finish(_ result: Result<ScannedQRPayload, PlatformFailure>) {
        let completion = handler
        if session.isRunning { session.stopRunning() }
        clearHandler()
        completion?(result)
    }

    private func clearHandler() {
        handler = nil
        if let backgroundObserver {
            NotificationCenter.default.removeObserver(backgroundObserver)
            self.backgroundObserver = nil
        }
    }
}
#else
final class QRScannerAdapter: Sendable {
    init(maximumBytes: Int = 2_331) throws {
        guard (1 ... 2_331).contains(maximumBytes) else {
            throw PlatformFailure.invalidConfiguration
        }
    }

    func start(
        handler _: @escaping @Sendable (Result<ScannedQRPayload, PlatformFailure>) -> Void
    ) async throws {
        throw PlatformFailure.cameraUnavailable
    }

    func cancel() {}
}
#endif
