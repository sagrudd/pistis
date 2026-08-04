import SwiftUI

#if canImport(AVFoundation) && canImport(UIKit)
import AVFoundation
import UIKit

/// A transient camera preview backed by the bounded Pistis QR adapter.
///
/// This view acquires text only. It does not interpret a challenge or grant
/// authority; the protocol verifier remains a separate mandatory boundary.
struct QRScannerCameraView: UIViewRepresentable {
    let profile: QRPayloadProfile
    let onResult: @MainActor (Result<ScannedQRPayload, PlatformFailure>) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onResult: onResult)
    }

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        do {
            let scanner = try QRScannerAdapter(profile: profile)
            context.coordinator.scanner = scanner
            view.previewLayer = scanner.makePreviewLayer()
            context.coordinator.startTask = Task {
                do {
                    try await scanner.start { result in
                        Task { @MainActor in onResult(result) }
                    }
                } catch {
                    let failure = (error as? PlatformFailure) ?? .cameraUnavailable
                    onResult(.failure(failure))
                }
            }
        } catch {
            Task { @MainActor in
                onResult(.failure((error as? PlatformFailure) ?? .invalidConfiguration))
            }
        }
        return view
    }

    func updateUIView(_: PreviewView, context _: Context) {}

    static func dismantleUIView(_: PreviewView, coordinator: Coordinator) {
        coordinator.startTask?.cancel()
        coordinator.startTask = nil
        coordinator.scanner?.cancel()
        coordinator.scanner = nil
    }

    final class Coordinator {
        var scanner: QRScannerAdapter?
        var startTask: Task<Void, Never>?
        let onResult: @MainActor (Result<ScannedQRPayload, PlatformFailure>) -> Void

        init(
            onResult: @escaping @MainActor (
                Result<ScannedQRPayload, PlatformFailure>
            ) -> Void
        ) {
            self.onResult = onResult
        }
    }

    final class PreviewView: UIView {
        var previewLayer: AVCaptureVideoPreviewLayer? {
            didSet {
                oldValue?.removeFromSuperlayer()
                if let previewLayer { layer.addSublayer(previewLayer) }
            }
        }

        override func layoutSubviews() {
            super.layoutSubviews()
            previewLayer?.frame = bounds
        }
    }
}
#else
struct QRScannerCameraView: View {
    let profile: QRPayloadProfile
    let onResult: @MainActor (Result<ScannedQRPayload, PlatformFailure>) -> Void

    var body: some View {
        Color.black
            .task { onResult(.failure(.cameraUnavailable)) }
    }
}
#endif
