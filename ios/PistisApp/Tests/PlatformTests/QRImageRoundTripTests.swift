import CoreImage
import CoreImage.CIFilterBuiltins
import CryptoKit
import XCTest

final class QRImageRoundTripTests: XCTestCase {
    private static let challengeFrame = "PISTIS1:pAABAQECWCiiAAEBeCJwaXN0aXMuYXV0aGVudGljYXRpb24tY2hhbGxlbmdlLnYxA1hAWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWg.775551d1121cb140"
    private static let challengeSHA256 = "2e2a88f27b4692db5a1e76e0fac6f31dc1fc3aa3a7367dedd43cfd5f43dfaa78"

    func testChallengeFrameSurvivesImageQRRoundTripByteForByte() throws {
        let source = try XCTUnwrap(Self.challengeFrame.data(using: .utf8))
        XCTAssertEqual(source.count, 179)
        XCTAssertEqual(Self.hexDigest(source), Self.challengeSHA256)

        let generator = CIFilter.qrCodeGenerator()
        generator.message = source
        generator.correctionLevel = "M"
        let modules = try XCTUnwrap(generator.outputImage)
        let scale: CGFloat = 8
        let quietZone = 4 * scale
        let scaled = modules.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let extent = CGRect(
            x: 0,
            y: 0,
            width: scaled.extent.width + (quietZone * 2),
            height: scaled.extent.height + (quietZone * 2)
        )
        let image = scaled
            .transformed(by: CGAffineTransform(translationX: quietZone, y: quietZone))
            .composited(over: CIImage(color: .white).cropped(to: extent))
        let context = CIContext(options: [.useSoftwareRenderer: true])
        let rendered = try XCTUnwrap(context.createCGImage(image, from: extent))
        let detector = try XCTUnwrap(
            CIDetector(
                ofType: CIDetectorTypeQRCode,
                context: context,
                options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]
            )
        )
        let observations = detector.features(in: CIImage(cgImage: rendered))
        XCTAssertEqual(observations.count, 1)
        let observation = try XCTUnwrap(observations.first as? CIQRCodeFeature)
        let decoded = try XCTUnwrap(observation.messageString)
        let decodedBytes = try XCTUnwrap(decoded.data(using: .utf8))

        XCTAssertEqual(decodedBytes, source)
        XCTAssertEqual(Self.hexDigest(decodedBytes), Self.challengeSHA256)
    }

    private static func hexDigest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
