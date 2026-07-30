import CryptoKit
import Foundation
import PistisCore
import XCTest

@testable import Pistis

final class ServerDrivenEnrolmentTransportTests: XCTestCase {
    func testClosedBeginStatusCancelShapesExcludeProviderCredentials() async throws {
        _ = EnrolmentURLProtocol.recordedBodies()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [EnrolmentURLProtocol.self]
        let presentation = try sharedPresentation()
        let transport = try ServerDrivenEnrolmentTransport(
            presentation: presentation,
            configuration: configuration
        )
        let publicKey = Data([
            0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
            0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
            0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
            0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
            0x96,
        ])
        let handle = try await transport.begin(
            operationID: Data(repeating: 0x10, count: 16),
            deviceKeyID: derivedKeyID(publicKey),
            devicePublicKey: publicKey,
            keyAssurance: "secure-enclave-biometry-current-set"
        )
        XCTAssertEqual(handle.providerVerificationID, Data(repeating: 0xaa, count: 16))
        XCTAssertEqual(handle.pollingCapability, Data(repeating: 0xbb, count: 32))
        XCTAssertEqual(handle.prompt.userCode, "ABCD-1234")
        let status = try await transport.status(handle)
        XCTAssertEqual(
            status,
            .verified(
                numericSubject: UInt64.max,
                displayLogin: "sagrudd",
                policyGeneration: 7,
                authorityChallenge: Data(repeating: 0xcc, count: 32),
                authorityChallengeExpiresAtMilliseconds: 1_700_000_240_000
            )
        )
        try await transport.cancel(handle)

        let bodies = EnrolmentURLProtocol.recordedBodies()
        XCTAssertEqual(bodies.count, 3)
        let begin = try XCTUnwrap(
            JSONSerialization.jsonObject(with: bodies[0]) as? [String: Any]
        )
        XCTAssertEqual(Set(begin.keys), [
            "version", "operation_id", "invitation", "presentation_digest",
            "device_key_id", "device_public_key", "key_assurance",
            "app_configuration_digest",
        ])
        XCTAssertEqual(
            begin["key_assurance"] as? String,
            "secure-enclave-biometry-current-set"
        )
        for body in bodies {
            let text = try XCTUnwrap(String(data: body, encoding: .utf8))
            XCTAssertFalse(text.contains("access_token"))
            XCTAssertFalse(text.contains("refresh_token"))
            XCTAssertFalse(text.contains("adapter_handle"))
            XCTAssertFalse(text.contains("email"))
        }
    }

    func testConfirmRejectsUnsignedOrWrongShapeReceiptResponse() async throws {
        _ = EnrolmentURLProtocol.recordedBodies()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [EnrolmentURLProtocol.self]
        let presentation = try sharedPresentation()
        let transport = try ServerDrivenEnrolmentTransport(
            presentation: presentation,
            configuration: configuration
        )
        let publicKey = Data([
            0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
            0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
            0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
            0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
            0x96,
        ])
        let operationID = Data(repeating: 0x10, count: 16)
        let deviceKeyID = derivedKeyID(publicKey)
        let handle = try await transport.begin(
            operationID: operationID,
            deviceKeyID: deviceKeyID,
            devicePublicKey: publicKey,
            keyAssurance: "secure-enclave-biometry-current-set"
        )
        let binding = try EnrolmentBindingInput(
            operationID: operationID,
            presentation: presentation,
            numericSubject: 123_456_789,
            devicePublicKey: publicKey,
            deviceKeyID: deviceKeyID,
            policyGeneration: 7,
            authorityChallenge: Data(repeating: 0xcc, count: 32),
            authorityChallengeExpiresAtMilliseconds: 1_700_000_240_000
        )
        do {
            _ = try await transport.confirm(
                handle,
                deviceRegistrationCOSE: Data([0x84]),
                binding: binding,
                now: Date(timeIntervalSince1970: 1_700_000_100)
            )
            XCTFail("unsigned response unexpectedly installed trust facts")
        } catch {
            XCTAssertEqual(
                error as? PlatformFailure,
                .productionEnvelopeUnavailable
            )
        }
    }

    func testRedirectAndUnknownStatusFailClosed() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [HostileEnrolmentURLProtocol.self]
        let transport = try ServerDrivenEnrolmentTransport(
            presentation: try sharedPresentation(),
            configuration: configuration
        )
        let publicKey = Data([
            0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
            0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
            0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
            0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
            0x96,
        ])
        do {
            _ = try await transport.begin(
                operationID: Data(repeating: 0x10, count: 16),
                deviceKeyID: derivedKeyID(publicKey),
                devicePublicKey: publicKey,
                keyAssurance: "secure-enclave-biometry-current-set"
            )
            XCTFail("redirect must fail")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .productionEnvelopeUnavailable)
        }
    }
}

private func derivedKeyID(_ publicKey: Data) -> Data {
    Data(SHA256.hash(
        data: Data("pistis:key-id:v1\0".utf8) + publicKey
    ))
}

private func sharedPresentation() throws -> VerifiedFirstDevicePresentation {
    let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent(
            "../../../../fixtures/protocol-v4/first-device/presentation-positive.json"
        )
        .standardizedFileURL
    let object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
    )
    return try FirstDevicePresentationV4.verify(
        qrText: try XCTUnwrap(object["qr_text"] as? String),
        expectedAppConfigurationDigest: try hex(
            try XCTUnwrap(object["app_configuration_digest_hex"] as? String)
        ),
        now: Date(timeIntervalSince1970: 1_700_000_060)
    )
}

private func hex(_ text: String) throws -> Data {
    guard text.count.isMultiple(of: 2) else {
        throw PlatformFailure.invalidConfiguration
    }
    var output = Data()
    var index = text.startIndex
    while index < text.endIndex {
        let end = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index ..< end], radix: 16) else {
            throw PlatformFailure.invalidConfiguration
        }
        output.append(byte)
        index = end
    }
    return output
}

private final class EnrolmentURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var bodies: [Data] = []

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let body = request.httpBody ?? readBodyStream(request.httpBodyStream)
        Self.lock.lock()
        Self.bodies.append(body)
        Self.lock.unlock()
        let path = request.url!.path
        let object: [String: Any]
        if path.hasSuffix("/begin") {
            object = [
                "version": 1,
                "provider_verification_id": base64(Data(repeating: 0xaa, count: 16)),
                "polling_capability": base64(Data(repeating: 0xbb, count: 32)),
                "user_code": "ABCD-1234",
                "verification_uri": "https://github.com/login/device",
                "expires_at_ms": 1_700_000_300_000,
                "poll_after_ms": 5_000,
            ]
        } else if path.hasSuffix("/status") {
            object = [
                "version": 1,
                "state": "verified",
                "numeric_subject": "18446744073709551615",
                "display_login": "sagrudd",
                "policy_generation": 7,
                "authority_challenge": base64(Data(repeating: 0xcc, count: 32)),
                "authority_challenge_expires_at_ms": 1_700_000_240_000,
            ]
        } else {
            object = ["version": 1, "state": "cancelled"]
        }
        complete(object)
    }

    override func stopLoading() {}

    static func recordedBodies() -> [Data] {
        lock.lock()
        defer {
            bodies = []
            lock.unlock()
        }
        return bodies
    }

    private func complete(_ object: [String: Any]) {
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
            ]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(
            self,
            didLoad: try! JSONSerialization.data(withJSONObject: object)
        )
        client?.urlProtocolDidFinishLoading(self)
    }

    private func base64(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func readBodyStream(_ stream: InputStream?) -> Data {
        guard let stream else { return Data() }
        stream.open()
        defer { stream.close() }
        var output = Data()
        var buffer = [UInt8](repeating: 0, count: 1_024)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count > 0 else { break }
            output.append(buffer, count: count)
        }
        return output
    }
}

private final class HostileEnrolmentURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let redirect = HTTPURLResponse(
            url: request.url!,
            statusCode: 307,
            httpVersion: "HTTP/1.1",
            headerFields: ["Location": "https://attacker.test/steal"]
        )!
        client?.urlProtocol(
            self,
            wasRedirectedTo: URLRequest(url: URL(string: "https://attacker.test/steal")!),
            redirectResponse: redirect
        )
    }

    override func stopLoading() {}
}
