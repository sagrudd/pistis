import CryptoKit
import Foundation
import Security

/// Extracts the exact DER SubjectPublicKeyInfo TLV from one DER certificate.
///
/// The parser accepts only definite, minimally encoded DER lengths and the
/// bounded X.509 TBSCertificate structure needed to locate SPKI.
enum CertificateSPKI {
    static func extract(from certificateDER: Data) throws -> Data {
        guard !certificateDER.isEmpty, certificateDER.count <= 64 * 1_024 else {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
        var certificate = DERReader(certificateDER)
        let certificateSequence = try certificate.element(expectedTag: 0x30)
        guard certificate.isAtEnd else {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
        var contents = DERReader(
            certificateDER,
            range: certificateSequence.contentRange
        )
        let tbs = try contents.element(expectedTag: 0x30)
        var fields = DERReader(certificateDER, range: tbs.contentRange)
        if fields.peekTag == 0xa0 {
            _ = try fields.element(expectedTag: 0xa0)
        }
        _ = try fields.element(expectedTag: 0x02) // serial number
        _ = try fields.element(expectedTag: 0x30) // signature algorithm
        _ = try fields.element(expectedTag: 0x30) // issuer
        _ = try fields.element(expectedTag: 0x30) // validity
        _ = try fields.element(expectedTag: 0x30) // subject
        let spki = try fields.element(expectedTag: 0x30)
        return certificateDER.subdata(in: spki.fullRange)
    }
}

private struct DERElement {
    let fullRange: Range<Data.Index>
    let contentRange: Range<Data.Index>
}

private struct DERReader {
    private let data: Data
    private let limit: Data.Index
    private var offset: Data.Index

    init(_ data: Data) {
        self.init(data, range: data.startIndex ..< data.endIndex)
    }

    init(_ data: Data, range: Range<Data.Index>) {
        self.data = data
        offset = range.lowerBound
        limit = range.upperBound
    }

    var isAtEnd: Bool { offset == limit }
    var peekTag: UInt8? { offset < limit ? data[offset] : nil }

    mutating func element(expectedTag: UInt8) throws -> DERElement {
        let start = offset
        guard readByte() == expectedTag, let firstLength = readByte() else {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
        let length: Int
        if firstLength < 0x80 {
            length = Int(firstLength)
        } else {
            let width = Int(firstLength & 0x7f)
            guard (1 ... 4).contains(width), offset + width <= limit,
                  data[offset] != 0
            else { throw PlatformFailure.productionEnvelopeUnavailable }
            var value = 0
            for _ in 0 ..< width {
                guard let byte = readByte() else {
                    throw PlatformFailure.productionEnvelopeUnavailable
                }
                value = (value << 8) | Int(byte)
            }
            guard value >= 128 else {
                throw PlatformFailure.productionEnvelopeUnavailable
            }
            length = value
        }
        guard length <= limit - offset else {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
        let contentStart = offset
        offset += length
        return DERElement(
            fullRange: start ..< offset,
            contentRange: contentStart ..< offset
        )
    }

    private mutating func readByte() -> UInt8? {
        guard offset < limit else { return nil }
        defer { offset += 1 }
        return data[offset]
    }
}

/// App-scoped exact-origin and exact-SPKI trust boundary for first enrolment.
final class PinnedEnrolmentSessionDelegate:
    NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable
{
    private let host: String
    private let port: Int
    private let expectedSPKISHA256: Data

    init(origin: URL, expectedSPKISHA256: Data) throws {
        guard let host = origin.host, expectedSPKISHA256.count == 32 else {
            throw PlatformFailure.invalidConfiguration
        }
        self.host = host
        port = origin.port ?? 443
        self.expectedSPKISHA256 = expectedSPKISHA256
    }

    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest _: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func urlSession(
        _: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (
            URLSession.AuthChallengeDisposition,
            URLCredential?
        ) -> Void
    ) {
        resolveServerTrustChallenge(challenge, completionHandler: completionHandler)
    }

    /// URLSession delivers server-trust challenges for data tasks through the
    /// task delegate on current iOS releases. Keep the exact same verifier at
    /// both delegate scopes so the fixed, self-pinned Monas authority is never
    /// silently delegated to the system trust store or rejected before the
    /// pinned verifier sees it.
    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (
            URLSession.AuthChallengeDisposition,
            URLCredential?
        ) -> Void
    ) {
        resolveServerTrustChallenge(challenge, completionHandler: completionHandler)
    }

    private func resolveServerTrustChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (
            URLSession.AuthChallengeDisposition,
            URLCredential?
        ) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod
                == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host == host,
              challenge.protectionSpace.port == port,
              let trust = challenge.protectionSpace.serverTrust,
              let leaf = SecTrustGetCertificateAtIndex(trust, 0)
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        do {
            let certificateDER = SecCertificateCopyData(leaf) as Data
            let spki = try CertificateSPKI.extract(from: certificateDER)
            let digest = Data(SHA256.hash(data: spki))
            guard digest == expectedSPKISHA256,
                  SecTrustSetPolicies(
                      trust,
                      SecPolicyCreateSSL(true, host as CFString)
                  ) == errSecSuccess,
                  SecTrustSetAnchorCertificates(
                      trust,
                      [leaf] as CFArray
                  ) == errSecSuccess,
                  SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
                  SecTrustEvaluateWithError(trust, nil)
            else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        } catch {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
