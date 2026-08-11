import CryptoKit
import Foundation
import Security

/// One exclusive app-scoped TLS trust mode for the fixed Monas origin.
///
/// Bootstrap builds pin the exact temporary leaf SPKI. Migrated builds carry
/// the authenticated Site root object and generation instead; they never
/// retain or fall back to the bootstrap leaf.
enum MonasServerTrustPolicy: Sendable, Equatable {
    case bootstrapLeafSPKI(Data)
    case siteRootGeneration(rootDER: Data, fingerprintSHA256: Data, generation: UInt64)

    init(siteRootDER: Data, fingerprintSHA256: Data, generation: UInt64) throws {
        guard !siteRootDER.isEmpty, siteRootDER.count <= 64 * 1_024,
              fingerprintSHA256.count == 32,
              !fingerprintSHA256.allSatisfy({ $0 == 0 }), generation > 0,
              Data(SHA256.hash(data: siteRootDER)) == fingerprintSHA256,
              SecCertificateCreateWithData(nil, siteRootDER as CFData) != nil
        else { throw PlatformFailure.invalidConfiguration }
        self = .siteRootGeneration(
            rootDER: siteRootDER,
            fingerprintSHA256: fingerprintSHA256,
            generation: generation
        )
    }
}

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
    private let trustPolicy: MonasServerTrustPolicy

    convenience init(origin: URL, expectedSPKISHA256: Data) throws {
        guard expectedSPKISHA256.count == 32,
              !expectedSPKISHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.invalidConfiguration }
        try self.init(origin: origin, trustPolicy: .bootstrapLeafSPKI(expectedSPKISHA256))
    }

    init(origin: URL, trustPolicy: MonasServerTrustPolicy) throws {
        guard let host = origin.host else {
            throw PlatformFailure.invalidConfiguration
        }
        self.host = host
        port = origin.port ?? 443
        self.trustPolicy = trustPolicy
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
        guard challenge.protectionSpace.authenticationMethod
                == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host == host,
              challenge.protectionSpace.port == port,
              let trust = challenge.protectionSpace.serverTrust,
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        do {
            let anchor: SecCertificate
            switch trustPolicy {
            case let .bootstrapLeafSPKI(expectedSPKISHA256):
                let certificateDER = SecCertificateCopyData(leaf) as Data
                let spki = try CertificateSPKI.extract(from: certificateDER)
                guard Data(SHA256.hash(data: spki)) == expectedSPKISHA256 else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                    return
                }
                anchor = leaf
            case let .siteRootGeneration(rootDER, fingerprintSHA256, generation):
                guard generation > 0,
                      Data(SHA256.hash(data: rootDER)) == fingerprintSHA256,
                      let root = SecCertificateCreateWithData(nil, rootDER as CFData)
                else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                    return
                }
                anchor = root
            }
            guard SecTrustSetPolicies(
                trust,
                SecPolicyCreateSSL(true, host as CFString)
            ) == errSecSuccess,
                  SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess,
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
