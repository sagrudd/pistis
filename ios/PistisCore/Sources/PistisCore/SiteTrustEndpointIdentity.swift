import Foundation
import Network

/// Versioned, authority-signed endpoint identity for local or DNS-addressed
/// Site Trust. An IP address is never an unpinned compatibility path.
enum SiteTrustEndpointHostV1: Equatable, Sendable {
    case dnsName(String)
    case ipv4(IPv4Address)
    case ipv6(IPv6Address)
}

struct SiteTrustEndpointIdentityV1: Equatable, Sendable {
    let origin: URL
    let host: SiteTrustEndpointHostV1
    let tlsSPKISHA256: Data

    init(origin text: String, tlsSPKISHA256: Data) throws {
        guard tlsSPKISHA256.count == 32,
              !tlsSPKISHA256.allSatisfy({ $0 == 0 }),
              text == text.lowercased(),
              text.unicodeScalars.allSatisfy(\.isASCII),
              !text.contains("%"),
              let url = URL(string: text),
              let components = URLComponents(
                  url: url,
                  resolvingAgainstBaseURL: false
              ),
              components.scheme == "https", components.user == nil,
              components.password == nil, components.path.isEmpty,
              components.query == nil, components.fragment == nil,
              let rawHost = components.host,
              components.percentEncodedHost == rawHost,
              components.port != 443, components.string == text
        else { throw FirstDevicePresentationError.malformed }

        let host: SiteTrustEndpointHostV1
        if rawHost.first == "[", rawHost.last == "]" {
            let addressText = String(rawHost.dropFirst().dropLast())
            guard let address = IPv6Address(addressText),
                  "[\(address.debugDescription)]" == rawHost
            else { throw FirstDevicePresentationError.malformed }
            host = .ipv6(address)
        } else if rawHost.contains(":") {
            throw FirstDevicePresentationError.malformed
        } else if rawHost.split(separator: ".", omittingEmptySubsequences: false).count == 4
            && rawHost.utf8.allSatisfy({ (48 ... 57).contains($0) || $0 == 46 })
        {
            guard let address = IPv4Address(rawHost),
                  address.debugDescription == rawHost
            else { throw FirstDevicePresentationError.malformed }
            host = .ipv4(address)
        } else {
            guard Self.canonicalDNSName(rawHost) else {
                throw FirstDevicePresentationError.malformed
            }
            host = .dnsName(rawHost)
        }
        self.origin = url
        self.host = host
        self.tlsSPKISHA256 = tlsSPKISHA256
    }

    func matches(allowedHost: String) -> Bool {
        switch host {
        case .dnsName(let host): allowedHost == host
        case .ipv4(let host): allowedHost == host.debugDescription
        case .ipv6(let host): allowedHost == "[\(host.debugDescription)]"
        }
    }

    private static func canonicalDNSName(_ host: String) -> Bool {
        !host.isEmpty && host.utf8.count <= 253 && !host.hasSuffix(".")
            && host.split(separator: ".", omittingEmptySubsequences: false)
                .allSatisfy { label in
                    !label.isEmpty && label.utf8.count <= 63
                        && label.first != "-" && label.last != "-"
                        && label.utf8.allSatisfy {
                            (48 ... 57).contains($0)
                                || (97 ... 122).contains($0) || $0 == 45
                        }
                }
    }
}
