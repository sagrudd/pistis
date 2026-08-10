import Foundation
import Testing
@testable import PistisCore

@Test func acceptsCanonicalDNSIPv4AndIPv6EndpointVariants() throws {
    let pin = Data(repeating: 0x77, count: 32)
    let dns = try SiteTrustEndpointIdentityV1(
        origin: "https://monas.example.test:8443",
        tlsSPKISHA256: pin
    )
    #expect(dns.matches(allowedHost: "monas.example.test"))
    let ipv4 = try SiteTrustEndpointIdentityV1(
        origin: "https://192.168.1.192:8443",
        tlsSPKISHA256: pin
    )
    #expect(ipv4.matches(allowedHost: "192.168.1.192"))
    let ipv6 = try SiteTrustEndpointIdentityV1(
        origin: "https://[2001:db8::1]:8443",
        tlsSPKISHA256: pin
    )
    #expect(ipv6.matches(allowedHost: "[2001:db8::1]"))
}

@Test func rejectsUnpinnedMismatchedAndNoncanonicalEndpointVariants() throws {
    #expect(throws: FirstDevicePresentationError.malformed) {
        try SiteTrustEndpointIdentityV1(
            origin: "https://192.168.1.192:8443",
            tlsSPKISHA256: Data(repeating: 0, count: 32)
        )
    }
    let endpoint = try SiteTrustEndpointIdentityV1(
        origin: "https://192.168.1.192:8443",
        tlsSPKISHA256: Data(repeating: 0x77, count: 32)
    )
    #expect(!endpoint.matches(allowedHost: "192.168.1.193"))
    for invalid in [
        "http://192.168.1.192:8443",
        "https://192.168.001.192:8443",
        "https://[2001:0db8:0:0:0:0:0:1]:8443",
        "https://[fe80::1%25en0]:8443",
        "https://monas.example.test:443",
        "https://monas.example.test:8443/path",
    ] {
        #expect(throws: FirstDevicePresentationError.malformed) {
            try SiteTrustEndpointIdentityV1(
                origin: invalid,
                tlsSPKISHA256: Data(repeating: 0x77, count: 32)
            )
        }
    }
}
