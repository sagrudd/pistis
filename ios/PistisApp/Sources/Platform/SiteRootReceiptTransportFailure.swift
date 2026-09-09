import Foundation

/// Closed receipt transport diagnostics. Never retains an underlying error,
/// URL, response body, header, proof or custody material.
struct SiteRootReceiptTransportFailure: Equatable, Sendable {
    enum Operation: String, Sendable { case presentation, submission }
    enum Reason: Equatable, Sendable {
        case cancelled, tls, timeout, offline, network, nonHTTP, endpoint
        case dns, connection, connectionLost, authenticationChallenge
        case httpStatus(Int)
        case cacheControl, emptyPresentation, oversizedPresentation, submissionBody

        var code: String {
            switch self {
            case .cancelled: "cancelled"
            case .tls: "tls"
            case .timeout: "timeout"
            case .offline: "offline"
            case .network: "network"
            case .dns: "dns"
            case .connection: "connection"
            case .connectionLost: "connection-lost"
            case .authenticationChallenge: "authentication-challenge"
            case .nonHTTP: "non-http"
            case .endpoint: "endpoint"
            case let .httpStatus(status):
                (100 ... 599).contains(status) ? "http-\(status)" : "invalid-status"
            case .cacheControl: "cache-control"
            case .emptyPresentation: "empty-presentation"
            case .oversizedPresentation: "oversized-presentation"
            case .submissionBody: "submission-body"
            }
        }
    }

    let operation: Operation
    let reason: Reason

    var message: String {
        let code = "receipt-\(operation.rawValue)-\(reason.code)"
        switch operation {
        case .presentation:
            return "The receipt presentation could not be obtained (\(code)). No proof was sent."
        case .submission:
            return "Receipt submission was not confirmed (\(code)). It may have reached Monas. Do not repeat approval; check the authority's result."
        }
    }

    static func network(_ error: any Error, operation: Operation) -> Self {
        if error is CancellationError { return Self(operation: operation, reason: .cancelled) }
        let reason: Reason
        switch (error as? URLError)?.code {
        case .cancelled: reason = .cancelled
        case .timedOut: reason = .timeout
        case .cannotFindHost, .dnsLookupFailed: reason = .dns
        case .cannotConnectToHost: reason = .connection
        case .networkConnectionLost: reason = .connectionLost
        case .userCancelledAuthentication: reason = .authenticationChallenge
        case .notConnectedToInternet, .dataNotAllowed, .internationalRoamingOff:
            reason = .offline
        case .secureConnectionFailed, .serverCertificateHasBadDate,
             .serverCertificateUntrusted, .serverCertificateHasUnknownRoot,
             .serverCertificateNotYetValid, .clientCertificateRejected,
             .clientCertificateRequired:
            reason = .tls
        default: reason = .network
        }
        return Self(operation: operation, reason: reason)
    }

    /// Same receipt response predicates as the transport, with fixed failure
    /// categories instead of collapsing GET and potentially delivered POST.
    static func validate(
        data: Data, response: URLResponse, endpoint: URL, operation: Operation
    ) throws {
        func reject(_ reason: Reason) throws {
            throw PlatformFailure.siteRootReceiptTransport(Self(operation: operation, reason: reason))
        }
        guard let http = response as? HTTPURLResponse else { return try reject(.nonHTTP) }
        guard http.url == endpoint else { return try reject(.endpoint) }
        let expected = operation == .presentation ? 200 : 202
        guard http.statusCode == expected else { return try reject(.httpStatus(http.statusCode)) }
        if operation == .presentation, data.count > 16_384 { return try reject(.oversizedPresentation) }
        if operation == .submission, !data.isEmpty { return try reject(.submissionBody) }
        guard http.value(forHTTPHeaderField: "Cache-Control")?
            .lowercased().contains("no-store") == true
        else { return try reject(.cacheControl) }
        if operation == .presentation, data.isEmpty { return try reject(.emptyPresentation) }
    }
}
