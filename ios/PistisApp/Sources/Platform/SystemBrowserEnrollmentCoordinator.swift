import Foundation

/// Authority-verifying exchange boundary for a future brokered profile.
///
/// ADR 0025 excludes this transport from v0.1. A future concrete broker must
/// have a separately accepted profile and implement issue 318's frozen receipt contract. It
/// must verify the exact host-signed receipt, its authority bootstrap, subject
/// registration, generations, identities, time, and endpoint hosts before
/// returning. A decoded server response is not sufficient.
protocol EnrollmentReceiptExchanging: Sendable {
    func exchangeAndVerify(
        authorization: OAuthAuthorizationCode,
        exactDeviceRegistrationEnvelope: Data
    ) async throws -> AuthenticatedEnrollmentOutput
}

/// Sequences a future one-use browser authorization and verified receipt
/// exchange before Keychain mutation.
///
/// There is intentionally no API that installs callback query values, scanned
/// material, or a decoded-but-unverified broker response.
@MainActor
final class SystemBrowserEnrollmentCoordinator {
    typealias BrowserAuthorization = @MainActor () async throws -> OAuthAuthorizationCode

    private let authorize: BrowserAuthorization
    private let broker: any EnrollmentReceiptExchanging
    private let trustStore: any InstallationTrustStoring

    init(
        authorize: @escaping BrowserAuthorization,
        broker: any EnrollmentReceiptExchanging,
        trustStore: any InstallationTrustStoring = InstallationTrustKeychain.shared
    ) {
        self.authorize = authorize
        self.broker = broker
        self.trustStore = trustStore
    }

    func enroll(exactDeviceRegistrationEnvelope: Data) async throws {
        guard !exactDeviceRegistrationEnvelope.isEmpty,
              exactDeviceRegistrationEnvelope.count <= 2_048
        else { throw PlatformFailure.invalidConfiguration }
        let authorization = try await authorize()
        let verified = try await broker.exchangeAndVerify(
            authorization: authorization,
            exactDeviceRegistrationEnvelope: exactDeviceRegistrationEnvelope
        )
        try await trustStore.installAuthenticated(verified)
    }
}
