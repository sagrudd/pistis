import Foundation
import XCTest

@testable import Pistis

final class SiteRootGenesisRegistrationTests: XCTestCase {
    private let origin = URL(string: "https://monas.example.test")!
    private let now: UInt64 = 1_700_000_000_000

    func testGenesisPresentationAcceptsOnlyFixedAuthorityAndExactNonceBinding() throws {
        let presentation = try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(),
            authorityOrigin: origin,
            nowUnixMillis: now
        )
        XCTAssertEqual(presentation.reference, "genesis-reference-1")
        XCTAssertEqual(presentation.siteTrustDomain, "site-demo-1")
        XCTAssertEqual(
            presentation.registrationURL.path,
            MonasSiteRootGenesisEndpointV1.registrationPath
        )
        XCTAssertEqual(presentation.appAttestChallengeDigest, Data(repeating: 0x22, count: 32))

        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(registrationURL: "https://other.example.test/auth/pistis/site-root-genesis/v1/register"),
            authorityOrigin: origin,
            nowUnixMillis: now
        ))
        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(expiry: now + 300_001),
            authorityOrigin: origin,
            nowUnixMillis: now
        ))
        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(extra: ",\"endpoint\":\"https://other.example.test\""),
            authorityOrigin: origin,
            nowUnixMillis: now
        ))
    }

    func testGenesisResultMustBindTheReturnedDelegationToTheSubmittedPublicKey() throws {
        let request = try request()
        let canonical = canonicalDelegation(deviceKeyID: request.siteRootKey.deviceKeyID)
        let result = try MonasSiteRootGenesisRegistrationResult(
            data: resultJSON(
                canonical: canonical,
                deviceKeyID: request.siteRootKey.deviceKeyID,
                reference: request.presentation.reference
            ),
            request: request,
            authorityOrigin: origin
        )
        XCTAssertEqual(result.presentation.deviceKeyID, request.siteRootKey.deviceKeyID)
        XCTAssertEqual(result.presentation.canonicalDelegationJSON, canonical)

        XCTAssertThrowsError(try MonasSiteRootGenesisRegistrationResult(
            data: resultJSON(
                canonical: canonical,
                deviceKeyID: "site-root-other",
                reference: request.presentation.reference
            ),
            request: request,
            authorityOrigin: origin
        ))
    }

    func testGenesisRequestContainsOnlyTypedPublicRegistrationAndExistingAppAttestEnvelope() throws {
        let request = try request()
        let encoded = try JSONEncoder().encode(MonasSiteRootGenesisRegistrationRequest(request))
        let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        XCTAssertEqual(Set(object.keys), ["schema", "reference", "site_root_key", "app_attest_registration"])
        XCTAssertEqual(object["schema"] as? String, "monas.site-root-genesis-registration.v1")
        XCTAssertNil(object["token"])
        XCTAssertNil(object["cookie"])
        XCTAssertNil(object["private_key"])
        let key = try XCTUnwrap(object["site_root_key"] as? [String: Any])
        XCTAssertEqual(key["device_key_id"] as? String, request.siteRootKey.deviceKeyID)
        XCTAssertEqual(key["secure_enclave_attestation"] as? String, "not-asserted")
    }

    @MainActor
    func testPresentedReviewSurvivesTransitionOutOfReviewPhase() async throws {
        let coordinator = SiteRootDelegationCoordinator(
            transport: GenesisReviewTransport(origin: origin)
        )

        coordinator.accept(qrText: genesisQR())
        let review = try XCTUnwrap(coordinator.presentedReview)
        XCTAssertTrue(review.isFirstDevice)

        // Simulator/device hardware may reject the protected-key operation;
        // either outcome must retain the attended review surface. Otherwise
        // SwiftUI dismisses the sheet and resets a ceremony before it can
        // submit its first network request.
        await coordinator.approve()
        XCTAssertEqual(coordinator.presentedReview, review)
    }

    private func request() throws -> SiteRootGenesisRegistrationRequestV1 {
        let presentation = try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(), authorityOrigin: origin, nowUnixMillis: now
        )
        let siteRootKey = SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-1234",
            publicKeyCompressedSEC1: Data([0x02] + Array(repeating: 0x11, count: 32)),
            secureEnclaveAttestation: "not-asserted"
        )
        let appAttestRegistration = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: presentation.appAttestCeremonyIDB64URL,
            siteTrustDomain: presentation.siteTrustDomain,
            appleKeyID: Data(repeating: 0x33, count: 32).base64EncodedString(),
            clientDataHash: presentation.appAttestChallengeDigest,
            attestationObject: Data(repeating: 0x44, count: 128)
        )
        return SiteRootGenesisRegistrationRequestV1(
            presentation: presentation,
            siteRootKey: siteRootKey,
            appAttestRegistration: appAttestRegistration
        )
    }

    private func canonicalDelegation(deviceKeyID: String) -> Data {
        Data("{\"device_key_id\":\"\(deviceKeyID)\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\",\"site_trust_domain\":\"site-demo-1\"}".utf8)
    }

    private func genesisQR(
        registrationURL: String = "https://monas.example.test/auth/pistis/site-root-genesis/v1/register",
        expiry: UInt64? = nil,
        extra: String = ""
    ) -> String {
        "{\"schema\":\"monas.site-root-genesis-registration-presentation.v1\",\"reference\":\"genesis-reference-1\",\"site_trust_domain\":\"site-demo-1\",\"registration_url\":\"\(registrationURL)\",\"app_attest_ceremony_id_b64url\":\"\(base64URL(Data(repeating: 0x11, count: 16)))\",\"app_attest_challenge_digest_b64url\":\"\(base64URL(Data(repeating: 0x22, count: 32)))\",\"expires_at_unix_millis\":\(expiry ?? now + 60_000)\(extra)}"
    }

    private func resultJSON(canonical: Data, deviceKeyID: String, reference: String) -> Data {
        Data("{\"schema\":\"monas.site-root-genesis-registration-result.v1\",\"canonical_delegation_base64url\":\"\(base64URL(canonical))\",\"device_key_id\":\"\(deviceKeyID)\",\"site_trust_domain\":\"site-demo-1\",\"submit_url\":\"https://monas.example.test/auth/pistis/site-root-delegations/v1/submit\",\"reference\":\"\(reference)\"}".utf8)
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private struct GenesisReviewTransport: MonasSiteRootCeremonyTransport {
    let origin: URL
    var genesisAuthorityOrigin: URL? { origin }

    func submit(_: MonasSiteRootDelegationSubmissionRequestV1) async throws
        -> MonasAppAttestCeremonyBootstrap
    {
        throw PlatformFailure.productionEnvelopeUnavailable
    }

    func registerGenesis(_: SiteRootGenesisRegistrationRequestV1) async throws
        -> SiteRootDelegationPresentationV1
    {
        throw PlatformFailure.productionEnvelopeUnavailable
    }
}
