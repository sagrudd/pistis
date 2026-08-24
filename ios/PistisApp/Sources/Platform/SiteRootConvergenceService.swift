import CryptoKit
import Foundation
import Security

struct SiteRootConvergenceAckRegistrationV2: Equatable, Sendable {
    let siteUUID: String
    let targetID: Data
    let ackPublicKeyCompressedSEC1: Data
    let enrolledDeviceProofCOSE: Data
}

struct SiteRootConvergenceAckRegistrationResultV2: Equatable, Sendable {
    let siteUUID: String
    let targetID: Data
    let generation: UInt64
}

protocol MonasSiteRootConvergenceSubmitting: Sendable {
    var authorityOrigin: URL { get }
    func submitBundleReceiptProvision(
        _ presentation: SiteRootBundleReceiptProvisionPresentationV1,
        detachedCOSE: Data
    ) async throws -> UInt64
    func submitSiteX509FirstProvision(
        _ presentation: SiteX509FirstProvisionPresentationV1,
        detachedCOSE: Data
    ) async throws
    func reserveSiteX509FirstProvisionBroker(
        _ presentation: SiteX509FirstProvisionBrokerPresentationV1
    ) async throws
    func submitSiteX509FirstProvisionBroker(
        _ presentation: SiteX509FirstProvisionBrokerPresentationV1,
        detachedCOSE: Data
    ) async throws
    func registerAckKey(_ registration: SiteRootConvergenceAckRegistrationV2) async throws
        -> SiteRootConvergenceAckRegistrationResultV2
    func submitAck(_ signedPXRA: Data, endpoint: URL) async throws
    func fetchBundleReceiptUnlock(nowUnixSeconds: UInt64) async throws
        -> IphoneMediatedCustodyRewrapPresentationV1
    func submitBundleReceiptUnlock(
        _ submission: IphoneMediatedCustodyRewrapSubmissionV1
    ) async throws
}

enum SiteX509BrokerContinuationPhaseV1: String, Sendable {
    case rootUnlock = "root-unlock"
    case issuerUnlock = "issuer-unlock"
    case ackRegistration = "ack-registration"
    case leafApproval = "leaf-approval"
}

struct SiteX509BrokerContinuationPresentationV1: Sendable {
    let payload: Data
    let sha256: Data
}

protocol MonasSiteX509BrokerContinuing: Sendable {
    func awaitSiteX509Continuation(
        correlation: Data, phase: SiteX509BrokerContinuationPhaseV1
    ) async throws -> SiteX509BrokerContinuationPresentationV1?
    func submitSiteX509Continuation(
        correlation: Data, phase: SiteX509BrokerContinuationPhaseV1,
        presentationSHA256: Data, submission: Data
    ) async throws
}

/// The first Site X.509 approval is deliberately brokered by the fixed
/// install service. It must remain available before a customer appliance has
/// a native Site Root authority profile, while every later direct authority
/// operation remains unavailable until the signed build configuration exists.
struct MonasSiteX509FirstProvisionBrokerTransport: MonasSiteRootConvergenceSubmitting,
    MonasSiteX509BrokerContinuing, Sendable
{
    let authorityOrigin: URL
    private let session: URLSession

    init() throws {
        guard let origin = URL(string: SiteRootConvergenceProfileV2.x509BrokerOrigin),
              MonasSiteRootDelegationTransport.isValidOrigin(origin)
        else { throw PlatformFailure.invalidConfiguration }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        authorityOrigin = origin
        session = URLSession(
            configuration: configuration,
            delegate: RedirectRejectingSessionDelegate(),
            delegateQueue: nil
        )
    }

    init(session: URLSession) throws {
        guard let origin = URL(string: SiteRootConvergenceProfileV2.x509BrokerOrigin),
              MonasSiteRootDelegationTransport.isValidOrigin(origin)
        else { throw PlatformFailure.invalidConfiguration }
        authorityOrigin = origin
        self.session = session
    }

    func submitBundleReceiptProvision(
        _: SiteRootBundleReceiptProvisionPresentationV1,
        detachedCOSE _: Data
    ) async throws -> UInt64 {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func submitSiteX509FirstProvision(
        _: SiteX509FirstProvisionPresentationV1,
        detachedCOSE _: Data
    ) async throws {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func reserveSiteX509FirstProvisionBroker(
        _ presentation: SiteX509FirstProvisionBrokerPresentationV1
    ) async throws {
        guard let brokerOrigin = URL(string: SiteRootConvergenceProfileV2.x509BrokerOrigin),
              SiteRootConvergenceEncoding.matches(
                  presentation.submissionURL, origin: brokerOrigin,
                  path: SiteRootConvergenceProfileV2.x509BrokerSubmitPath
              ) else { throw PlatformFailure.invalidConfiguration }
        let endpoint = try fixedEndpoint(SiteRootConvergenceProfileV2.x509BrokerAttemptPath)
        let body: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.x509BrokerAttemptSchema,
            "purpose": SiteRootConvergenceProfileV2.x509BrokerPurpose,
            "correlation_b64url": SiteRootConvergenceEncoding.encode(
                presentation.correlation
            ),
            "site_uuid": presentation.siteUUID,
            "transaction_uuid": presentation.transactionUUID,
            "generation": presentation.generation,
            "canonical_challenge_b64url": SiteRootConvergenceEncoding.encode(
                presentation.challenge
            ),
            "roles": SiteX509FirstProvisionBrokerPresentationV1.roles,
        ]
        let data = try await postAttemptJSON(body, endpoint: endpoint, maximum: 8_192)
        let object: [String: StrictJSONObject.Value]
        do { object = try StrictJSONObject(data: data, maximumBytes: 1_024).values }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
        guard Set(object.keys) == ["schema", "state"],
              SiteRootConvergenceEncoding.string(object, "schema")
                == SiteRootConvergenceProfileV2.x509BrokerResponseSchema,
              SiteRootConvergenceEncoding.string(object, "state")
                == SiteRootConvergenceProfileV2.x509BrokerAttemptResponseState
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    func submitSiteX509FirstProvisionBroker(
        _ presentation: SiteX509FirstProvisionBrokerPresentationV1,
        detachedCOSE: Data
    ) async throws {
        guard !detachedCOSE.isEmpty, detachedCOSE.count <= 4_096,
              let brokerOrigin = URL(string: SiteRootConvergenceProfileV2.x509BrokerOrigin),
              SiteRootConvergenceEncoding.matches(
                  presentation.submissionURL, origin: brokerOrigin,
                  path: SiteRootConvergenceProfileV2.x509BrokerSubmitPath
              )
        else { throw PlatformFailure.invalidConfiguration }
        let body: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.x509BrokerSubmissionSchema,
            "purpose": SiteRootConvergenceProfileV2.x509BrokerPurpose,
            "correlation_b64url": SiteRootConvergenceEncoding.encode(
                presentation.correlation
            ),
            "site_uuid": presentation.siteUUID,
            "transaction_uuid": presentation.transactionUUID,
            "generation": presentation.generation,
            "canonical_challenge_b64url": SiteRootConvergenceEncoding.encode(
                presentation.challenge
            ),
            "roles": SiteX509FirstProvisionBrokerPresentationV1.roles,
            "detached_cose_sign1_b64url": SiteRootConvergenceEncoding.encode(detachedCOSE),
        ]
        guard JSONSerialization.isValidJSONObject(body) else {
            throw PlatformFailure.invalidConfiguration
        }
        let requestBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        guard requestBody.count <= 8_192 else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: presentation.submissionURL)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = requestBody
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, rawResponse) = try await session.data(for: request)
            guard let response = rawResponse as? HTTPURLResponse,
                  response.url == presentation.submissionURL,
                  response.statusCode == 202, data.count <= 1_024,
                  response.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            let object = try StrictJSONObject(data: data, maximumBytes: 1_024).values
            guard Set(object.keys) == ["schema", "state"],
                  case let .string(schema)? = object["schema"],
                  schema == SiteRootConvergenceProfileV2.x509BrokerResponseSchema,
                  case let .string(state)? = object["state"], state == "accepted"
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    func awaitSiteX509Continuation(
        correlation: Data, phase: SiteX509BrokerContinuationPhaseV1
    ) async throws -> SiteX509BrokerContinuationPresentationV1? {
        guard correlation.count == 32 else { throw PlatformFailure.invalidConfiguration }
        let endpoint = try fixedEndpoint(
            SiteRootConvergenceProfileV2.x509BrokerContinuationPresentationPath
        )
        let deadline = Date().addingTimeInterval(300)
        while Date() < deadline {
            let data = try await postContinuationJSON([
                "schema": "mnemosyne.monas.first-install-broker.site-x509-continuation-presentation-poll.v1",
                "correlation_b64url": SiteRootConvergenceEncoding.encode(correlation),
                "phase": phase.rawValue,
            ], endpoint: endpoint, maximum: 2_048)
            let object = try StrictJSONObject(data: data, maximumBytes: 18_000).values
            guard SiteRootConvergenceEncoding.string(object, "schema")
                    == SiteRootConvergenceProfileV2.x509BrokerResponseSchema,
                  let state = SiteRootConvergenceEncoding.string(object, "state")
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            switch state {
            case "pending", "submitted":
                guard Set(object.keys) == ["schema", "state"] else {
                    throw PlatformFailure.siteRootAuthorityUnavailable
                }
                try await Task.sleep(for: .seconds(2))
            case "accepted":
                guard Set(object.keys) == ["schema", "state"] else {
                    throw PlatformFailure.siteRootAuthorityUnavailable
                }
                return nil
            case "ready":
                guard Set(object.keys) == [
                    "schema", "state", "presentation_b64url",
                    "presentation_sha256_b64url",
                ], let payload = SiteRootConvergenceEncoding.bytes(
                    object, "presentation_b64url", maximum: 16_384, nonzero: true
                ), let digest = SiteRootConvergenceEncoding.bytes(
                    object, "presentation_sha256_b64url", count: 32, nonzero: true
                ), Data(SHA256.hash(data: payload)) == digest
                else { throw PlatformFailure.siteRootAuthorityUnavailable }
                return SiteX509BrokerContinuationPresentationV1(
                    payload: payload, sha256: digest
                )
            default: throw PlatformFailure.siteRootAuthorityUnavailable
            }
        }
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func submitSiteX509Continuation(
        correlation: Data, phase: SiteX509BrokerContinuationPhaseV1,
        presentationSHA256: Data, submission: Data
    ) async throws {
        guard correlation.count == 32, presentationSHA256.count == 32,
              !submission.isEmpty, submission.count <= 16_384
        else { throw PlatformFailure.invalidConfiguration }
        let data = try await postContinuationJSON([
            "schema": "mnemosyne.monas.first-install-broker.site-x509-continuation-submission.v1",
            "correlation_b64url": SiteRootConvergenceEncoding.encode(correlation),
            "phase": phase.rawValue,
            "presentation_sha256_b64url": SiteRootConvergenceEncoding.encode(presentationSHA256),
            "submission_b64url": SiteRootConvergenceEncoding.encode(submission),
        ], endpoint: try fixedEndpoint(
            SiteRootConvergenceProfileV2.x509BrokerContinuationSubmissionPath
        ), maximum: 24_000)
        let object = try StrictJSONObject(data: data, maximumBytes: 1_024).values
        guard Set(object.keys) == ["schema", "state"],
              SiteRootConvergenceEncoding.string(object, "schema")
                == SiteRootConvergenceProfileV2.x509BrokerResponseSchema,
              SiteRootConvergenceEncoding.string(object, "state") == "submitted"
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    func registerAckKey(
        _: SiteRootConvergenceAckRegistrationV2
    ) async throws -> SiteRootConvergenceAckRegistrationResultV2 {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func submitAck(_: Data, endpoint _: URL) async throws {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func fetchBundleReceiptUnlock(
        nowUnixSeconds _: UInt64
    ) async throws -> IphoneMediatedCustodyRewrapPresentationV1 {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func submitBundleReceiptUnlock(
        _: IphoneMediatedCustodyRewrapSubmissionV1
    ) async throws {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    private func fixedEndpoint(_ path: String) throws -> URL {
        var components = URLComponents(
            string: SiteRootConvergenceProfileV2.x509BrokerOrigin
        )
        components?.path = path
        components?.query = nil
        components?.fragment = nil
        guard let endpoint = components?.url else {
            throw PlatformFailure.invalidConfiguration
        }
        return endpoint
    }

    private func postJSON(
        _ object: [String: Any], endpoint: URL, maximum: Int
    ) async throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw PlatformFailure.invalidConfiguration
        }
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard body.count <= maximum else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, rawResponse) = try await session.data(for: request)
            guard let response = rawResponse as? HTTPURLResponse,
                  response.url == endpoint,
                  response.statusCode == 202, data.count <= 1_024,
                  response.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            return data
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    private func postAttemptJSON(
        _ object: [String: Any], endpoint: URL, maximum: Int
    ) async throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw PlatformFailure.invalidConfiguration
        }
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard body.count <= maximum else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, rawResponse) = try await session.data(for: request)
            guard let response = rawResponse as? HTTPURLResponse,
                  response.url == endpoint,
                  data.count <= 1_024,
                  response.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            if response.statusCode == 409 {
                let object = try StrictJSONObject(data: data, maximumBytes: 1_024).values
                guard Set(object.keys) == ["schema", "state"],
                      SiteRootConvergenceEncoding.string(object, "schema")
                        == SiteRootConvergenceProfileV2.x509BrokerResponseSchema,
                      SiteRootConvergenceEncoding.string(object, "state") == "attempted"
                else { throw PlatformFailure.siteRootAuthorityUnavailable }
                throw PlatformFailure.siteX509PresentationAlreadyAttempted
            }
            guard response.statusCode == 202 else {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
            return data
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    private func postContinuationJSON(
        _ object: [String: Any], endpoint: URL, maximum: Int
    ) async throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw PlatformFailure.invalidConfiguration
        }
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard body.count <= maximum else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, rawResponse) = try await session.data(for: request)
            guard let response = rawResponse as? HTTPURLResponse,
                  response.url == endpoint, [200, 202].contains(response.statusCode),
                  data.count <= 18_000,
                  response.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            return data
        } catch let failure as PlatformFailure { throw failure }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
    }
}

struct MonasSiteRootConvergenceTransport: MonasSiteRootConvergenceSubmitting, Sendable {
    let authorityOrigin: URL
    private let session: URLSession
    private let brokerSession: URLSession

    init(authorityOrigin: URL, expectedSPKISHA256: Data) throws {
        guard expectedSPKISHA256.count == 32,
              !expectedSPKISHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.invalidConfiguration }
        try self.init(
            authorityOrigin: authorityOrigin,
            trustPolicy: .bootstrapLeafSPKI(expectedSPKISHA256)
        )
    }

    init(authorityOrigin: URL, trustPolicy: MonasServerTrustPolicy) throws {
        guard authorityOrigin.scheme == "https", authorityOrigin.host != nil
        else { throw PlatformFailure.invalidConfiguration }
        self.authorityOrigin = authorityOrigin
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        brokerSession = URLSession(
            configuration: configuration,
            delegate: RedirectRejectingSessionDelegate(),
            delegateQueue: nil
        )
        session = URLSession(
            configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(
                origin: authorityOrigin, trustPolicy: trustPolicy
            ),
            delegateQueue: nil
        )
    }

    func submitBundleReceiptProvision(
        _ presentation: SiteRootBundleReceiptProvisionPresentationV1,
        detachedCOSE: Data
    ) async throws -> UInt64 {
        guard !detachedCOSE.isEmpty, detachedCOSE.count <= 4_096 else {
            throw PlatformFailure.invalidConfiguration
        }
        let endpoint = try fixedEndpoint(SiteRootConvergenceProfileV2.provisionPath)
        let body: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.provisionSubmissionSchema,
            "purpose": SiteRootConvergenceProfileV2.provisionPurpose,
            "correlation_b64url": SiteRootConvergenceEncoding.encode(presentation.correlation),
            "canonical_challenge_b64url": SiteRootConvergenceEncoding.encode(
                presentation.canonicalChallenge
            ),
            "detached_cose_sign1_b64url": SiteRootConvergenceEncoding.encode(detachedCOSE),
        ]
        let data = try await postJSON(body, endpoint: endpoint, maximum: 8_192)
        return try Self.parseBundleReceiptProvisionAccepted(
            data, expectedGeneration: presentation.receiptKeyGeneration
        )
    }

    /// Decode the exact Monas relay response. Keeping this boundary independently
    /// testable prevents a locally invented response field from surviving while
    /// the production Rust relay emits a different closed JSON contract.
    static func parseBundleReceiptProvisionAccepted(
        _ data: Data, expectedGeneration: UInt64
    ) throws -> UInt64 {
        let object: [String: StrictJSONObject.Value]
        do { object = try StrictJSONObject(data: data, maximumBytes: 1_024).values }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
        guard Set(object.keys) == ["schema", "purpose", "receipt_key_generation"],
              SiteRootConvergenceEncoding.string(object, "schema")
                == "monas.site-root-bundle-receipt-provision-accepted.v1",
              SiteRootConvergenceEncoding.string(object, "purpose")
                == SiteRootConvergenceProfileV2.provisionPurpose,
              let generation = SiteRootConvergenceEncoding.positiveUInt64(
                  object, "receipt_key_generation"
              ),
              generation == expectedGeneration
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return generation
    }

    func submitSiteX509FirstProvision(
        _ presentation: SiteX509FirstProvisionPresentationV1,
        detachedCOSE: Data
    ) async throws {
        guard !detachedCOSE.isEmpty, detachedCOSE.count <= 4_096 else {
            throw PlatformFailure.invalidConfiguration
        }
        let endpoint = try fixedEndpoint(SiteRootConvergenceProfileV2.x509SubmitPath)
        let body: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.x509SubmissionSchema,
            "purpose": SiteRootConvergenceProfileV2.x509Purpose,
            "site_uuid": presentation.siteUUID,
            "transaction_uuid": presentation.transactionUUID,
            "generation": presentation.generation,
            "canonical_challenge_b64url": SiteRootConvergenceEncoding.encode(
                presentation.challenge
            ),
            "roles": SiteX509FirstProvisionPresentationV1.roles,
            "detached_cose_sign1_b64url": SiteRootConvergenceEncoding.encode(detachedCOSE),
        ]
        let data = try await postJSON(body, endpoint: endpoint, maximum: 8_192)
        let object = try strictObject(data)
        guard Set(object.keys) == ["schema", "purpose", "site_uuid", "generation", "roles"],
              SiteRootConvergenceEncoding.string(object, "schema")
                == "monas.site-x509-first-provision-accepted.v1",
              SiteRootConvergenceEncoding.string(object, "purpose")
                == SiteRootConvergenceProfileV2.x509Purpose,
              SiteRootConvergenceEncoding.string(object, "site_uuid") == presentation.siteUUID,
              SiteRootConvergenceEncoding.positiveUInt64(object, "generation")
                == presentation.generation,
              SiteRootConvergenceEncoding.stringArray(object, "roles")
                == SiteX509FirstProvisionPresentationV1.roles
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    func reserveSiteX509FirstProvisionBroker(
        _ presentation: SiteX509FirstProvisionBrokerPresentationV1
    ) async throws {
        guard let brokerOrigin = URL(string: SiteRootConvergenceProfileV2.x509BrokerOrigin),
              SiteRootConvergenceEncoding.matches(
                  presentation.submissionURL, origin: brokerOrigin,
                  path: SiteRootConvergenceProfileV2.x509BrokerSubmitPath
              ) else { throw PlatformFailure.invalidConfiguration }
        let endpoint = try fixedBrokerEndpoint(
            SiteRootConvergenceProfileV2.x509BrokerAttemptPath
        )
        let body: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.x509BrokerAttemptSchema,
            "purpose": SiteRootConvergenceProfileV2.x509BrokerPurpose,
            "correlation_b64url": SiteRootConvergenceEncoding.encode(
                presentation.correlation
            ),
            "site_uuid": presentation.siteUUID,
            "transaction_uuid": presentation.transactionUUID,
            "generation": presentation.generation,
            "canonical_challenge_b64url": SiteRootConvergenceEncoding.encode(
                presentation.challenge
            ),
            "roles": SiteX509FirstProvisionBrokerPresentationV1.roles,
        ]
        let data = try await postBrokerAttemptJSON(
            body, endpoint: endpoint, maximum: 8_192
        )
        let object = try strictObject(data)
        guard Set(object.keys) == ["schema", "state"],
              SiteRootConvergenceEncoding.string(object, "schema")
                == SiteRootConvergenceProfileV2.x509BrokerResponseSchema,
              SiteRootConvergenceEncoding.string(object, "state")
                == SiteRootConvergenceProfileV2.x509BrokerAttemptResponseState
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    func submitSiteX509FirstProvisionBroker(
        _ presentation: SiteX509FirstProvisionBrokerPresentationV1,
        detachedCOSE: Data
    ) async throws {
        guard !detachedCOSE.isEmpty, detachedCOSE.count <= 4_096,
              let brokerOrigin = URL(string: SiteRootConvergenceProfileV2.x509BrokerOrigin),
              SiteRootConvergenceEncoding.matches(
                  presentation.submissionURL, origin: brokerOrigin,
                  path: SiteRootConvergenceProfileV2.x509BrokerSubmitPath
              ) else { throw PlatformFailure.invalidConfiguration }
        let body: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.x509BrokerSubmissionSchema,
            "purpose": SiteRootConvergenceProfileV2.x509BrokerPurpose,
            "correlation_b64url": SiteRootConvergenceEncoding.encode(
                presentation.correlation
            ),
            "site_uuid": presentation.siteUUID,
            "transaction_uuid": presentation.transactionUUID,
            "generation": presentation.generation,
            "canonical_challenge_b64url": SiteRootConvergenceEncoding.encode(
                presentation.challenge
            ),
            "roles": SiteX509FirstProvisionBrokerPresentationV1.roles,
            "detached_cose_sign1_b64url": SiteRootConvergenceEncoding.encode(detachedCOSE),
        ]
        let data = try await postBrokerJSON(
            body, endpoint: presentation.submissionURL, maximum: 8_192
        )
        let object = try strictObject(data)
        guard Set(object.keys) == ["schema", "state"],
              SiteRootConvergenceEncoding.string(object, "schema")
                == SiteRootConvergenceProfileV2.x509BrokerResponseSchema,
              SiteRootConvergenceEncoding.string(object, "state") == "accepted"
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    func registerAckKey(_ registration: SiteRootConvergenceAckRegistrationV2) async throws
        -> SiteRootConvergenceAckRegistrationResultV2
    {
        guard registration.targetID.count == 32,
              registration.ackPublicKeyCompressedSEC1.count == 33,
              !registration.enrolledDeviceProofCOSE.isEmpty,
              registration.enrolledDeviceProofCOSE.count <= 4_096
        else { throw PlatformFailure.invalidConfiguration }
        let endpoint = try fixedEndpoint(SiteRootConvergenceProfileV2.registrationPath)
        let body: [String: Any] = [
            "schema": "monas.site-root-convergence-ack-registration.v2",
            "site_uuid": registration.siteUUID,
            "target_id_b64url": SiteRootConvergenceEncoding.encode(registration.targetID),
            "purpose": SiteRootConvergenceProfileV2.ackPurpose,
            "ack_public_key_compressed_sec1_b64url": SiteRootConvergenceEncoding.encode(
                registration.ackPublicKeyCompressedSEC1
            ),
            "enrolled_device_proof_cose_b64url": SiteRootConvergenceEncoding.encode(
                registration.enrolledDeviceProofCOSE
            ),
        ]
        let data = try await postJSON(body, endpoint: endpoint, maximum: 8_192)
        let object = try strictObject(data)
        guard Set(object.keys) == ["schema", "site_uuid", "target_id_b64url", "purpose", "generation"],
              SiteRootConvergenceEncoding.string(object, "schema")
                == "monas.site-root-convergence-ack-registration-result.v2",
              SiteRootConvergenceEncoding.string(object, "site_uuid") == registration.siteUUID,
              SiteRootConvergenceEncoding.string(object, "purpose")
                == SiteRootConvergenceProfileV2.ackPurpose,
              let target = SiteRootConvergenceEncoding.bytes(
                  object, "target_id_b64url", count: 32, nonzero: true
              ), target == registration.targetID,
              let generation = SiteRootConvergenceEncoding.positiveUInt64(object, "generation")
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return SiteRootConvergenceAckRegistrationResultV2(
            siteUUID: registration.siteUUID, targetID: target, generation: generation
        )
    }

    func submitAck(_ signedPXRA: Data, endpoint: URL) async throws {
        guard signedPXRA.count <= 768,
              SiteRootConvergenceEncoding.matches(
                  endpoint, origin: authorityOrigin,
                  path: SiteRootConvergenceProfileV2.ackSubmissionPath
              ) else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = signedPXRA
        request.setValue(
            SiteRootConvergenceProfileV2.pxraContentType, forHTTPHeaderField: "Content-Type"
        )
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        _ = try await response(request, endpoint: endpoint, maximum: 1_024)
    }

    func fetchBundleReceiptUnlock(nowUnixSeconds: UInt64) async throws
        -> IphoneMediatedCustodyRewrapPresentationV1
    {
        let endpoint = try fixedEndpoint(
            "/v1/pistis/site-root-bundle-receipt-unlock/presentation"
        )
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let data = try await response(request, endpoint: endpoint, maximum: 16_384)
        guard !data.isEmpty else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return try MonasRetainedCustodyPresentationResponseV1(
            data: data,
            nowUnixSeconds: nowUnixSeconds,
            expectedChallengeSchema: SiteRootBundleReceiptRewrapV1.challengeSchema,
            requiredGenerationPrefix: "site-root-bundle-receipt-"
        ).presentation
    }

    func submitBundleReceiptUnlock(
        _ submission: IphoneMediatedCustodyRewrapSubmissionV1
    ) async throws {
        guard submission.purpose == SiteRootBundleReceiptRewrapV1.purpose else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let endpoint = try fixedEndpoint(
            "/v1/pistis/site-root-bundle-receipt-unlock/submit"
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let body = try encoder.encode(MonasRetainedCustodyRewrapSubmissionV1(submission))
        guard body.count <= 16_384 else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = body
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, rawResponse) = try await session.data(for: request)
            guard let http = rawResponse as? HTTPURLResponse, http.url == endpoint,
                  http.statusCode == 202, data.isEmpty,
                  http.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
        } catch let failure as PlatformFailure { throw failure }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    private func postJSON(
        _ object: [String: Any], endpoint: URL, maximum: Int
    ) async throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw PlatformFailure.invalidConfiguration
        }
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard body.count <= maximum else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        return try await response(request, endpoint: endpoint, maximum: 1_024)
    }

    private func postBrokerJSON(
        _ object: [String: Any], endpoint: URL, maximum: Int
    ) async throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw PlatformFailure.invalidConfiguration
        }
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard body.count <= maximum else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, rawResponse) = try await brokerSession.data(for: request)
            guard let http = rawResponse as? HTTPURLResponse, http.url == endpoint,
                  http.statusCode == 202, data.count <= 1_024,
                  http.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            return data
        } catch let failure as PlatformFailure { throw failure }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    private func postBrokerAttemptJSON(
        _ object: [String: Any], endpoint: URL, maximum: Int
    ) async throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw PlatformFailure.invalidConfiguration
        }
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard body.count <= maximum else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, rawResponse) = try await brokerSession.data(for: request)
            guard let http = rawResponse as? HTTPURLResponse, http.url == endpoint,
                  data.count <= 1_024,
                  http.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            if http.statusCode == 409 {
                let object = try StrictJSONObject(data: data, maximumBytes: 1_024).values
                guard Set(object.keys) == ["schema", "state"],
                      SiteRootConvergenceEncoding.string(object, "schema")
                        == SiteRootConvergenceProfileV2.x509BrokerResponseSchema,
                      SiteRootConvergenceEncoding.string(object, "state") == "attempted"
                else { throw PlatformFailure.siteRootAuthorityUnavailable }
                throw PlatformFailure.siteX509PresentationAlreadyAttempted
            }
            guard http.statusCode == 202 else {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
            return data
        } catch let failure as PlatformFailure { throw failure }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    private func response(_ request: URLRequest, endpoint: URL, maximum: Int) async throws
        -> Data
    {
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.url == endpoint,
                  http.statusCode == 200, data.count <= maximum,
                  http.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            return data
        } catch let failure as PlatformFailure { throw failure }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    private func strictObject(_ data: Data) throws -> [String: StrictJSONObject.Value] {
        do { return try StrictJSONObject(data: data, maximumBytes: 1_024).values }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    private func fixedEndpoint(_ path: String) throws -> URL {
        guard var components = URLComponents(url: authorityOrigin, resolvingAgainstBaseURL: false)
        else { throw PlatformFailure.invalidConfiguration }
        components.path = path
        guard let endpoint = components.url else { throw PlatformFailure.invalidConfiguration }
        return endpoint
    }

    private func fixedBrokerEndpoint(_ path: String) throws -> URL {
        var components = URLComponents(
            string: SiteRootConvergenceProfileV2.x509BrokerOrigin
        )
        components?.path = path
        components?.query = nil
        components?.fragment = nil
        guard let endpoint = components?.url else {
            throw PlatformFailure.invalidConfiguration
        }
        return endpoint
    }
}

/// Bounded readiness hand-off between one-use receipt provision and the
/// steady attended-unlock runtime. Provision success is durable before the
/// host finalizer can expose its new Unix socket, so only that coarse,
/// transient authority-unavailable result is eligible for a short retry.
enum SiteRootBundleReceiptUnlockReadiness {
    static let maximumAttempts = 41

    static func awaitValue<Value: Sendable>(
        maximumAttempts: Int = 41,
        fetch: @Sendable () async throws -> Value,
        pause: @Sendable () async throws -> Void = {
            try await Task.sleep(for: .milliseconds(250))
        }
    ) async throws -> Value {
        guard maximumAttempts > 0 else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        for attempt in 1 ... maximumAttempts {
            do {
                return try await fetch()
            } catch let failure as PlatformFailure
                where failure == .siteRootAuthorityUnavailable
            {
                guard attempt < maximumAttempts else { throw failure }
                try await pause()
            }
        }
        throw PlatformFailure.siteRootAuthorityUnavailable
    }
}

struct SiteRootConvergenceAckRecordV2: Codable, Equatable, Sendable {
    let siteUUID: String
    let targetIDB64URL: String
    let ackPublicKeyB64URL: String
    let generation: UInt64
}

final class SiteRootConvergenceAckStoreV2: @unchecked Sendable {
    private let service = "org.mnemosyne.pistis.site-root-convergence-ack-v2"
    private let account = "registration"

    func retain(_ record: SiteRootConvergenceAckRecordV2) throws {
        if let existing = try load() {
            guard existing == record else { throw PlatformFailure.invalidConfiguration }
            return
        }
        let data = try JSONEncoder().encode(record)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: data,
        ]
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else {
            throw PlatformFailure.enrolmentStorageFailed
        }
    }

    /// Loads the exact enrolled acknowledgement signer binding. This exposes
    /// public identifiers only and never creates or repairs a signer.
    func current() throws -> SiteRootConvergenceAckRecordV2 {
        guard let record = try load(), record.generation > 0 else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        return record
    }

    private func load() throws -> SiteRootConvergenceAckRecordV2? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecItemNotFound: return nil
        case errSecSuccess:
            guard let data = item as? Data,
                  let value = try? JSONDecoder().decode(
                      SiteRootConvergenceAckRecordV2.self, from: data
                  ) else { throw PlatformFailure.enrolmentStorageFailed }
            return value
        default: throw PlatformFailure.enrolmentStorageFailed
        }
    }
}

private struct BrokerSiteX509AuthorizationV1: @unchecked Sendable {
    let detachedCOSE: Data
    let ceremony: FaceIDCeremonyContext?
}

struct SiteRootConvergenceServiceV2: Sendable {
    private let transport: any MonasSiteRootConvergenceSubmitting
    private let continuationTransport: (any MonasSiteX509BrokerContinuing)?
    private let store: SiteRootConvergenceAckStoreV2
    private let brokerAuthorizationFactory: @Sendable (
        SiteX509FirstProvisionBrokerPresentationV1
    ) async throws -> BrokerSiteX509AuthorizationV1

    init(
        transport: any MonasSiteRootConvergenceSubmitting,
        continuationTransport: (any MonasSiteX509BrokerContinuing)? = nil,
        store: SiteRootConvergenceAckStoreV2 = SiteRootConvergenceAckStoreV2()
    ) {
        self.transport = transport
        self.continuationTransport = continuationTransport
            ?? (transport as? any MonasSiteX509BrokerContinuing)
        self.store = store
        brokerAuthorizationFactory = SiteRootConvergenceServiceV2.makeBrokerAuthorization
    }

    init(
        transport: any MonasSiteRootConvergenceSubmitting,
        continuationTransport: (any MonasSiteX509BrokerContinuing)? = nil,
        store: SiteRootConvergenceAckStoreV2 = SiteRootConvergenceAckStoreV2(),
        brokerProofFactory: @escaping @Sendable (
            SiteX509FirstProvisionBrokerPresentationV1
        ) async throws -> Data
    ) {
        self.transport = transport
        self.continuationTransport = continuationTransport
            ?? (transport as? any MonasSiteX509BrokerContinuing)
        self.store = store
        brokerAuthorizationFactory = { presentation in
            BrokerSiteX509AuthorizationV1(
                detachedCOSE: try await brokerProofFactory(presentation), ceremony: nil
            )
        }
    }

    @MainActor
    func provisionBundleReceipt(
        _ presentation: SiteRootBundleReceiptProvisionPresentationV1,
        didProvision: () -> Void = {}
    ) async throws {
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Approve this exact Site Root receipt key provision"
        )
        let siteRoot = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Approve this exact Site Root receipt key provision"
        )
        guard try siteRoot.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let publicKey = try siteRoot.publicKey(using: ceremony)
        let deviceKeyID = Self.siteRootDeviceKeyID(publicKey.compressedSEC1)
        try presentation.validateChallenge(deviceKeyID: deviceKeyID)
        let protected = try DetachedES256Cose.protectedHeaders(kid: deviceKeyID)
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: presentation.canonicalChallenge
        )
        let signature = try siteRoot.sign(message: structure, using: ceremony)
        let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)
        _ = try await transport.submitBundleReceiptProvision(presentation, detachedCOSE: cose)
        didProvision()
        let convergenceTransport = transport
        let unlock = try await SiteRootBundleReceiptUnlockReadiness.awaitValue(
            maximumAttempts: SiteRootBundleReceiptUnlockReadiness.maximumAttempts,
            fetch: {
                try await convergenceTransport.fetchBundleReceiptUnlock(
                    nowUnixSeconds: Self.nowUnixSeconds()
                )
            }
        )
        let rewrap = try SecureEnclaveSiteRootBundleReceiptRewrapProducerV1()
            .produce(unlock, using: ceremony)
        try await transport.submitBundleReceiptUnlock(rewrap)
    }

    func provisionSiteX509(_ presentation: SiteX509FirstProvisionPresentationV1) async throws {
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Approve fresh Site X.509 root and issuer custody"
        )
        let siteRoot = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Approve fresh Site X.509 root and issuer custody"
        )
        guard try siteRoot.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let publicKey = try siteRoot.publicKey(using: ceremony)
        let target = Data(SHA256.hash(data: publicKey.compressedSEC1))
        let protected = try DetachedES256Cose.protectedHeaders(
            kid: target, contentType: SiteRootConvergenceProfileV2.x509ContentType
        )
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: presentation.challenge
        )
        let signature = try siteRoot.sign(message: structure, using: ceremony)
        let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)
        try await transport.submitSiteX509FirstProvision(presentation, detachedCOSE: cose)
    }

    func provisionSiteX509Broker(
        _ presentation: SiteX509FirstProvisionBrokerPresentationV1
    ) async throws {
        // The fixed broker reservation is deliberately the first side effect.
        // It consumes the QR even when Face ID, App Attest, signing, or the
        // later proof submission fails; a failed authorization must not make
        // the same protected presentation reusable.
        try await transport.reserveSiteX509FirstProvisionBroker(presentation)
        let authorization = try await brokerAuthorizationFactory(presentation)
        try await transport.submitSiteX509FirstProvisionBroker(
            presentation, detachedCOSE: authorization.detachedCOSE
        )
        if let continuation = continuationTransport,
           let ceremony = authorization.ceremony
        {
            try await continueBrokerSiteX509(
                correlation: presentation.correlation,
                expectedSiteUUID: presentation.siteUUID,
                transport: continuation,
                authorizer: SecureEnclaveSiteX509BrokerContinuationAuthorizerV2(
                    ceremony: ceremony, store: store
                )
            )
        }
    }

    func continueRecoveredSiteX509(
        _ presentation: SiteX509ContinuationRecoveryPresentationV1
    ) async throws {
        guard let continuation = continuationTransport else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Resume accepted Site X.509 custody and certificate approval"
        )
        try await continueBrokerSiteX509(
            correlation: presentation.correlation,
            expectedSiteUUID: presentation.siteUUID,
            transport: continuation,
            authorizer: SecureEnclaveSiteX509BrokerContinuationAuthorizerV2(
                ceremony: ceremony, store: store
            )
        )
    }

    static func validateBrokerEnrolledSiteRootPublicKeyID(
        _ expectedKeyID: Data, actualPublicKeyCompressedSEC1: Data
    ) throws {
        guard Data(SHA256.hash(data: actualPublicKeyCompressedSEC1)) == expectedKeyID else {
            throw PlatformFailure.siteRootAuthorityKeyMismatch
        }
    }

    private static func makeBrokerAuthorization(
        _ presentation: SiteX509FirstProvisionBrokerPresentationV1
    ) async throws -> BrokerSiteX509AuthorizationV1 {
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Approve fresh Site X.509 root and issuer custody"
        )
        let siteRoot = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Approve fresh Site X.509 root and issuer custody"
        )
        guard try siteRoot.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let publicKey = try siteRoot.publicKey(using: ceremony)
        try validateBrokerEnrolledSiteRootPublicKeyID(
            presentation.enrolledSiteRootPublicKeyID,
            actualPublicKeyCompressedSEC1: publicKey.compressedSEC1
        )
        let target = Data(SHA256.hash(data: publicKey.compressedSEC1))
        let protected = try DetachedES256Cose.protectedHeaders(
            kid: target, contentType: SiteRootConvergenceProfileV2.x509ContentType
        )
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: presentation.challenge
        )
        let signature = try siteRoot.sign(message: structure, using: ceremony)
        let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)
        return BrokerSiteX509AuthorizationV1(detachedCOSE: cose, ceremony: ceremony)
    }

    func continueBrokerSiteX509(
        correlation: Data,
        expectedSiteUUID: String,
        transport: any MonasSiteX509BrokerContinuing,
        authorizer: any SiteX509BrokerContinuationAuthorizingV2
    ) async throws {
        for (phase, role) in [
            (SiteX509BrokerContinuationPhaseV1.rootUnlock, SiteX509AttendedUnlockRoleV2.root),
            (.issuerUnlock, .issuer),
        ] {
            guard let brokered = try await transport.awaitSiteX509Continuation(
                correlation: correlation, phase: phase
            ) else { continue }
            let submission = try authorizer.attendedUnlock(
                brokered.payload, role: role
            )
            try await transport.submitSiteX509Continuation(
                correlation: correlation, phase: phase,
                presentationSHA256: brokered.sha256,
                submission: submission
            )
        }

        try authorizer.prepareAckRegistration(expectedSiteUUID: expectedSiteUUID)
        if let brokered = try await transport.awaitSiteX509Continuation(
            correlation: correlation, phase: .ackRegistration
        ) {
            let submission = try authorizer.ackRegistration(brokered.payload)
            try await transport.submitSiteX509Continuation(
                correlation: correlation, phase: .ackRegistration,
                presentationSHA256: brokered.sha256,
                submission: submission
            )
        }

        if let brokered = try await transport.awaitSiteX509Continuation(
            correlation: correlation, phase: .leafApproval
        ) {
            let submission = try authorizer.leafApproval(brokered.payload)
            try await transport.submitSiteX509Continuation(
                correlation: correlation, phase: .leafApproval,
                presentationSHA256: brokered.sha256,
                submission: submission
            )
        }
    }

    func acknowledge(_ presentation: SiteRootConvergenceAckPresentationV2) async throws {
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Approve this exact Site Root HTTPS convergence"
        )
        let siteRoot = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Approve this exact Site Root HTTPS convergence"
        )
        let ack = try SecureEnclaveSigner(
            namespace: "site-root-convergence-ack-v2",
            authenticationReason: "Approve this exact Site Root HTTPS convergence"
        )
        guard try siteRoot.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let siteRootPublic = try siteRoot.publicKey(using: ceremony)
        let target = Data(SHA256.hash(data: siteRootPublic.compressedSEC1))
        guard target == presentation.assertion.targetID else {
            throw PlatformFailure.invalidConfiguration
        }
        let ackPublic = try ack.create(using: ceremony).compressedSEC1
        let registrationPayload = Data("PXAK/v2".utf8) + presentation.assertion.siteUUID
            + target + ackPublic
        guard registrationPayload.count == 88 else { throw PlatformFailure.invalidConfiguration }
        let registrationProtected = try DetachedES256Cose.protectedHeaders(
            kid: target, contentType: SiteRootConvergenceProfileV2.pxakContentType
        )
        let registrationStructure = try DetachedES256Cose.signatureStructure(
            protected: registrationProtected, payload: registrationPayload
        )
        let registrationSignature = try siteRoot.sign(
            message: registrationStructure, using: ceremony
        )
        let registrationProof = try DetachedES256Cose.envelope(
            protected: registrationProtected, signature: registrationSignature
        )
        let result = try await transport.registerAckKey(
            SiteRootConvergenceAckRegistrationV2(
                siteUUID: presentation.assertion.siteUUIDText,
                targetID: target,
                ackPublicKeyCompressedSEC1: ackPublic,
                enrolledDeviceProofCOSE: registrationProof
            )
        )
        guard result.generation == presentation.assertion.ackKeyGeneration else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        try store.retain(SiteRootConvergenceAckRecordV2(
            siteUUID: result.siteUUID,
            targetIDB64URL: SiteRootConvergenceEncoding.encode(target),
            ackPublicKeyB64URL: SiteRootConvergenceEncoding.encode(ackPublic),
            generation: result.generation
        ))
        let ackProtected = try DetachedES256Cose.protectedHeaders(
            kid: SiteRootConvergenceEncoding.uint64Bytes(result.generation),
            contentType: SiteRootConvergenceProfileV2.pxraContentType
        )
        let ackStructure = try DetachedES256Cose.signatureStructure(
            protected: ackProtected, payload: presentation.unsignedPXRA
        )
        let ackSignature = try ack.sign(message: ackStructure, using: ceremony)
        let proof = try DetachedES256Cose.envelope(
            protected: ackProtected, signature: ackSignature
        )
        let signed = presentation.unsignedPXRA + proof
        guard signed.count <= 768 else { throw PlatformFailure.invalidConfiguration }
        try await transport.submitAck(signed, endpoint: presentation.submissionURL)
    }

    private static func siteRootDeviceKeyID(_ publicKey: Data) -> String {
        "site-root-" + Data(SHA256.hash(data: publicKey)).map {
            String(format: "%02x", $0)
        }.joined()
    }

    static func nowUnixSeconds() throws -> UInt64 {
        let value = Date().timeIntervalSince1970
        guard value >= 0, value <= TimeInterval(UInt64.max) else {
            throw PlatformFailure.invalidConfiguration
        }
        return UInt64(value)
    }
}
