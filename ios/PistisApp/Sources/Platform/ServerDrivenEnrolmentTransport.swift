import CryptoKit
import Foundation
import PistisCore

struct ProviderVerificationHandle: Sendable {
    let operationID: Data
    let providerVerificationID: Data
    let pollingCapability: Data
    let prompt: GitHubDeviceAuthorizationPrompt
    let expiresAtMilliseconds: UInt64
    let pollAfterMilliseconds: UInt64
}

enum ProviderVerificationStatus: Equatable, Sendable {
    case pending(pollAfterMilliseconds: UInt64)
    case verified(
        numericSubject: UInt64,
        displayLogin: String?,
        policyGeneration: UInt64,
        authorityChallenge: Data,
        authorityChallengeExpiresAtMilliseconds: UInt64
    )
    case denied
    case cancelled
    case expired
    case consumed
}

/// Closed ADR 0027 mobile port to the enrolment-only Monas process.
///
/// The adapter handle, GitHub token, refresh token, raw provider response and
/// mutable identity inputs have no representation in this API.
struct ServerDrivenEnrolmentTransport: Sendable {
    private static let beginPath = "/auth/pistis/v1/first-device-enrolments/begin"
    private static let statusPath = "/auth/pistis/v1/first-device-enrolments/status"
    private static let cancelPath = "/auth/pistis/v1/first-device-enrolments/cancel"
    private static let confirmPath = "/auth/pistis/v1/first-device-enrolments/confirm"

    private let presentation: VerifiedFirstDevicePresentation
    private let session: URLSession

    init(
        presentation: VerifiedFirstDevicePresentation,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        self.presentation = presentation
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(
            configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(
                origin: presentation.httpsOrigin,
                expectedSPKISHA256: presentation.tlsSPKISHA256
            ),
            delegateQueue: nil
        )
    }

    func begin(
        operationID: Data,
        deviceKeyID: Data,
        devicePublicKey: Data,
        keyAssurance: String
    ) async throws -> ProviderVerificationHandle {
        let parsedDeviceKey = try? P256.Signing.PublicKey(
            compressedRepresentation: devicePublicKey
        )
        let derivedKeyID = Data(SHA256.hash(
            data: Data("pistis:key-id:v1\0".utf8) + devicePublicKey
        ))
        guard operationID.count == 16,
              !operationID.allSatisfy({ $0 == 0 }),
              deviceKeyID.count == 32,
              devicePublicKey.count == 33,
              parsedDeviceKey?.compressedRepresentation == devicePublicKey,
              deviceKeyID == derivedKeyID,
              keyAssurance == "secure-enclave-biometry-current-set"
        else { throw PlatformFailure.invalidConfiguration }
        let body = try encode([
            "version": 1,
            "operation_id": base64URL(operationID),
            "invitation": base64URL(presentation.exactInvitation),
            "presentation_digest": base64URL(presentation.presentationDigest),
            "device_key_id": base64URL(deviceKeyID),
            "device_public_key": base64URL(devicePublicKey),
            "key_assurance": keyAssurance,
            "app_configuration_digest": base64URL(
                presentation.appConfigurationDigest
            ),
        ])
        let object = try await request(
            path: Self.beginPath,
            body: body,
            maximumResponseBytes: 4_096
        )
        let expected: Set<String> = [
            "version", "provider_verification_id", "polling_capability",
            "user_code", "verification_uri", "expires_at_ms", "poll_after_ms",
        ]
        guard Set(object.keys) == expected,
              number(object["version"]) == 1,
              let verificationID = bytes(object["provider_verification_id"], count: 16),
              let capability = bytes(object["polling_capability"], count: 32),
              !verificationID.allSatisfy({ $0 == 0 }),
              !capability.allSatisfy({ $0 == 0 }),
              let userCode = text(object["user_code"], maximum: 9),
              validUserCode(userCode),
              text(object["verification_uri"], maximum: 31)
                == "https://github.com/login/device",
              let expires = number(object["expires_at_ms"]),
              let pollAfter = number(object["poll_after_ms"]),
              (1_000 ... 60_000).contains(pollAfter)
        else { throw PlatformFailure.productionEnvelopeUnavailable }
        return ProviderVerificationHandle(
            operationID: operationID,
            providerVerificationID: verificationID,
            pollingCapability: capability,
            prompt: .init(
                userCode: userCode,
                verificationURI: GitHubEnrolmentConfiguration.verificationURI,
                expiresInSeconds: 0,
                intervalSeconds: pollAfter / 1_000
            ),
            expiresAtMilliseconds: expires,
            pollAfterMilliseconds: pollAfter
        )
    }

    func status(_ handle: ProviderVerificationHandle) async throws
        -> ProviderVerificationStatus
    {
        let object = try await request(
            path: Self.statusPath,
            body: try handleBody(handle),
            maximumResponseBytes: 2_048
        )
        guard number(object["version"]) == 1,
              let state = text(object["state"], maximum: 16)
        else { throw PlatformFailure.productionEnvelopeUnavailable }
        switch state {
        case "pending":
            guard Set(object.keys) == ["version", "state", "poll_after_ms"],
                  let interval = number(object["poll_after_ms"]),
                  (1_000 ... 60_000).contains(interval)
            else { throw PlatformFailure.productionEnvelopeUnavailable }
            return .pending(pollAfterMilliseconds: interval)
        case "verified":
            guard Set(object.keys) == [
                "version", "state", "numeric_subject", "display_login",
                "policy_generation", "authority_challenge",
                "authority_challenge_expires_at_ms",
            ],
                let subjectText = text(object["numeric_subject"], maximum: 20),
                let subject = canonicalSubject(subjectText),
                let display = optionalText(object["display_login"], maximum: 128),
                let policyGeneration = number(object["policy_generation"]),
                policyGeneration > 0,
                let challenge = bytes(object["authority_challenge"], count: 32),
                !challenge.allSatisfy({ $0 == 0 }),
                let challengeExpires = number(
                    object["authority_challenge_expires_at_ms"]
                ),
                challengeExpires <= handle.expiresAtMilliseconds
            else { throw PlatformFailure.productionEnvelopeUnavailable }
            return .verified(
                numericSubject: subject,
                displayLogin: display,
                policyGeneration: policyGeneration,
                authorityChallenge: challenge,
                authorityChallengeExpiresAtMilliseconds: challengeExpires
            )
        case "denied", "cancelled", "expired", "consumed":
            guard Set(object.keys) == ["version", "state"] else {
                throw PlatformFailure.productionEnvelopeUnavailable
            }
            return switch state {
            case "denied": .denied
            case "cancelled": .cancelled
            case "expired": .expired
            default: .consumed
            }
        default:
            throw PlatformFailure.productionEnvelopeUnavailable
        }
    }

    func cancel(_ handle: ProviderVerificationHandle) async throws {
        let object = try await request(
            path: Self.cancelPath,
            body: try handleBody(handle),
            maximumResponseBytes: 256
        )
        guard Set(object.keys) == ["version", "state"],
              number(object["version"]) == 1,
              text(object["state"], maximum: 9) == "cancelled"
        else { throw PlatformFailure.productionEnvelopeUnavailable }
    }

    /// Submit and verify the exact signed binding and purpose-separated
    /// authority receipt before returning storage-ready public facts.
    func confirm(
        _ handle: ProviderVerificationHandle,
        deviceRegistrationCOSE: Data,
        binding: EnrolmentBindingInput,
        verificationTime: @Sendable () -> Date = Date.init
    ) async throws -> VerifiedMobileEnrolmentReceipt {
        guard !deviceRegistrationCOSE.isEmpty,
              deviceRegistrationCOSE.count <= 2_048
        else { throw PlatformFailure.invalidConfiguration }
        let body = try encode([
            "version": 1,
            "provider_verification_id": base64URL(
                handle.providerVerificationID
            ),
            "polling_capability": base64URL(handle.pollingCapability),
            "invitation": base64URL(presentation.exactInvitation),
            "device_registration_cose": base64URL(deviceRegistrationCOSE),
        ])
        let response = try await request(
            path: Self.confirmPath,
            body: body,
            maximumResponseBytes: 16_384
        )
        guard Set(response.keys) == [
            "version", "authority_bundle", "device_registration_cose",
            "mobile_enrolment_receipt_cose",
        ],
            number(response["version"]) == 1,
            let bundle = variableBytes(
                response["authority_bundle"],
                maximum: 512
            ),
            let returnedRegistration = variableBytes(
                response["device_registration_cose"],
                maximum: 2_048
            ),
            let receipt = variableBytes(
                response["mobile_enrolment_receipt_cose"],
                maximum: 8_192
            )
        else { throw PlatformFailure.enrolmentReceiptInvalid }
        do {
            return try MobileEnrolmentReceiptV2.verify(
                returnedAuthorityBundle: bundle,
                returnedRegistrationCOSE: returnedRegistration,
                receiptCOSE: receipt,
                expectedRegistrationCOSE: deviceRegistrationCOSE,
                binding: binding,
                // The receipt is created by the authority while the request is
                // in flight. Sampling before the request would reject every
                // honest receipt whose commit follows that stale timestamp.
                now: verificationTime()
            )
        } catch {
            throw PlatformFailure.enrolmentReceiptInvalid
        }
    }

    private func handleBody(_ handle: ProviderVerificationHandle) throws -> Data {
        try encode([
            "version": 1,
            "provider_verification_id": base64URL(
                handle.providerVerificationID
            ),
            "polling_capability": base64URL(handle.pollingCapability),
        ])
    }

    private func request(path: String, body: Data, maximumResponseBytes: Int)
        async throws -> [String: StrictJSONObject.Value]
    {
        let data = try await rawRequest(
            path: path,
            body: body,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            return try StrictJSONObject(
                data: data,
                maximumBytes: maximumResponseBytes
            ).values
        } catch {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
    }

    private func rawRequest(path: String, body: Data, maximumResponseBytes: Int)
        async throws -> Data
    {
        guard body.count <= 8_192,
              let endpoint = URL(
                  string: path,
                  relativeTo: presentation.httpsOrigin
              )?.absoluteURL,
              endpoint.absoluteString
                  == presentation.httpsOrigin.absoluteString + path
        else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = body
        request.timeoutInterval = 15
        request.setValue(
            "application/json; charset=utf-8",
            forHTTPHeaderField: "Content-Type"
        )
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  http.url == endpoint,
                  (200 ... 299).contains(http.statusCode),
                  data.count <= maximumResponseBytes,
                  http.value(forHTTPHeaderField: "Cache-Control")?
                      .lowercased().contains("no-store") == true
            else { throw PlatformFailure.productionEnvelopeUnavailable }
            return data
        } catch let error as PlatformFailure {
            throw error
        } catch {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
    }

    private func encode(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw PlatformFailure.invalidConfiguration
        }
        return try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func bytes(_ value: StrictJSONObject.Value?, count: Int) -> Data? {
        guard let result = variableBytes(value, maximum: count),
              result.count == count
        else { return nil }
        return result
    }

    private func variableBytes(
        _ value: StrictJSONObject.Value?,
        maximum: Int
    ) -> Data? {
        guard let text = text(value, maximum: ((maximum + 2) / 3) * 4),
              !text.contains("="),
              text.unicodeScalars.allSatisfy({
                  $0.isASCII && (
                      CharacterSet.alphanumerics.contains($0)
                          || $0 == "-" || $0 == "_"
                  )
              })
        else { return nil }
        var padded = text.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        guard let result = Data(base64Encoded: padded), !result.isEmpty,
              result.count <= maximum,
              base64URL(result) == text
        else { return nil }
        return result
    }

    private func text(
        _ value: StrictJSONObject.Value?,
        maximum: Int
    ) -> String? {
        guard case let .string(text)? = value,
              !text.isEmpty, text.utf8.count <= maximum,
              !text.unicodeScalars.contains(
                  where: CharacterSet.controlCharacters.contains
              )
        else { return nil }
        return text
    }

    private func optionalText(
        _ value: StrictJSONObject.Value?,
        maximum: Int
    ) -> String?? {
        if case .null? = value { return .some(nil) }
        guard let text = text(value, maximum: maximum) else { return nil }
        return .some(text)
    }

    private func number(_ value: StrictJSONObject.Value?) -> UInt64? {
        guard case let .number(lexeme)? = value,
              !lexeme.isEmpty,
              lexeme.utf8.allSatisfy({ (48 ... 57).contains($0) }),
              lexeme == "0" || lexeme.first != "0"
        else { return nil }
        return UInt64(lexeme)
    }

    private func canonicalSubject(_ value: String) -> UInt64? {
        guard value.utf8.allSatisfy({ (48 ... 57).contains($0) }),
              value.first != "0", value.utf8.count <= 20,
              value.utf8.count < 20 || value <= "18446744073709551615"
        else { return nil }
        return UInt64(value)
    }

    private func validUserCode(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return bytes.count == 9 && bytes[4] == 45
            && bytes.enumerated().allSatisfy {
                $0.offset == 4 || (48 ... 57).contains($0.element)
                    || (65 ... 90).contains($0.element)
            }
    }
}
