# Phone-held Site Root issuer operation

This source implements the owner's adopted ADR 0045 R2 phone wire, canonical
IADM/IRCS envelopes and bounded operation. It uses the existing
`site-root-delegation-v1` Secure Enclave key, with a coarse noninteractive
existence check followed by exact public-key comparison and message signing
through the same freshly evaluated Face ID context. It creates no key, invokes
no authentication-key fallback and introduces no signature purpose.

The application adapter uses the existing configured Monas origin and
`MonasServerTrustPolicy`. It posts CBOR only to the two adopted fixed paths,
rejects redirects, cookies, compression, unexpected response types and oversized
streamed responses. Its monotonic deadline is passed unchanged through every
request; neither a response nor a retry renews it.

The private handoff must contain the independently admitted Site key, current
session/device/permission and exact mode-specific originals. The current source
has no genuine producer for that handoff: `IssuerSiteRootPreparedHandoff.current`
fails closed. A pinned connection, readiness response, redacted installation
history, confirmation button or optional genesis binding record cannot construct
it. The confirmation view therefore has no production mounting path yet.
The server owner must supply its actual authenticated prepared-owner evidence
contract and producer before this flow can become operational.

Once that genuine handoff exists, the concrete confirmation method performs the
single immediate operation. The complete summary is presented before a separate
confirmation. Preparation and Face ID share the original thirty-second bound;
arm must follow the successful LocalAuthentication reply callback within 250
milliseconds, including continuation scheduling and public-key lookup. The earlier phone
native bound is two seconds from arm. The server's independently established
original two-second bound still applies and is never changed by the phone.

Before any key invocation, the adapter atomically adds a this-device-only
Keychain fence for the ceremony and exact task ordinal/digest. Duplicate,
ambiguous or failed invocations cannot be retried through a new context. The
same local context permits exactly one IADM signature or the two IRCS PRE/POST
signatures; POST must bind the complete PRE envelope reference, unchanged current
facts and boot, a distinct nonce and increasing serial. The server independently
owns proof of the actual protected read and the distinct PRE IRSP linkage.
The concrete issuer signing boundary rechecks the unchanged native deadline and
cancellation after synchronous existing-key lookup, immediately before the
SecKey invocation, and again after completion. A slow lookup cannot start a late
signature; a late completion remains uncertain.
Cancellation, backgrounding, expiry and uncertainty invalidate the live context
and leave durable fences. No private key or authentication context is persisted.

The new Swift tests cover canonical bounds, mode/phase restrictions, exact
software-fixture signatures, immutable clocks and mocked HTTP boundaries.
These tests have not been run in this source lane. They provide no live Face ID,
Secure Enclave, TLS, durable crash, current-owner or receiving-factory positive.
The genuine handoff producer, its current authentication transport, actual
server endpoints and private pre-handler integration remain required.

## Private native AuthenticateSession ingress

The compatible native HTTP profile `issuer-site-root-native-v1` obtains the
phone's own existing AuthenticateSession capability. It adds no signing purpose
and changes none of the adopted R2 CBOR arrays. The source entry is
`IssuerSiteRootTransport.authenticatedNative()`, whose private session factory
reads the actual active `InstallationTrustKeychain` enrolment. It accepts no
caller-selected session, raw credential, desktop cookie or response DTO owner.

The fixed enrolled HTTPS origin and exact signed enrolment SPKI are used through
the existing pinned delegate, with no discovery, redirect, cookie store, cache,
alternate origin or retry. Native begin posts the existing principal ID at
`/auth/pistis/v2/begin`, with `Pistis-Session-Profile` and exact retained native
installation/device/key-ID headers. The key ID is the existing derived Pistis
32-byte identifier encoded as bare lowercase hexadecimal. The server returns
the existing begin secret once, its opaque reference, full signed challenge,
PISTIS1 transfer and expiry. Duplicate/unknown fields and noncanonical encodings
deny; the full signed challenge must equal the transfer's original bytes.

The existing `ProductionChallengeVerifier` authenticates the challenge against
the retained installation, identity, product audience and exact submit endpoint
before any device signature. A fresh Face ID context and the existing enrolled
authentication key in the installation namespace produce the unchanged COSE
AuthenticateSession response. The actual key's derived ID must match retained
enrolment. This key is separate from the Site Root key. Backgrounding,
cancellation, changed enrolment and expiry fence the attempt; the concrete
existing-key invocation rechecks the original deadline after Keychain lookup.
The authentication flow has a conservative 30-second outer cap, additionally
bounded by actual challenge, begin and enrolment expiry. It does not renew the
separate issuer ceremony's original two-second bound.

The phone submits once to `/auth/pistis/v2/submit?challenge_id=...`; only completed
status advances. It then finalises once at `/auth/pistis/v2/finalize` with its own
reference and same owned begin secret under the native profile. The response
contains only actual session/identity/binding/counter/completion/challenge/expiry
metadata, with no credential or Set-Cookie. Every identity must join the exact
retained target and signed challenge; counters cannot regress below the retained
enrolment. The server independently verifies current Core binding and App Attest
state and consumes its native preauthentication once, including across restart.
Pending status, ambiguous delivery, failed finalise and replay cannot recover a
credential or trigger an automatic retry.

Only this complete awaited flow constructs `IssuerNativeCurrentSession`. It
keeps the capability in memory without Codable, Keychain persistence or a raw
token constructor. The R2 transport attaches
`Authorization: Pistis <sessionUUID>.<base64urlOwnedBeginSecret>` solely to the
fixed issuer readiness/exchange origin and paths, after rereading the same active
enrolment and checking actual expiry. A failed R2 request terminally clears the
local capability. This authentication owner alone does not construct
`IssuerSiteRootPreparedHandoff`; independently admitted full owner evidence
remains mandatory and its existing absent-producer gate stays closed.

New codec and request tests are source-only and unrun at this checkpoint. Their
synthetic carriage/metadata fixtures create no authenticated session owner, live
key, biometric approval or issuer capability. The existing 0.27.0+74 campaign
coordinate remains unchanged; native qualification and publication belong to the
sole campaign integrator.
