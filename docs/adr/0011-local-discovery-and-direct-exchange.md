# ADR 0011: Local discovery and direct exchange

- Status: Accepted
- Date: 2026-07-24
- Owners: Pistis protocol, transport, iOS, Android, Synoptikon, Monas, security,
  privacy, and operations

## Context

EPIC 11 adds local-network discovery and direct response submission as a
convenience layer. The network is hostile: an attacker can advertise the same
service, race or replay answers, return arbitrary addresses and ports, block
multicast, operate a local certificate authority, redirect HTTP requests, and
observe broadcast metadata.

The existing EPIC-6 reference flow already accepts direct-local and response-QR
inputs through one verification path. Its challenge contains up to two HTTPS
endpoint hints, an installation fingerprint, and an installation signature,
but ADR 0006 explicitly says that its detached signature envelope is not the
production mobile format. Endpoint hints are metadata rather than authority.
The accepted production COSE profile, mobile conformance fixtures, durable
challenge storage, and host completion transactions are still outstanding.

iOS and Android source foundations exist, but neither currently declares the
local-network discovery permissions or service declarations. Browsers cannot
browse arbitrary mDNS services, so a browser-only design is not viable.

## Decision

### Security and dependency boundary

Discovery is never authentication, authorization, installation trust, or proof
of proximity. It returns untrusted endpoint candidates only. The exact signed
challenge, enrolled device response, authoritative stored bindings, revocation
policy, and atomic host completion remain unchanged whether transport is direct
or QR.

`pistis-discovery` is a framework-neutral transport contract. It depends on
inward Pistis domain and protocol types but not on Axum, Yew, Network.framework,
Android NSD, a specific mDNS crate, Synoptikon, Monas, or database types.
Platform and host adapters own permissions, sockets, interfaces, lifecycle,
HTTP, and presentation. Protocol and verifier crates do not depend on
discovery.

The smallest independently deliverable slice is a deterministic discovery
model, candidate-validation policy, transfer-selection state machine, adapter
ports, and hostile-network tests. It must identify itself as a contract and
cannot claim local-network interoperability until native and host adapters pass
the acceptance matrix.

### Advertisement model

Only the installation advertises. A phone does not broadcast user, device, or
availability information. The installation publishes an ephemeral
`_pistis._tcp.local.` DNS-SD service only while at least one bounded ceremony
window is active.

The service instance name is fresh, random, non-semantic, and not reused as an
installation identifier. TXT data is closed, size-bounded, and limited to:

- discovery protocol version;
- an opaque, short-lived endpoint identifier; and
- explicitly negotiated transport capabilities that disclose no product,
  purpose, assurance, or user state.

The advertisement never contains a username, local-user identifier, external
identity, device or key identifier, installation identifier or persistent
fingerprint, challenge identifier or nonce, project or report name, session or
browser capability, URL, credential, or personal metadata. Hostnames,
addresses, ports, service timing, and traffic remain observable network
metadata and are documented as such.

Advertisements have a short TTL bounded by the ceremony window, are withdrawn
when no ceremony is eligible, and are re-registered after relevant interface
or sleep/wake changes. One process owns an advertisement instance. Cleanup,
duplicate-name handling, partial interface failure, and stale cache entries
have explicit outcomes.

### Authenticated endpoint binding

Discovery records and DNS answers never select the trusted endpoint by
themselves. Before a direct connection, the phone already has an exact,
installation-signed transport binding obtained from the scanned challenge or a
previously authenticated pairing. The binding covers:

- protocol version and installation identity;
- opaque endpoint identifier;
- expected service type;
- HTTPS port or permitted port constraint;
- installation-controlled TLS public-key digest;
- issue and expiry times; and
- the exact challenge or pairing context for which it is valid.

The production encoding of this binding is part of the accepted signed
protocol profile. It must not be introduced as an unsigned TXT extension or
ad-hoc JSON field.

A candidate is eligible only when its service type and endpoint identifier
match the signed binding, its binding is current, and its resolved address
belongs to the interface and IP scope that produced the answer. Candidate
selection is deterministic. Multiple matching answers do not weaken pinning
and an ambiguous or unsupported scope fails to QR.

The direct client establishes HTTPS while pinning the exact
installation-controlled public-key digest from the signed binding. It does not
trust the local CA environment, DNS name, TXT-supplied key, redirects, ambient
proxy configuration, cleartext upgrade, or alternate certificate. Certificate
or binding rotation requires a newly authenticated binding; silent trust-on-
first-use is prohibited.

### Direct exchange

Challenge retrieval and response submission use narrowly scoped, bounded
endpoints. The client disables redirects, compression surprises, cookies,
ambient credentials, and cross-origin authentication. It applies explicit
connect, read, total-operation, response-size, content-type, and concurrency
limits.

The phone compares the retrieved exact canonical challenge and installation
identity with the signed context it approved before key use. A retrieved
challenge cannot change the displayed user, installation, purpose, expiry, or
policy. The signed response remains fully bound to the authoritative challenge.

Direct and response-QR submissions enter the same host ingestion, verification,
replay, revocation, and completion path. A transport adapter cannot verify,
consume, poll a session into existence, or mint a host session. Safe idempotent
retry may resend the identical response; a different response conflicts.

No QR, discovery record, endpoint identifier, or retrieval capability is
sufficient to authenticate without the enrolled device signature. Challenge
confidentiality is not assumed merely because a short-lived locator is opaque.

### Transfer selection and fallback

The deterministic preference order is:

1. a previously authenticated, currently valid pairwise local endpoint;
2. a candidate matching the signed endpoint binding;
3. an HTTPS endpoint hint matching that same signed binding; and
4. response QR.

Each network attempt has a bounded deadline and cancellation path. Permission
denial, unavailable APIs, no result, multicast filtering, client isolation,
address-family mismatch, interface change, invalid pin, ambiguity, timeout, or
server unavailability produces a typed reason and advances to QR. Security
rejection of the signed challenge or response is terminal and must not be
relabelled as a transport fallback.

There is no indefinite searching, background scanning unrelated to an active
user ceremony, automatic cleartext downgrade, or weaker verifier mode.
Fallback changes transport only.

For the MVP, the user opens Pistis on the phone and explicitly enters the
nearby-requests surface. That foreground action starts one bounded browse for
previously authenticated installations and shows their pending requests only
after the pairwise installation binding and channel authenticate. The MVP does
not promise a notification while the application is closed or backgrounded.
Closed-app notification requires a later ADR and must not introduce a cloud
relay, public advertisement, or unbounded background discovery implicitly.

### Browser and host responsibilities

The Synoptikon or Monas backend advertises and receives the phone's direct
submission. The browser remains same-origin with its host and learns only
coarse ceremony state through the established polling, SSE, or WebSocket
boundary. It does not browse mDNS, connect to TXT-selected origins, receive a
mobile response, or hold the installation TLS pin.

Host adapters apply rate limits, request bounds, CSRF and origin policy where
applicable, pre-authentication binding, audit correlation, durable challenge
state, and the atomic completion rules of ADRs 0009 and 0010.

### Native platform adapters

The iOS adapter uses the supported native local-network browsing and connection
APIs, declares the local-network purpose and approved Bonjour service type,
and scopes browsing to an explicit foreground ceremony. Permission is
requested with explanatory UI before system presentation. Denial and
restriction are ordinary QR-fallback states. Native acceptance covers initial
grant, denial, settings changes, background/foreground, sleep/wake, IPv4,
IPv6, multiple interfaces, and certificate-pin failure.

The Android adapter uses the supported platform network-service discovery and
network-binding APIs. Its manifest declares only permissions required by the
supported SDK range; runtime permission and nearby-network changes are handled
explicitly rather than inferred from connectivity. Discovery is scoped to a
foreground ceremony and connections stay bound to the network that produced
the candidate. Native acceptance covers grant/denial where applicable,
Wi-Fi/cellular transitions, lifecycle recreation, IPv4, IPv6, multiple
networks, multicast filtering, and certificate-pin failure.

Platform adapters expose typed lifecycle events to the application core. They
do not pass raw DNS records, URLs, certificates, sockets, or permission objects
into protocol or presentation state.

### Evaluation and test gate

The mDNS implementation choice is accepted only after a time-boxed comparison
of maintained pure-Rust and operating-system-native options against:

- supported operating systems and address families;
- interface-change, sleep/wake, TTL, withdrawal, and duplicate-name behavior;
- bounded parsing and memory use;
- dependency, unsafe-code, advisory, license, maintenance, and provenance
  review;
- deterministic test injection without public network services; and
- packaging and service-manager behavior.

Selecting a crate is not itself completion of issue 137. The evaluation report,
dependency review, and negative prototype evidence are retained before the
implementation dependency is added.

The evaluation selects native Network.framework/Bonjour on iOS and
`NsdManager` on Android. The host Rust adapter may use pinned `mdns-sd` behind
the narrow discovery port: it is safe Rust, does not impose an async runtime,
supports publication, browsing, conflict handling, and daemon monitoring, and
is actively released. `simple-mdns` and `agnostic-mdns` remain rejected for the
MVP because they add no mobile permission/lifecycle advantage and would expand
the host runtime or integration surface.

The `mdns-sd` 0.20.2 API does not expose its per-service DNS cache TTL. The
host adapter therefore enforces the capped wire lifetime as a publication
deadline and unregisters with goodbye records. A crash may leave an opaque
cache entry for the library's RFC-default TTL, but neither that entry nor its
endpoint identifier conveys authority; the durable ceremony expiry and
authenticated endpoint binding fail closed. A future dependency change may
set the DNS TTL to the same bound only after compatibility and network
acceptance evidence.

The MVP wire projection is closed and minimal. It uses service type
`_pistis._tcp.local.`, a fresh 128-bit lowercase-hexadecimal instance name, and
exactly three ordered TXT entries: `v=1`, `id=<32 lowercase hexadecimal
characters>`, and `cap=https`. TTL is the remaining whole-second advertisement
lifetime capped at 30 seconds; an expired or subsecond record is not published.
No additional TXT key is accepted without an additive ADR revision and privacy
review.

Deterministic tests cover forged and conflicting advertisements, wrong service
type and endpoint identifier, TXT additions and oversize, stale TTL and
binding, address substitution, redirects, local-CA and certificate
substitution, response bounds, retry, cancellation, and QR fallback.
Integration tests use isolated local fixtures for IPv4, IPv6, multiple
interfaces where the runner permits them, multicast blocked, and client
isolation. iOS and Android native tests and at least one physical-device LAN
matrix are required for production interoperability claims.

## Consequences

- Local transfer remains a convenience layer with identical verifier and
  completion semantics to response QR.
- Advertisements reveal minimal ephemeral service metadata and no application
  identity.
- A malicious or conflicting mDNS service cannot become trusted without the
  installation-signed endpoint binding and TLS pin.
- Pure contract, policy, and state-machine work can proceed before selecting an
  mDNS implementation.
- EPIC 11 cannot close until EPIC 10, the accepted production signed-message
  profile, host adapters, native permission adapters, and the network
  acceptance matrix are delivered.

## Alternatives considered

- Have phones advertise availability: rejected because it broadcasts device
  presence and creates unnecessary privacy and targeting risk.
- Trust the first `_pistis._tcp.local.` answer: rejected because mDNS is
  unauthenticated and trivially spoofed.
- Put a URL or certificate pin only in TXT data: rejected because an attacker
  controls the advertisement.
- Trust the local CA or silently use HTTP: rejected because local network trust
  does not establish installation identity.
- Pin a certificate on first discovery: rejected because discovery cannot
  authenticate the first observation.
- Let the browser browse or connect directly: rejected because browser mDNS
  support and cross-origin policy cannot provide the required architecture.
- Treat permission denial or multicast blocking as authentication failure:
  rejected because QR is the universal equivalent transport.
- Start with a concrete mDNS crate in protocol code: rejected because platform
  lifecycle, supply-chain, and packaging evaluation must precede dependency
  selection.

## Review evidence

The architecture review inspected EPIC 11 issues 135–141, M9 acceptance
criteria, accepted ADRs, QR framing and authentication reference code, and the
current iOS and Android manifests. It found the shared direct/QR verification
path and signed HTTPS hints, but no accepted production endpoint-binding
encoding, mDNS adapter, native service permission declarations, or hostile-LAN
acceptance matrix.
