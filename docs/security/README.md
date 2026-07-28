# Security documentation

Threat models, trust boundaries, cryptographic review records, privacy reviews,
and penetration-test scopes belong here. Vulnerabilities must be reported using
`SECURITY.md`, not committed here before coordinated disclosure.

## External enrolment trust boundary

GitHub OAuth and Google OpenID Connect are online only during external-identity
enrolment and explicit reauthentication. They do not participate in routine
local authentication. A provider response creates no trust until callback
correlation, provider-specific identity validation, device-key binding, and
durable commit all succeed.

Google enrolment additionally depends on authenticated discovery and rotating
public signing keys. Discovery starts at a fixed Google URI; issuer, endpoint,
algorithm, signature, audience, authorized presenter, time, and nonce checks
fail closed. Cached public metadata may improve availability but must not
extend token validity or permit an unknown key indefinitely.

Authorization codes, bearer and ID tokens, PKCE verifiers, state, nonce, and
complete provider responses cross the transient-enrolment boundary only. They
must be redacted, cleared on every terminal path, and excluded from persistent
evidence. Provider email, login, and hosted-domain values are mutable metadata,
not identity keys.

ADR 0023 is the **Accepted** v0.1 GitHub App device-flow profile. It supersedes
only the GitHub transport portions of ADRs 0003, 0007 and 0008.
Its device code, user code, access/refresh token, browser and `/user` response
remain transient capabilities; its browser-suspended state does no polling;
and it requires explicit confirmation, platform-key proof and an atomic
Prosopikon invitation/principal/device receipt. Persistent throttles and
redacted audit mitigate but do not eliminate phishing/session-misbinding risk.
Implementation and production enablement remain gated by ADR 0023's reviewed
configuration, physical-device, canary, attack-exercise, and attestation
evidence.

## Device-registry persistence boundary

The local device registry is security-sensitive authorization state. It stores
canonical public verification keys, derived key identifiers, assurance claims,
opaque external-identity references, and immutable lifecycle history. It has no
field or supported path for a private key. Private device keys remain on the
device and must not appear in registry files, backups, logs, or diagnostics.

Registry errors fail closed. An unavailable or corrupt database, invalid
public-key material, unknown assurance or lifecycle values, unsupported schema
version, migration inconsistency, lock failure, or stale concurrent transition
must not be interpreted as an empty registry or active device.

Suspension blocks current use and can be reversed only by an explicit,
auditable resume transition. Revocation is terminal and blocks new
authentication and approval while retaining the record needed to interpret
historic evidence. Whole-record replacement, deletion, or direct SQL must not
be used to bypass these transitions.

External identity bindings remain in a separate store. Enrolment must resolve
the binding before inserting the device and must surface cross-store failure;
an unresolved reference never establishes trust. Operational backup and
forward-only migration procedures are documented in
[Device registry operations](../operations/device-registry.md).

## QR authentication boundary

Browsers, cameras, QR displays, copied transfer text, endpoint hints, and local
networks are untrusted transports. A QR checksum detects accidental corruption
only. It cannot establish installation or device authenticity, and an attacker
who replaces a frame can recompute it. Authority comes only from verification
of the exact signed canonical payload and its locally stored challenge,
identity, device, key, lifecycle, purpose, audience, and expiry bindings.

Challenge and response frames have distinct closed kinds and schemas.
Decoders reject unsupported versions, unknown fields, non-canonical data,
invalid checksums, padding, trailing data, fragmentation, and oversized input.
Endpoint hints never override local HTTPS or endpoint policy. Local-network
failure does not weaken verification or silently switch to a bearer mechanism;
the response-QR path remains the offline fallback.

Polling is capability-bound and redacted. It returns no nonce, signed response,
signature, session identifier, capability, audit record, or complete challenge
identifier, and polling alone never mutates authentication state. Logs likewise
exclude transfer bodies, capabilities, nonces, signatures, private keys,
provider credentials, and complete challenge identifiers.

Completion verifies before mutation. Challenge consumption,
pre-authentication session invalidation, authenticated-session rotation, audit
record creation, and terminal completion share one atomic boundary. Denials do
not create sessions; injected failure leaves the challenge unconsumed; and
concurrent or replayed completions cannot establish a second session.

The EPIC-6 implementation demonstrates these rules in memory. It is not a
durable production security boundary. Production HTTP must additionally
provide TLS, request and content-type bounds, no-store responses, CSRF and
cookie protections, rate limiting, durable transactions, and operational
monitoring. Production COSE parsing and mobile interoperability also remain
deferred.

## Exact-action execution boundary

Session authentication and action approval are separate authorities. A version
1 `authenticate-session` response cannot authorize a command. Exact action
approval uses the distinct version 2 purposes and closed descriptor in ADR
0016; version or purpose substitution fails before policy evaluation.

The descriptor binds executable path and content digest, argument boundaries,
working directory, an explicit non-secret environment allow-list, and typed
resources. It does not bind a shell string. Secrets must never be placed in the
descriptor because signed challenge content is displayed and retained as
evidence.

An approval is single-use and expires. The local agent consumes it before
revalidating mutable host state, then invokes the resolved executable directly.
Executable replacement, path substitution, argument joining or reordering,
working-directory changes, extra inherited environment, resource substitution,
expiry, denial, and replay fail closed. If a platform cannot establish stable
identity for a requested executable or resource, that action cannot use the
exact-action path.

The portable execution traits are a testable trust boundary, not an operating
system sandbox. Production adapters require platform review for file
descriptors, symlinks, mounts, interpreter scripts, dynamic libraries, process
credentials, signals, resource limits, and audit durability.

## Local-agent boundary

The per-user agent, not the CLI, owns durable challenge state and installation
signing. Its database and Unix socket require owner-only, non-symlinked paths.
Canonical socket messages are length bounded before dispatch. Restart never
changes a consumed or otherwise terminal challenge back to pending.

The installation signer exposes signing only. Private-key export is absent from
the interface, and provider failures do not select a software fallback. The
macOS provider calls Security-framework signing on exactly one labelled key,
normalises and independently verifies its ES256 output, and requests only the
public representation. Until Keychain provisioning and peer-credential checks
pass platform review, the CLI must report the agent as unavailable.
