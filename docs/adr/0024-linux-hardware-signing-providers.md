# ADR 0024: Provider-neutral Linux hardware signing

- Status: Proposed
- Date: 2026-07-29
- Project-owner direction: approved 2026-07-29
- Decision owners: Pistis protocol, Linux operations, and cryptography
- Security review: required before implementation
- Related issue: [#320](https://github.com/sagrudd/pistis/issues/320)
- Implementation: prohibited until specialist review accepts this ADR

## Context

ADR 0017 requires production installation signing through a narrow
non-exporting `InstallationSigner` and forbids a portable software fallback.
The current Linux authority candidate has TPM 2.0 hardware, but the production
estate also contains older Dell servers and virtual machines. TPM or
trustworthy vTPM availability cannot be assumed across that estate.

The authentication authority and its relying products are separate trust
boundaries. A Jenkins worker, DASObjectStore host, or other product node does
not need an installation private key merely because it consumes a
Pistis-authenticated Monas context. Requiring signing hardware on every worker
would enlarge the secret-bearing surface and make otherwise valid deployments
impossible.

Production needs a stable provider contract, an explicit deployment choice,
and hardware-specific qualification. It must not obtain portability by
silently substituting an ordinary file key when hardware is absent.

## Decision

### Provider boundary

Linux implements one provider-neutral `InstallationSigner` boundary. A
production authority selects exactly one configured, reviewed provider before
it begins listening. Selection is static for the process lifetime. Missing,
partial, ambiguous, unavailable, or incompatible configuration fails startup.

The boundary accepts the exact COSE `Sig_structure` bytes defined by ADR 0018
and returns only:

- the enrolled 32-byte Pistis key identifier; and
- one fixed-width, low-S, 64-byte ES256 signature.

It has no private-key import, export, recovery, enumeration, or arbitrary
cryptographic-operation API. The adapter verifies every returned signature
against the enrolled canonical public key before returning it. Provider
readiness is diagnostic and cannot grant access or select another provider.

An implementation, configuration file, feature combination, or runtime error
must never cause automatic provider fallback. A software signer may exist only
inside explicitly test-only construction and cannot satisfy production,
packaging, deployment, or physical-host evidence.

### Signing purpose and authority separation

This provider key is a machine-held installation-signing key. It is distinct
from the human Pistis signer on the physical iPhone, App Attest or Secure
Enclave keys, Site Root or certificate-issuer keys, package-release signing
keys, and Thesaurophylax custody keys. It must never be reused as any of those
keys or represented as proof of human presence, user approval, Site Trust, or
certificate issuance.

The signer is a cryptographic primitive called by Monas inside the Prosopikon
host-authority boundary. The Prosopikon `HostCompletionPort` described by ADR
0017 is the sole owner of authorization decisions, session issuance, key
generation and revocation state, one-use consumption, and audit commits. Monas
may transport the exact request and result but cannot create sessions, select
or restore a key generation, or grant installation or trust changes. A request
may reach the signer only after the `HostCompletionPort` has validated an
allowed installation-signing purpose and its complete bindings. Callers must
not be able to submit arbitrary bytes from a CLI, browser, worker, or network
interface. Before consuming the signed result, the same Prosopikon transaction
rechecks the exact purpose, audience, target, key generation, expiry,
revocation state, and one-use binding. The production conformance suite must
prove that invalid or unapproved purposes cannot reach the provider and that a
signature alone cannot create authority.

### Key identity lifecycle and rollback

The enrolled public key, key identifier, provider type, exact provider object
locator, and monotonically increasing authority generation form one identity
record. Every signing request is bound to the current generation. The
generation and revocation authority remain exclusively with the durable
Prosopikon `HostCompletionPort` transaction described by ADR 0017; Monas
readiness and local provider state cannot select or restore an identity.

Provider key creation and authority enrollment are separate staged operations.
A newly created key is unusable until its exact public identity is committed
as current by the host authority. A crash before that commit leaves no signing
authority; recovery may resume only the exact staged provider object and
matching public identity. It must not discover or silently choose another key.
The Prosopikon `HostCompletionPort` transition to a successor generation
atomically makes the successor current, revokes the predecessor, invalidates
sessions and pending work bound to the predecessor, and records the redacted
audit event. A crash must recover either the previous committed generation or
the successor committed generation, never a mixed state.

Restoring an older database or configuration must not make a revoked
generation current again. The implementation must select and qualify an
anti-rollback source for the committed generation; a restorable local database
copy alone does not establish that property. Until that source and the
crash/recovery transition are defined, key rotation and production recovery
remain blocked.

### Provider order

The first production provider is **TPM2**. It is used when the authority host
has a physical TPM 2.0 or a separately qualified vTPM capable of creating and
using a non-exportable P-256 key.

The second production provider is **PKCS#11**. It supports a reviewed local,
USB, passed-through, network, or VM-accessible HSM/token whose module,
mechanism, slot/token identity, and key identity are explicitly pinned.

This order is an implementation priority, not an automatic preference chain.
A deployment names one provider. If that provider fails, the authority fails
closed; it does not attempt the other provider.

### Initial candidate scope proposal

The first implementation candidate is proposed to be one physical TPM 2.0 on
the NUC running Ubuntu 26.04 x86_64. This is a bounded qualification target,
not a supported-host declaration, package coordinate, release, or permission
to activate the authority. Before implementation, read-only inventory must
confirm that the selected device is a physical TPM 2.0 rather than a vTPM and
record the exact model, firmware, host, kernel, TPM stack and interface. The
candidate remains blocked until that inventory and the hardware-specific
qualification plan are reviewed.

Acceptance of this ADR would authorize no vTPM, PKCS#11 device, network HSM,
other host, package format, or production deployment. Each requires a separate
owner-selected candidate and its own provider, transport, hardware and
host-qualification review. In particular, a PKCS#11 module must not be loaded
into the authority process or treated as trusted solely because its digest or
token identity is pinned; module isolation and its residual process-compromise
risk require a separate accepted design.

### Deployment topology

Only the Monas/Prosopikon authentication-authority boundary holds or invokes
the installation signing key. Ordinary Jenkins agents, DASObjectStore nodes,
and relying-product workers remain keyless.

A nominally standalone installation may use:

1. a local physical TPM2;
2. a qualified vTPM whose snapshot, migration, cloning, rollback, and
   hypervisor trust behaviour has been accepted;
3. a local or passed-through PKCS#11 device; or
4. an explicitly configured network PKCS#11 HSM.

The fourth topology remains standalone at the product layer but has an
operational dependency on the HSM. Its availability, TLS/network trust,
credential delivery, and recovery evidence must say so. A host with none of
these reviewed choices cannot run the production authority, though it may
remain a keyless relying product or build worker.

### Provisioning and identity

Provisioning is a distinct, idempotent operator ceremony. It creates a
non-exportable P-256 key inside the configured provider, exports only the
canonical public key and derived Pistis key identifier, and records the
provider type plus non-secret locator required to reopen that exact key.

Provisioning must not silently replace a key. An existing locator whose public
key differs from the enrolled identity is a hard failure. Authorisation
values, PINs, sessions, private objects, sealed contexts containing sensitive
authorisation material, and provider credentials never appear in arguments,
environment variables, repository files, logs, browser responses, or Jenkins
evidence.

Provider authorisation is delivered through a reviewed service credential or
hardware policy. Device-node, group, systemd, and module access is limited to
the dedicated authority service. Provider libraries and packages are pinned
and included in supply-chain evidence.

### Recovery, rotation, and virtual machines

Pistis does not back up or migrate the private key. Recovery from device loss,
TPM clear, token replacement, unrecoverable lockout, or untrusted VM cloning
is revoke, invalidate affected sessions, provision a new key, and re-enrol the
new public identity.

A vTPM is not accepted merely because the guest exposes `/dev/tpmrm0`.
Qualification must cover snapshot and clone behaviour, rollback resistance,
migration authorisation, host-administrator trust, and whether two guests can
operate the same effective key. Unresolved duplication or rollback risk
disqualifies that vTPM for production authority.

PKCS#11 qualification pins the module digest, supported ES256 mechanism,
token/slot identity, key label or identifier, public key, session limits, and
reconnect semantics. A changed module, token, or key never becomes trusted
through discovery alone.

### Evidence and conformance

All providers pass the same provider-neutral conformance suite:

- exact-byte signing and one-byte mutation rejection;
- key-identifier and public-key binding;
- fixed-width and low-S signature enforcement;
- absent, wrong, replaced, locked, timed-out, malformed, and unavailable
  provider failures;
- concurrency, resource exhaustion, restart, and recovery;
- redacted error, log, metric, and audit behaviour; and
- proof that no fallback provider is invoked.

TPM2 and PKCS#11 add hardware-specific negative tests. Jenkins retains exact
source, dependency, package, module, host, configuration-shape, and public-key
evidence. It never receives a production private key or authorisation value.
A hardware-gated native lane is required; portable unit tests alone do not
qualify a provider.

## Consequences

- One Monas authority can serve keyless Jenkins and DASObjectStore workers.
- TPM2 gives the current physical Linux candidate the shortest compliant path.
- PKCS#11 supports older servers and VMs without weakening the non-export
  boundary.
- Deployment becomes explicit: a host without an accepted provider cannot run
  production signing.
- Private-key backup is replaced by public-identity backup, revocation, and
  re-enrolment procedures.
- Two providers increase packaging and qualification work, but do not create
  two signing semantics.
- Provider outages deny new ceremonies instead of changing the trust root.

## Security and privacy

The main threats are provider substitution, software fallback, key
duplication, VM rollback or cloning, overly broad device access, malicious
PKCS#11 modules, authorisation-value disclosure, signature malleability, and
availability attacks. Static provider selection, enrolled public-key binding,
post-signature verification, low-S enforcement, pinned modules, least
privilege, bounded sessions, fail-closed readiness, and hardware-specific
evidence address those threats.

Public keys, key identifiers, provider type, coarse readiness, and non-secret
hardware identity may be retained. Private keys, PINs, authorisation values,
provider sessions, and sensitive sealed material are never evidence.

## Alternatives considered

- Require TPM2 on every host: rejected because older servers and many VMs do
  not provide a trustworthy TPM, and relying workers do not need signing keys.
- Use an ordinary encrypted file when hardware is absent: rejected because it
  violates ADR 0017 and turns availability failure into a trust downgrade.
- Use the Linux kernel keyring or desktop Secret Service as the production
  private-key store: rejected for this decision because neither alone proves
  hardware non-exportability or the required VM/host isolation.
- Automatically try TPM2 and then PKCS#11: rejected because failure-driven
  provider selection makes the active trust boundary ambiguous.
- Put signing keys on Jenkins workers: rejected because builds are relying
  computations, not authentication authorities.
- Back up provider private keys: rejected because exportability would weaken
  the provider contract; recovery uses revocation and re-enrolment.
