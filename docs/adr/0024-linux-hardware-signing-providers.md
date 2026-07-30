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
