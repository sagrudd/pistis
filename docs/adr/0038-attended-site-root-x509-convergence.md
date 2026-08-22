# ADR 0038: attended Site Root X.509 convergence

- Status: Accepted for the owner-operated internal deployment
- Date: 2026-08-11
- Decision owners: Pistis, Monas, Proxenos and Thesaurophylax
- Issue: `PIS-X509-F1` (#448)
- Upstream authority decision: accepted Proxenos ADR 0012

## Context

The production local-network path must replace an exact bootstrap-leaf pin with
private-IP HTTPS rooted in the authenticated current Site root. The previous
operational failure mode repeatedly prompted Face ID, restarted first-device
enrolment, or exposed no continuation after a successful custody recovery.
None of those behaviours is an acceptable recovery mechanism.

Four authority boundaries participate. Pistis owns attended device approval;
Monas owns the pinned HTTPS presentation and relay; Thesaurophylax owns
purpose-separated key custody; Proxenos owns Site root generations, certificate
objects and the atomic convergence transaction.

## Decision

Pistis implements one ordered, fail-closed sequence:

1. A distinct Face ID ceremony signs the exact THBR receipt-key provision
   challenge with the existing Site Root device key.
2. One atomic Site X.509 first-provision challenge approves two fresh server-side
   P-256 role keys. The root and issuer have distinct role purposes, records and
   public bindings. No legacy plaintext key is imported. Before the resulting
   native leaf exists, the same fixed broker and signed-QR correlation carry
   three ordered opaque continuations: root rewrap, issuer rewrap and the
   combined initial-leaf approval. The original Face ID context may be reused
   only for this bounded sequence; every operation retains its distinct
   purpose, parser, key namespace and local acceptance boundary. No second QR,
   proxy, tunnel, temporary certificate or broker signing authority is added.
3. Pistis creates the distinct Secure Enclave namespace
   `site-root-convergence-ack-v2`. One freshly evaluated `LAContext` is shared
   only across its registration proof, using the existing Site Root key, and
   the exact PXRA/v2 acknowledgement signature. Proxenos allocates the positive
   acknowledgement generation; Pistis retains but never invents or resets it.

All COSE proofs are untagged detached ES256 Sign1 values with canonical
protected headers, an empty unprotected map, nil payload and fixed-width low-S
signature. THBR retains its existing Site Root profile. PXAK registration uses
`application/vnd.mnemosyne.pxak.v2`; PXRA uses
`application/vnd.mnemosyne.pxra.v2`; atomic X.509 provision uses
`application/vnd.mnemosyne.pxfp.v1`.

The QR may carry only exact canonical bytes and a submission URL equal to one
of the bounded build-pinned Monas origins and the fixed route. A portable
computer may publish more than one such origin (the shipped profile pins
`https://192.168.1.192:8443` and `https://192.168.0.193:8443`), but those
addresses share one Site Root identity and TLS policy; they are not separate
authorities. Redirects, cookies, unknown members, stale lifetimes, changed
Site/target/root/generation, reordered roles, duplicate transactions and
trailing bytes deny. There is no unlisted alternate origin, local password,
passcode, software signing key, re-enrolment or trust-on-first-use path.

## Atomicity and recovery

THBR provision is no-replace and an exact retry returns retained public
evidence. Site X.509 provision commits the fresh root and issuer records,
certificate objects, configuration, journal and approval claim as one server
transaction or none. PXAK registration is idempotent only for the identical
Site, target and acknowledgement public key; a changed binding requires a
separate governed rotation.

Interruption leaves the last consistent trust mode. A retry reuses server-held
transaction state and an existing purpose-specific device key; it does not
repeat enrolment or silently create another authority. A fresh QR is required
after expiry or denial.

## Secret and trust boundaries

Secure Enclave private keys never leave the device. X.509 private keys never
enter Pistis or Monas. QR, JSON, public keys, digests, certificate objects and
generation records are public binding material, not authority by themselves.
Pistis changes no operating-system trust store. Browser and CLI platform trust
remain the separately verified native installer responsibility.

## Consequences

The bootstrap build retains its one exact leaf pin only through PXFP. Before
the formal leaf becomes active, the PXFP root DER, fingerprint and generation
are compiled into a replacement signed build. That migrated build validates
normal TLS exclusively to that Site root and contains no bootstrap pin or dual
fallback. Ordinary Monas leaf renewal under the acknowledged Site root does
not require an app rebuild or device re-enrolment. Root replacement requires a
new governed transaction and replacement build. Physical-iPhone acceptance
must retain exact-revision evidence for one Face ID per bounded ceremony,
successful relaunch/recovery, and the final authenticated Monas session without
retaining QR or proof material.
