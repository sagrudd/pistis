# ADR 0021: Production QR envelope and installation trust

- Status: Proposed
- Date: 2026-07-28
- Decision owners: Pistis protocol, cryptography, iOS, CLI, and Prosopikon maintainers
- Security review: required before implementation
- Tracking issue: [#300](https://github.com/sagrudd/pistis/issues/300)

## Context

ADR 0006 and `pistis-qr` define the reference `PISTIS1` frame as a canonical
CBOR map containing a payload and a detached 64-byte signature. ADR 0018 later
accepted a production message as one self-contained untagged COSE Sign1 value
and says production QR carries that complete signed byte string. Treating the
old detached frame as production would create two signature representations.

The iOS app can acquire bounded `PISTIS1` text, but it cannot safely present the
content as a request. Its remembered installation currently has a fingerprint,
not the installation verification key and authority chain needed to verify the
challenge's COSE signature and key identifier.

## Proposed decision

### Production transport

Retain the ASCII `PISTIS1:` prefix, base64url-without-padding body, lowercase
16-hex-character scanning checksum, 2,331-byte text bound, and version-40/M QR
limit. The checksum remains corruption detection and grants no authority.

Replace the reference frame body for production with deterministic CBOR:

```text
{
  0: 2,                 / transport version /
  1: 1 or 2,            / challenge or response /
  2: bstr .cbor cose    / exact complete untagged COSE Sign1 bytes /
}
```

Version 2 is intentionally distinct from the detached version 1 frame. The
COSE byte string must decode under ADR 0018, and its embedded payload must
decode under the purpose-specific ADR 0019 schema. Kind and signed purpose must
agree. Unknown, missing, duplicate, reordered, or mis-typed frame fields,
padding, non-ASCII text, checksum mismatch, trailing bytes, tags, oversized
values, and kind confusion fail closed before presentation.

The production decoder returns exact envelope and payload bytes. It does not
re-encode either before signature or digest verification.

### Installation verification-key binding

Device enrolment must install a host-signed, audience-bound installation trust
record containing:

- installation identifier, display name, audience, and canonical fingerprint;
- installation signing key identifier, compressed SEC1 P-256 public key, and
  ES256 algorithm;
- Prosopikon authority key identifier and the authority-signed enrolment
  receipt or digest that binds the record;
- policy and revocation generations; and
- issued, expiry or rotation, and last-confirmed timestamps.

The authority key is bootstrapped only through the single-use enrolment
invitation accepted by ADR 0019 and the Prosopikon transaction in ADR 0020.
Camera content, endpoint hints, DNS, TLS, Bonjour, display text, a bare
fingerprint, or a previously unseen QR key cannot create or replace trust.

Before showing Approve or Deny, iOS must:

1. parse the bounded version-2 frame and strict COSE profile;
2. select an existing active installation record by signed installation ID;
3. require COSE `kid` and the signed `installation_key_id` to match that
   record;
4. verify ES256 over the exact COSE Sig_structure;
5. validate the complete authentication-challenge schema, purpose, audience,
   expiry, identity binding, fingerprint, and display-context digest; and
6. render security-relevant values from the verified signed payload only.

Missing, expired, rotated, revoked, or generation-stale trust requires a new
enrolment or authenticated refresh. It must never offer “trust this QR”.

### Response and delivery

After an explicit decision, the device constructs the ADR 0019 response,
requires fresh Face ID for any approving signature, and emits one ADR 0018 COSE
envelope. HTTPS direct delivery and response QR transport the identical bytes
through the same server verifier. Endpoint hints are considered only after
challenge verification and must satisfy the accepted HTTPS allow-list policy.
Delivery, server verification, and host-session creation remain separate
states in the UI and history.

Denial semantics require specialist review before implementation: the accepted
schema permits a signed `denied` response, while the existing iOS reference UX
states that denial produces no device signature. Review must select one rule
and reconcile ADR 0019 and the UI contract.

## Required conformance evidence

- shared Rust/Swift positive version-2 challenge and response fixtures;
- negative fixtures for every structural, COSE, schema, key, trust, audience,
  expiry, digest, endpoint, and replay failure;
- substitution tests proving display and signed values cannot diverge;
- simulator acquisition and parser tests without network access;
- physical iPhone scan, Face ID, direct-return, and response-QR evidence; and
- exact-revision Jenkins verification by the independent Rust verifier.

The test-only vectors under `fixtures/proposed-qr-v2` make the candidate outer
bytes executable in Rust and Swift while this ADR is Proposed. They wrap an
already accepted COSE response fixture and prove that a previously enrolled
installation key is needed for signature verification. They are review
material, not a product decoder or evidence of protocol acceptance.

## Consequences

- Version 1 remains reference-only and is rejected by production mobile paths.
- Scanner implementation can proceed independently, but approval presentation
  and signing remain disabled until this ADR is accepted and its trust record
  is delivered.
- Installation-key rotation and authority-key rollover need explicit lifecycle
  tests; silent trust replacement is impossible.

## Alternatives considered

- Put raw COSE bytes directly after `PISTIS1:`: rejected because explicit kind,
  version evolution, and deterministic kind-confusion rejection are useful.
- Reuse version 1 and replace its fields: rejected because identical versions
  with incompatible semantics enable downgrade and implementation confusion.
- Continue detached signatures: rejected by ADR 0018.
- Trust the key or fingerprint scanned from the QR: rejected because the
  attacker controls the transport.
