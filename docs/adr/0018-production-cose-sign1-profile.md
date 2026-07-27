# ADR 0018: Production COSE Sign1 profile

- Status: Accepted
- Date: 2026-07-27
- Decision owners: Pistis protocol, cryptography, and iOS maintainers
- Security review: required for any change to this profile

## Context

ADR 0001 selected deterministic CBOR and reserved COSE for interoperable
signatures. ADR 0002 selected ES256 and the canonical P-256 key and signature
forms. ADR 0006 deliberately used a detached reference envelope because the
exact production COSE structure had not been accepted.

COSE permits several representations and extension points. Accepting all of
them would create algorithm, header, detached-payload, and encoding ambiguity
between Rust and Apple's Security framework. Pistis needs one byte-exact
profile before shared Rust/iOS fixtures can be authoritative.

## Decision

### Wire representation

A production signed message is exactly one **untagged** `COSE_Sign1` array:

```text
[
  protected : bstr,
  unprotected : {},
  payload : bstr,
  signature : bstr
]
```

The array and its nested values use the deterministic CBOR rules in ADR 0001.
The semantic tag `18` is forbidden. A tagged `COSE_Sign1`, including a
byte-for-byte equivalent tagged form, is a different representation and must
be rejected. This exception does not weaken the general ADR 0001 prohibition
on CBOR tags: tags remain forbidden everywhere in the Pistis wire profile.

`protected` is the exact deterministic-CBOR encoding of:

```text
{
  1: -7,       / alg: ES256 /
  4: key_id    / kid: 32-byte Pistis KeyId /
}
```

Both fields are mandatory and no other protected header is accepted in v1.
The unprotected map must be empty. Header labels must not be duplicated across
the protected and unprotected maps.

`payload` is present and contains one complete closed Pistis canonical payload.
Detached payloads and `null` payloads are forbidden. The payload must not be
decoded and re-encoded before signature verification.

`signature` is exactly 64 bytes: the unsigned, fixed-width, big-endian
`r || s` form defined by ADR 0002. DER, variable-width, zero, out-of-range, and
high-S signatures are rejected.

### Signature input

The signature input is the deterministic CBOR encoding of the COSE
`Sig_structure`:

```text
[
  "Signature1",
  protected,
  h'',
  payload
]
```

External additional authenticated data is always the empty byte string.
Applications must bind audience, installation, purpose, version, and every
other security-relevant value inside the closed signed payload; transport
metadata is never external AAD.

Verification is fail closed in this order:

1. enforce the total input bound and decode one untagged four-element array;
2. require the exact protected and empty unprotected maps;
3. reject an unsupported algorithm before resolving a key;
4. require `kid` to equal the key identifier derived under ADR 0002;
5. validate the closed canonical payload and its purpose before use; and
6. verify the low-S ES256 signature over the exact `Sig_structure` bytes.

No algorithm inference, critical-header extension, countersignature,
certificate-chain header, compression, encryption, indefinite-length value,
or alternate signature encoding is supported in v1. A future extension needs
a new accepted ADR and protocol version; it must not be silently ignored.

### Platform boundary

Apple Security produces DER-encoded ECDSA signatures and X9.63 public keys.
The iOS adapter must strictly convert DER to the 64-byte low-S form and X9.63
to the compressed SEC1 form before applying this profile. Conversion failure,
Secure Enclave unavailability, changed biometric enrollment, cancellation, or
authentication fallback fails closed.

The portable Rust and Swift implementations must consume the same positive
and negative byte fixtures. Unit or simulator tests prove encoding behavior,
not Secure Enclave or Face ID behavior. Production interoperability remains
blocked until a physical Face ID device produces a signature which the Rust
verifier accepts, and the exact-revision Jenkins dossier retains that result.

## Consequences

- Production QR and local transports carry one self-contained signed byte
  string rather than the EPIC-6 detached reference pair.
- There is one canonical representation: tagged and detached alternatives are
  rejected even when their cryptographic content is otherwise equivalent.
- Protected algorithm and key identity cannot be changed without invalidating
  the signature.
- A generic COSE library may be used only behind a strict profile adapter.
- Existing detached reference fixtures remain reference-only and must not be
  relabeled as production COSE evidence.

## Alternatives considered

- Require CBOR tag 18: rejected because Pistis canonical input rejects tags and
  accepting tagged and untagged forms would create two encodings.
- Permit protected or unprotected extensions: rejected because ignored header
  semantics create downgrade and cross-implementation risk.
- Use detached payloads: rejected because transport binding and fixture
  handling become more error-prone without an MVP benefit.
- Accept DER signatures directly: rejected because COSE defines fixed-width
  `r || s` and Rust already enforces that form.
