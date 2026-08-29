# ADR 0042: Purpose-separated Base Camp vault migration on iPhone

- Status: Accepted for the route-independent protocol core
- Date: 2026-08-29
- Decision owners: Programme owner, Pistis, Thesaurophylax, Monas, and
  Expedition maintainers
- Upstream authority: Thesaurophylax ADR-0012, accepted at exact revision
  `a548b43da2a1f07220d93d2a2546923105a2364c`
- Implementation issue: [#501](https://github.com/sagrudd/pistis/issues/501)
- Security review: specialist implementation review remains required before
  merge; Monas route and application presentation require a later coordinated
  decision

## Context

Thesaurophylax must migrate one existing Base Camp vault passphrase from its
fixed root-only source into the accepted portable iPhone custody format. The
passphrase is exactly 32 decoded secret bytes. It must never cross Monas,
HTTP, a QR, a browser, a shell, an environment variable, application state or
logs.

The existing Pistis generic custody rewrap and Site Root bundle receipt rewrap
use different purpose, generation and canonical-challenge domains. Merely
allowing another purpose or generation prefix in either implementation would
erase purpose separation and could authorise a foreign ciphertext or proof.

Thesaurophylax already projects the public and encrypted material through the
existing thirteen-field `THESMIP1` presentation carriage and consumes the
existing eight-field `THESMIR1` submission carriage. Their field counts do not
make the inner operation generic: the complete Base Camp canonical challenge
has nineteen fixed fields and a distinct wrapping context.

## Decision

Pistis implements one distinct Base Camp protocol type. It accepts only the
canonical challenge schema
`thesaurophylax.basecamp-vault-custody-provisioning.v1\0`, purpose
`basecamp-vault-passphrase-delivery-v1`, recipient
`mnemosyne-expedition-basecamp.service`, credential socket
`/run/mnemosyne-thesaurophylax/basecamp-vault-passphrase.sock`, and generation
prefix `basecamp-vault-`.

The validator parses exactly nineteen one-byte-tag, two-byte-big-endian-length
fields in order and permits no empty, duplicate, reordered, trailing or
unknown field. It verifies:

1. Site Trust Domain;
2. custody generation;
3. enrolled device key identifier;
4. enrolled compressed P-256 public key;
5. current revocation generation;
6. sixteen-byte non-zero transaction identifier;
7. non-zero vault digest;
8. non-zero legacy-source digest;
9. non-zero inventory digest;
10. SHA-256 of the staged ciphertext;
11. the Ed25519 public key derived from the staged 32-byte payload;
12. staged-host compressed P-256 public key;
13. fixed purpose;
14. fixed recipient;
15. fixed credential socket;
16. delegation serial;
17. issue time;
18. exclusive expiry; and
19. distinct completion-host compressed P-256 public key.

Every fact also carried outside the canonical challenge must be byte-identical
to its challenge field. The validator additionally requires the trusted Site
Trust Domain, device identifier and current revocation generation supplied by
the retained enrolment boundary. Issue time may not be in the future, expiry
is exclusive, and the issue-to-expiry interval is at most ten minutes.

The producer uses only the enrolled Site Root Secure Enclave key. It requires
an explicitly evaluated, operation-scoped Face ID context supplied after the
operator has reviewed the Site Trust Domain, Base Camp migration purpose,
generation, device and expiry. It signs the complete canonical challenge,
opens the staged ciphertext in transient memory, proves the derived Ed25519
public key, and immediately rewraps the same 32 bytes to the completion host.
Old shared material, new shared material and plaintext are zeroised on every
return path.

Both old and new ciphertext use the existing P-256 ECDH, HKDF-SHA-256 and
AES-256-GCM algorithms. Their AAD is the SHA-256 of five length-prefixed values
in this exact order: fixed Base Camp purpose, Site Trust Domain, generation,
device identifier and the applicable host compressed SEC1 key. It cannot
equal the generic or Site Root wrapping contexts.

The submission remains the established eight-field carriage: transaction
correlation, canonical challenge, device identifier, delegation serial, Site
Trust Domain, fixed purpose, detached COSE_Sign1 and rewrapped ciphertext.

## Deferred routing and presentation

This decision does not choose a Monas HTTP endpoint, QR family, browser
trigger, polling contract or application navigation. No transport or UI is
activated until Pistis and Monas agree exact constants and Monas can prove its
authenticated current session before contacting only
`/run/mnemosyne-thesaurophylax/basecamp-vault-migration.v1.sock`.

The eventual application flow is a governed migration. It must display the
fixed evidence and require an explicit application-level approval followed by
fresh Face ID. The ordinary-login scan-as-intent exception in ADR 0007 never
applies. There is no compatibility, manual-copy, local-file, CLI-secret,
browser-secret, environment or generic-rewrap fallback.

## Consequences

- Pistis can validate and cryptographically answer an independently supplied
  accepted Base Camp presentation without widening any existing purpose.
- Simulator tests can prove canonical parsing, cross-field equality, wrapping
  and submission compatibility without claiming Secure Enclave or Face ID.
- Physical-iPhone, Monas relay, Thesaurophylax claim, Expedition vault and
  plaintext-retirement evidence remain required for end-to-end acceptance.
- A future route or UI change must extend this ADR or introduce a linked
  decision and must not reinterpret this protocol core.

## Alternatives considered

- **Allow the Base Camp prefix in the generic rewrap.** Rejected because the
  nine-field generic challenge cannot authenticate the nineteen Base Camp
  fields or purpose-bound AAD.
- **Reuse the Site Root bundle producer with a different string.** Rejected
  because its schema, generation namespace, evidence and authority intent are
  distinct.
- **Put the legacy passphrase in a QR, HTTP body or application model.**
  Rejected because the accepted transaction keeps the secret only inside
  Thesaurophylax, transient iPhone cryptographic memory and the fixed
  Expedition verifier.
- **Invent the pending Monas route in Pistis.** Rejected because that would
  create an unreviewed authority and session-binding contract.

## Validation

Conformance tests require one independently derived positive vector plus
negative cases for the schema, every tag, order, length, identifier, fixed
string, timestamp, revocation generation, cross-field equality, digest,
public key, ciphertext and AAD binding. Tests must also prove that the generic
and Site Root purposes remain rejected and that no ordinary-login coordinator
entry point references the Base Camp protocol.
