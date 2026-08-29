# ADR 0042: Purpose-separated Base Camp vault custody on iPhone

- Status: Accepted
- Date: 2026-08-29
- Decision owners: Programme owner, Pistis, Thesaurophylax, Monas, and
  Expedition maintainers
- Upstream authority: Thesaurophylax ADR-0012 migration contract at exact
  revision `a548b43da2a1f07220d93d2a2546923105a2364c` and successor contract at
  exact revision `eff757e`
- Implementation issue: [#501](https://github.com/sagrudd/pistis/issues/501)
- Security review: cross-product route constants and purpose separation were
  reviewed with Monas and Thesaurophylax in issue #501

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

Thesaurophylax projects public and encrypted material through the established
thirteen-field `THESMIP1` carriage and consumes the eight-field `THESMIR1`
submission. Their field counts do not make the inner operation generic. The
Base Camp migration and every later successor are two distinct complete
canonical challenges with purpose-bound wrapping contexts.

## Migration decision

Pistis accepts only the canonical challenge schema
`thesaurophylax.basecamp-vault-custody-provisioning.v1\0`, purpose
`basecamp-vault-passphrase-delivery-v1`, recipient
`mnemosyne-expedition-basecamp.service`, credential socket
`/run/mnemosyne-thesaurophylax/basecamp-vault-passphrase.sock`, and generation
prefix `basecamp-vault-`.

The migration validator parses exactly nineteen one-byte-tag,
two-byte-big-endian-length fields in order and permits no empty, duplicate,
reordered, trailing or unknown field. It verifies:

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
to its challenge field. Issue time may not be in the future, expiry is
exclusive, and the issue-to-expiry interval is at most ten minutes.

## Successor decision

Every later Base Camp start uses the separate canonical schema
`thesaurophylax.basecamp-vault-successor-rotation.v1\0` with exactly eighteen
ordered fields: Site Trust Domain, current generation, current host, current
ciphertext digest, current binding digest, successor generation, device ID,
enrolled device public key, payload-integrity public key, revocation,
transaction, delegation, issue time, expiry, successor host, fixed purpose,
fixed recipient and fixed credential socket.

Generations are canonical `basecamp-vault-N` values where N is greater than
zero with no leading zero. The successor must be exactly `N+1`; repeats, gaps,
zero and overflow deny. The old record is opened only under the N AAD and the
unchanged secret is rewrapped only under the N+1 AAD. The migration parser,
generic nine-field parser and Site Root parser all deny this profile.

## Cryptographic production

Both producers use only the enrolled Site Root Secure Enclave key. Each
requires an explicitly evaluated, operation-scoped Face ID context created
after the operator reviews the Site Trust Domain, exact operation, generation,
device and expiry. A producer signs the complete canonical challenge, opens
the existing ciphertext only in transient memory, proves the derived Ed25519
public key, and immediately rewraps the same 32 bytes to the fresh host. Old
shared material, new shared material and plaintext are zeroised on every
return path.

Both old and new ciphertext use P-256 ECDH, HKDF-SHA-256 and AES-256-GCM. AAD
is SHA-256 over five length-prefixed values in exact order: fixed Base Camp
purpose, Site Trust Domain, applicable generation, device identifier and
applicable host compressed SEC1 key. This cannot equal the generic or Site
Root wrapping contexts.

The submission remains the established eight-field carriage: transaction
correlation, byte-identical canonical challenge, device identifier, delegation
serial, Site Trust Domain, fixed purpose, detached COSE_Sign1 and rewrapped
ciphertext.

## Pinned transport

The migration QR schema is `monas.basecamp-vault-migration-qr.v1`. Its browser
page is `/settings/basecamp-vault-migration`, presentation endpoint is
`/v1/pistis/basecamp-vault-migration/presentation`, and submit endpoint is
`/v1/pistis/basecamp-vault-migration/submit`. Its presentation and submission
schemas are `monas.basecamp-vault-migration-presentation.v1` and
`monas.basecamp-vault-migration-submission.v1`.

The successor QR schema is
`monas.basecamp-vault-successor-rotation-qr.v1`. Its browser page is
`/settings/basecamp-vault-unlock`, presentation endpoint is
`/v1/pistis/basecamp-vault-unlock/presentation`, and submit endpoint is
`/v1/pistis/basecamp-vault-unlock/submit`. Its presentation and submission
schemas are `monas.basecamp-vault-successor-rotation-presentation.v1` and
`monas.basecamp-vault-successor-rotation-submission.v1`.

Both QR families are exact closed four-field JSON objects containing only
`schema`, `purpose`, `recipient`, and `presentation_path`. They contain no
origin, reference, capability, challenge, proof, ciphertext or secret. Pistis
fetches only the build-fixed path from the retained installation origin using
the retained TLS SPKI pin. Presentation GET and submission POST use strict
JSON, reject unknown fields and bodies over 16 KiB, require
`Cache-Control: no-store`, require GET `Content-Type: application/json` with at
most an optional UTF-8 charset, and accept only an empty `204` submit response.
After a transient unreachable result, Pistis retries the byte-identical POST
once at the same pinned origin. It does not create another proof, reopen
review, or request Face ID again; every non-transient response remains final.

The outer presentation contains its schema plus the exact thirteen named
THESMIP1 values. The submission contains its schema plus the exact eight named
THESMIR1 values. Pistis neither reconstructs the canonical challenge nor
permits a caller-selected route.

The retained signed installation stores the authority origin, TLS SPKI,
revocation generation and enrolled device state, but does not persist a second
authorising Site Trust Domain. Before fetching, Pistis independently derives
the actual local Site Root device ID from the retained Secure Enclave public
key and supplies that ID plus the retained revocation generation as mandatory
validator inputs. The Site Trust Domain is an authority claim received only
over the retained origin/SPKI channel: Monas independently derives it from
sealed installation inputs and the current Prosopikon binding. Pistis requires
the outer value to match its field in the complete signed canonical challenge
byte-for-byte. A substituted origin or SPKI, Monas sealed-domain mismatch,
local key, revocation, or cross-site outer/challenge drift denies. This release
does not invent a second locally persisted domain authority absent from the
signed first-device contract.

## Application flow

Both flows are governed. Scanning only fetches and validates a presentation.
Pistis displays the fixed operation, Site Trust Domain, recipient, generation
or exact N-to-N+1 transition, device and expiry. Only an explicit
operation-specific approval creates a fresh Face ID context and produces a
response. The ordinary-login scan-as-intent exception in ADR 0007 never
applies.

On accepted completion the sheet dismisses and Pistis lands on Identities; it
does not reopen the camera or require a redundant Done action. Cancellation
and retry may reopen Scan. There is no compatibility, manual-copy, local-file,
CLI-secret, browser-secret, environment or generic-rewrap fallback.

## Consequences

- Pistis can validate and answer migration and successor presentations without
  widening an existing purpose.
- Simulator tests can prove canonical parsing, cross-field equality, wrapping,
  route and submission compatibility without claiming Secure Enclave or Face
  ID.
- Physical-iPhone, Monas relay, Thesaurophylax claim, Expedition vault and
  plaintext-retirement evidence remain required for end-to-end acceptance.
- Any future route or UI change must extend this ADR or introduce a linked
  decision and must not reinterpret either protocol core.

## Alternatives considered

- **Allow the Base Camp prefix in the generic rewrap.** Rejected because the
  nine-field generic challenge cannot authenticate either complete Base Camp
  challenge or its purpose-bound AAD.
- **Reuse the Site Root bundle producer with a different string.** Rejected
  because its schema, generation namespace, evidence and authority intent are
  distinct.
- **Put the legacy passphrase in a QR, HTTP body or application model.**
  Rejected because the transaction keeps the secret only inside
  Thesaurophylax, transient iPhone cryptographic memory and the fixed
  Expedition verifier.
- **Reuse migration for later starts.** Rejected because a settled generation
  may never be delivered again; a successor binds exact predecessor state and
  exactly N+1.

## Validation

Conformance tests require independent positive vectors for migration and
successor plus negative cases for each schema, every tag, order, length,
identifier, fixed string, timestamp, revocation, cross-field equality, digest,
public key, ciphertext, predecessor/successor generation and AAD binding. They
must prove exact closed QR envelopes, strict outer JSON, local key/revocation
binding, cross-site denial, explicit review before Face ID, generic and Site
Root purpose rejection, and the absence of any ordinary-login Base Camp entry
point. Simulator UI coverage preserves operation-specific approval labels and
completion navigation that does not restart Scan.

The migration vector's legacy-source digest is the authoritative SHA-256 of
the lowercase hexadecimal 32-byte test passphrase plus its final line feed.
The successor vector includes the exact 621-byte current runtime binding and
binds its SHA-256 into field 5. Both vectors are test-only complete HTTP and
cryptographic transcripts, not illustrative placeholders.
