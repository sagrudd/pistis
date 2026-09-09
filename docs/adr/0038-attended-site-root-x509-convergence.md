# ADR 0038: attended Site Root X.509 convergence

- Status: Accepted for the owner-operated internal deployment
- Date: 2026-08-11
- Amended: 2026-08-22 to make the already-decided PXAK registration ordering
  explicit in the pre-native continuation
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
   four ordered opaque continuations: root rewrap, issuer rewrap, PXAK
   acknowledgement-key registration and the combined initial-leaf approval.
   The registration phase is accepted by the fixed local Monas verifier and
   Proxenos port before Proxenos can present a leaf challenge that names the
   allocated acknowledgement-key generation. Pistis retains that exact
   generation from the protected leaf presentation before signing it. The
   original Face ID context may be reused
   only for this bounded sequence; every operation retains its distinct
   purpose, parser, key namespace and local acceptance boundary. No second QR,
   proxy, tunnel, temporary certificate or broker signing authority is added.
   A result accepted before a continuation-capable phone build existed may use
   one purpose-fixed continuation-recovery QR bound to the retained result and
   broker proof-collection marker. It resumes only these four operations and
   cannot reissue Site Root or first provision.
3. Pistis creates or opens the distinct Secure Enclave namespace
   `site-root-convergence-ack-v2`. Within the pre-native continuation, one
   freshly evaluated `LAContext` is shared only across its registration proof,
   using the existing Site Root key, and the immediately following
   initial-leaf approval. A later direct convergence ceremony may instead
   share its fresh context across an idempotent registration proof and the
   exact PXRA/v2 acknowledgement signature. Proxenos allocates the positive
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

## Accepted amendment: standalone retained receipt unlock

- Amendment status: Accepted, 2026-09-09, after independent security/design
  review and owner-authorised bounded repair decision; device acceptance remains pending.
- Date: 2026-09-09
- Issue: `PIS-RECEIPT-UNLOCK` (#510)
- Affected owners: Pistis (scan/review/Face ID), Monas (pinned presentation and
  relay), Thesaurophylax (existing receipt custody). Proxenos registration and
  convergence authority are unchanged.

The current phone implements receipt unlock only as the automatic continuation
of successful receipt provision. Monas also exposes an already-defined
standalone unlock descriptor for an existing receipt signer. Omitting that
descriptor from the scanner leaves the retained recovery path inaccessible;
it does not justify rerunning provision or creating a new receipt key.

The proposed fix admits exactly the existing four-field JSON descriptor:

- `schema`: `monas.site-root-bundle-receipt-unlock-qr.v1`;
- `purpose`: `thesaurophylax.site-root-bundle-receipt-rewrap.v1`;
- `role`: `site-root-bundle-receipt`; and
- `presentation_path`: `/v1/pistis/site-root-bundle-receipt-unlock/presentation`.

Reject unknown, duplicate, missing or mistyped fields, alternate paths and
oversized input. The descriptor is routing information, not approval or
authenticated challenge facts. It supplies no authority URL, trust pin, Site
selection, credential or key. The coordinator selects only the existing
direct pinned-origin transport, never the first-provision broker. Fetch the
existing bounded protected challenge through that transport and validate its
canonical framing, authenticated Site facts, purpose, generation and expiry
before exposing review facts or requesting authentication. This does not
claim an independent device-key match before review: local setup/history
observations are not trust authority, and public-key access must not cause an
extra biometric prompt before the explicit decision.

Show a distinct governed **Unlock Site Root receipt signer** review with the
validated Site, generation and expiry. Explicit approval invokes a fresh
Face-ID-only context and the existing Secure Enclave receipt rewrap producer;
do not borrow an earlier provision/login context. Revalidate expiry and let
the existing producer check the actual Site Root device-key/purpose binding
inside that approved fresh ceremony before proof production or submission;
wrong binding must fail before either. Submit through the same fixed pinned route,
and distinguish local approval/rewrap from authoritative server acceptance.
Cancellation, backgrounding, stale fetch completion or reset retires local
pending state and must not sign or submit. A replacement scan cannot approve
facts fetched for a previous scan. No automatic retry after signing/submission
and no second endpoint are introduced.

The existing same-ceremony automatic provision-to-unlock continuation remains
unchanged. Standalone unlock neither provisions nor registers a key, reruns
enrolment, modifies the operating-system trust store, alters a key namespace,
exports private material nor changes the existing rewrap wire/proof contract.

The added scan route could otherwise enable wrong-purpose approval, arbitrary
network requests or stale asynchronous work. Closed descriptor parsing,
pinned transport, exact fetched-fact validation, explicit governed review and
fresh local authentication preserve those boundaries. A printed descriptor
alone cannot authorise custody use. Device compromise is not mitigated by
route parsing; existing Secure Enclave and biometric guarantees remain the
limits of assurance.

Propose iOS **0.25.3+62**, a compatible patch for an omitted entry to the
existing accepted protocol rather than a new custody capability. Coordinate
the exact iOS identity witness in Kanon339 before release; 0.25.2+61 remains
reserved for the separate language-only companion in Kanon337. Preserve
`org.mnemosynebiosciences.pistis`, the existing development team, keychain
access groups, entitlements and retained keys. An owner-authorised operator
performs any later reviewed same-identity update, preserving the app container
and keychain without uninstalling or resetting. Verify the target and the
approved Distribution Ad Hoc artefact's bundle, team and production
entitlements before update; genuine operating-system/device-unlock prompts
remain attended. No user build or device is modified by this proposal.

Required source evidence covers the actual Monas descriptor, all closed-shape
denials, direct-versus-broker routing, fetched challenge validation, reset and
stale completion, explicit review and no-submit cancellation. Portable Swift
tests and unsigned native compilation/tests remain separate from physical
iPhone Face ID, relaunch and same-identity upgrade acceptance. Retain missing
native/device evidence honestly; no signing or camera substitute establishes
production interoperability.

## Accepted amendment: retained receipt wrapping-domain compatibility

- Status: Accepted, 2026-09-09, after delegated owner review of the exact
  compatibility boundary; implementation review and device acceptance remain separate.
- Issue: `PIS-RECEIPT-AAD` (#512); coordinated with Thesaurophylax #298 and
  Kanon #339. Proposed compatible iOS patch: **0.25.4+63**.
- Owners: Pistis (device rewrap), Thesaurophylax (retained ciphertext and proof
  admission), Monas (unchanged canonical challenge and relay).

The existing receipt protocol has distinct purpose domains:

| Boundary | Exact value |
| --- | --- |
| External proof purpose | `thesaurophylax.site-root-bundle-receipt-rewrap.v1` |
| Canonical challenge prefix | The full external purpose followed by NUL |
| Retained and fresh ciphertext AAD domain | `site-root-bundle-receipt` |
| Internal provider/signer scope intent | `site-root-bundle-receipt` |

Thesaurophylax's actual receipt provisioning implementation at canonical
`f6354aca13f9cbc5fe416a655ad65f722e54423c`, in
`portable_site_trust_receipt_issuer_v1.rs`, selects the short domain in
`purpose_aad` and passes that digest to the custody record's `write_new`.
The provision challenge itself binds this digest. Pistis canonical
`f0071a4ce64b6d8aff294c4a680b2ebb980acef2` instead uses the full proof purpose
for both opening that record and fresh rewrap. Those bytes cannot authenticate
the provisioned record. This is a cross-component compatibility defect, not a
reason to regenerate the retained receipt key or reinterpret ciphertext.

Correct only the fixed receipt AAD domain in the existing iOS producer to the
short value for both old-record opening and fresh rewrap. Preserve the exact
U32-length-prefixed SHA-256 encoding, field order, Site, generation, device-key
identifier and compressed host key. The external proof purpose and canonical
challenge remain full and unchanged. The paired Thesaurophylax correction
selects the full external proof expectation while retaining its short AAD and
internal scope. Neither correction alone establishes interoperability.

There is exactly one accepted AAD domain: no alias, alternate-domain probing,
decryption fallback, schema negotiation or record migration. Existing review,
fresh Face ID, actual device-key binding, expiry/cancellation checks, fixed
pinned transport, detached proof, seed/public-key equality and server replay
admission remain unchanged. No new UI, key namespace, provision operation,
service action, private-key export or cryptographic primitive is introduced.
Domain separation remains fail-closed; wrong domain or any changed bound field
must fail authentication rather than select another key or purpose.

Retain an explicitly synthetic interoperability vector produced using the
actual Thesaurophylax receipt provision path, with public source provenance and
test-only key material. Native Swift tests must open that old short-AAD record,
preserve its exact seed, and authenticate fresh rewrap with the same short
domain; the full proof-purpose string used as AAD must fail. Cross-check the
fresh output with the existing server wrapping implementation. Keep these
software fixtures distinct from physical Secure Enclave, Face ID and live
retained-record acceptance; no production record or key enters test evidence.

Preserve the existing bundle, team, keychain groups and production entitlements.
Any later owner-authorised same-identity phone update requires the reviewed
approved archive and target identity verification, without uninstalling,
resetting or replacing retained device keys. This source decision does not
claim a signed artefact, installation, physical acceptance or formal release.

## Accepted amendment: foreground selected-authority refresh

- Status: Accepted, 2026-09-09, after owner and independent security review;
  implementation and physical acceptance remain separate.
- Issue: `PIS-FOREGROUND-BINDING` (#514); prospective Kanon #339 coordination.
- Proposed compatible patch: **0.25.5+64**.

The generic app initially uses the fixed first-install broker. Its transport
store loads the selected authenticated enrolment at launch and on enrolment
change notifications. Protected storage is available only while unlocked.
A failed launch read currently leaves the broker selected; foregrounding
refreshes the displayed inventory but not this transport. A standalone receipt
scan can therefore reach the broker's deliberately unavailable direct operation
without making an appliance request. This source lifecycle gap is not yet
established as the cause of the observed physical-phone failure.

Refresh the same selected authenticated-enrolment binding when the application
becomes active. Use the existing protected loader and verified-enrolment factory;
neither a QR, displayed history, cached public setup information nor a host name
may provide authority. Retain the exact origin, enrolled allow-list and TLS
policy checks. When no current valid binding can be read, remove a previous
direct binding and report a distinct, non-sensitive local binding-unavailable
state for direct receipt unlock. Do not imply server rejection or lost keys.
The fixed broker remains available only for its existing supported operations.

A changed binding invalidates the scanner's previous coordinators through the
existing transport revision/view-identity boundary. It does not automatically
fetch, approve, sign or submit any operation. Existing cancellation, explicit
governed review, fresh Face ID, device-key checks and wire/cryptographic rules
remain unchanged. No credential, key, trust record or selected installation is
written by refresh. A transient storage failure may stop a pending operation;
retaining stale authority to avoid that interruption is not an acceptable
alternative. Repeated identical successful refreshes must not reset an active
ceremony. Late asynchronous results must not reinstate an obsolete selection.

Reproduce an initially unavailable loader followed by a valid authenticated
selection and foreground refresh, and test missing/invalid bindings, removal
of a stale direct binding, unchanged-binding stability and stale completion.
Use a narrow injected loader for deterministic tests; production continues to
use only the existing protected storage API. Native source tests do not prove
actual Keychain lock behaviour, camera interaction or physical recovery.
Preserve app identity, entitlements and keys; any later device update remains a
separately verified same-identity operation without uninstall/reset.

### Accepted diagnostic clarification for the same patch

The observed generic authority error does not establish the lifecycle gap as
the physical cause. Add closed, non-sensitive diagnostics only to receipt
unlock GET and POST. Report the operation (`presentation` or `submission`) and
one fixed category: cancelled, TLS, timeout, offline, DNS, connection,
connection-lost, authentication-challenge, other network failure,
non-HTTP response, unexpected endpoint, HTTP status, missing no-store header,
empty presentation, oversized presentation, or unexpected submission body.
Only a numeric HTTP status in 100–599 may supplement the closed category;
other status values map to a fixed invalid-status category. Map only known
`URLError.Code` constants; unknown errors map to other network failure.
Never expose underlying descriptions, NSError userInfo, URLs, headers, bodies,
pins, QR contents, proofs or custody material. Existing presentation parser
failures remain the separate custody-unavailable error.

Preserve the same endpoint, TLS policy, timeout, response predicates and
cancelled-operation checks. Do not add a retry or alternate pin. Presentation
failures may say no proof was sent. A failure after entering the submission
transport must instead say that submission was not confirmed: the request
may have reached the authority, so it must not claim that no proof was sent
or invite automatic replay. HTTP acknowledgement remains distinct from local
approval and server custody completion. This clarification is accepted after
owner review, before its diagnostic implementation.

### Receipt POST media-type compatibility correction

Owner-authorised compatible correction, 2026-09-09, issue #516; prospective
iOS **0.25.6+65**, linked Kanon #339. Monas 0.124.9 canonical
`03f7877440581b41d83e333fbadb52a1d8c3f020` accepts only the exact receipt POST
Content-Type `application/json`. Pistis currently adds `; charset=utf-8` and
therefore receives HTTP400 before JSON decoding, pending-state consumption or
custody submission. Send the exact existing server media type on this one
receipt endpoint. No server parser relaxation, body/schema change, alternate
route, trust change, proof replay or approval-protocol change is introduced.
The next genuine phone operation still requires its existing fresh approval.

Retain the exact canonical server header/body contract as a source-referenced
fixture. Capture the actual Swift submission request and pass it through a
synthetic server-predicate adapter: the current header/body must reach202;
the old charset-bearing header must reach400, never acceptance. Assert all
nine string fields and the schema. This adapter models only the HTTP admission
boundary, not real server custody verification or physical success. Existing
Face ID, cryptographic fixtures, fixed TLS, lifetime, cancellation and uncertain
submission diagnostics remain unchanged. Any later device update requires the
existing same-identity approved archive/export gates; never uninstall or reset.

### Accepted correction: native ACK target and phone signer are distinct

Issue518, iOS0.25.7+66, Kanon339; owner and independent contract review accepted
this compatible correction on 2026-09-09 before implementation. Proxenos PXRA/v2
tag2 is the native target whose observed root is acknowledged. PXAK/v2 instead
binds the ACK signer identifier derived as SHA256 of the enrolled phone's Site
Root compressed public key. These identifiers are deliberately unequal. The
phone currently compares them and throws invalidConfiguration after Face ID,
before registration or ACK submission; that comparison is not the contract.

Keep the derived phone identifier in PXAK registration and its COSE kid only;
that registration occurs in the existing authenticated pre-native broker flow.
The retained completion listener does not expose registration. Final ACK must
reuse only `SiteRootConvergenceAckStoreV2.current()` and both existing Secure
Enclave keys. Require record Site equal PXRA Site, record signer hash equal the
actual Site Root compressed-key hash, record ACK public key equal the actual
existing ACK key, and record positive generation equal PXRA ACK generation.
The current 0.25.6 broker `leafApproval` path persists that record only after
validating the authenticated leaf presentation. This source fact does not
claim the physical phone currently has a readable record. Missing or mismatched
record/key denies; no creation, repair, re-registration or fallback is allowed.
Keep the complete native PXRA bytes unchanged. Monas/Proxenos retain their
existing enrolled-proof and configured-signer registration checks. Proxenos
independently checks the signed native target against the
retained transaction: do not invent a phone-native inventory or substitute the
phone identifier into the native assertion. Wrong registration binding or
generation denies before ACK signing/submission; wrong native target denies
at the owner-side pending-transaction verifier. Reuse is the same protected
record/existing-key pattern as the existing leaf-approval producer, not authority
from display history. Existing QR framing, expiry,
fixed TLS, explicit fresh Face ID, key namespaces, proof bytes and server replay
checks remain unchanged. No new approval authority, fallback or key replacement.

Retain a real Proxenos-generated PXRA fixture with source provenance and an
actual phone producer sequencing regression with deliberately distinct native
and signer identifiers. Use synthetic keys only; no physical Secure Enclave or
OS installation claim follows from the fixture. Preserve app bundle, team,
keychain groups and entitlements through the existing approved archive gates.
