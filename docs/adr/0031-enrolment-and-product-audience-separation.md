# ADR 0031: Separate enrolment and product audiences

- Status: Accepted
- Date: 2026-07-30
- Accepted: 2026-07-30
- Decision owners: Pistis mobile security, Prosopikon authority, Monas
  transport, and product owner
- Tracking issue: [#349](https://github.com/sagrudd/pistis/issues/349)
- Implementation: permitted in dependency order with specialist review and
  exact cross-project conformance evidence

## Context

The first-device protocol correctly uses the fixed audience
`prosopikon:pistis:enrolment` to prevent an invitation or receipt from being
replayed as a product authentication request. The iOS implementation currently
persists that ceremony audience as the sole audience in its installation trust
record.

Monas later signs authentication challenges for the product session being
requested: `propylaion`, `dasobjectstore`, or `jenkins`. A genuine
Prosopikon-enrolled phone therefore rejects a genuine Monas challenge because
the two deliberately different audiences cannot be equal. Isolated tests
missed the defect by constructing the trust record and challenge with the same
hand-written value.

Accepting any audience signed by the installation key would remove the
cross-product replay boundary. Reusing the enrolment audience for a product
session would confuse two protocol purposes. Neither shortcut is acceptable.

## Decision

### Distinct signed facts

The authority treats these as independent facts:

1. `enrolment_audience` is exactly `prosopikon:pistis:enrolment` and applies
   only to the invitation, presentation, registration, and enrolment receipt.
2. `authorised_product_audiences` is a non-empty, closed set selected by the
   administrator from the installation's deployed product profile. It applies
   only to later authentication challenges and responses.

The initial Mnemosyne portfolio profile permits the exact lower-case values
`propylaion`, `dasobjectstore`, and `jenkins`. An installation receives only
the values it actually exposes. Customer-hosted systems use the same values;
DNS names, ports, customer names, usernames, and mutable display text are not
audiences.

### Canonical protocol extension

The protected first-device invitation and presentation commit the ordered
`authorised_product_audiences` array. The mobile enrolment receipt repeats the
same array under the authority signature. The array contains 1..16 unique,
non-empty ASCII texts of at most 128 bytes, ordered by encoded byte order.
Unknown, duplicated, unsorted, empty, or unsupported values fail closed.

The new receipt field follows existing key 25 as key 26. The invitation and
presentation profiles receive their next available integer keys. Because all
of these maps reject unknown fields, their purpose and version advance
together rather than silently changing a version-one map. Old and new
profiles are not reinterpreted as each other.

Prosopikon persists both audiences and includes them in invitation,
presentation, registration, receipt, audit, idempotency, and reconciliation
digests. Monas never supplies or broadens the enrolled set.

### Mobile verification

iOS stores `enrolmentAudience` separately from
`authorisedProductAudiences`. Before displaying an approval it still verifies
the installation identifier and key, COSE signature, identity, generations,
expiry, display digest, and endpoint allow-list. It additionally requires the
signed challenge audience to be an exact member of the authority-signed
product set.

The signed device response repeats the challenge audience. Prosopikon creates
only that audience's session, and Monas scopes its cookie to the corresponding
product route. A Propylaion approval cannot become a Jenkins or
DASObjectStore session.

Existing version-one enrolments cannot be upgraded locally or inferred from
host configuration. They require an authenticated authority refresh or a new
enrolment under this profile.

### User experience and diagnostics

The prominent QR target on the Scan screen starts the camera directly and is
an accessible button. The lower start/stop control may remain as a secondary
control.

A structurally invalid QR remains labelled unsupported. A cryptographically
valid request that fails installation, audience, identity, expiry, or endpoint
policy receives a bounded, category-specific recovery message without
revealing keys, raw payloads, or attacker-controlled text.

## Consequences

- This is an incompatible canonical protocol revision and must land in
  dependency order across Prosopikon, PistisCore/iOS, shared fixtures, Monas
  conformance tests, CLI documentation, and Jenkins evidence.
- The first implementation must not weaken the existing fixed enrolment
  audience or infer product authority from an HTTPS endpoint.
- One installation can support the accepted standalone Propylaion,
  DASObjectStore, and Jenkins routes without enrolling three independent
  device identities.
- Future products require a reviewed profile extension; arbitrary
  caller-supplied audiences are not accepted.

## Required evidence

- A byte-exact Prosopikon enrolment fixture is consumed by Swift and retains
  distinct enrolment and product audiences.
- Byte-exact Monas challenges for every authorised audience are accepted by
  Rust and Swift; an unlisted audience and every malformed set fail closed.
- A challenge accepted for one product cannot finalise or receive the cookie
  for another product.
- Restart, replay, stale-generation, expired trust, wrong identity, wrong key,
  endpoint substitution, and old-profile migration cases are deterministic.
- A physical iPhone scans a real Monas QR, shows verified request facts,
  approves with Face ID, and completes the intended browser session.
- The Scan target's tap and accessibility activation both start the camera.
