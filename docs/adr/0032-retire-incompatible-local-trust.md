# ADR 0032: Retire incompatible local trust

- Status: Accepted
- Date: 2026-07-30
- Accepted: 2026-07-30
- Decision owners: Pistis mobile security, Prosopikon authority, and product
  owner
- Tracking issue: [#352](https://github.com/sagrudd/pistis/issues/352)
- Implementation: permitted with specialist review and the required evidence

## Context

ADR 0031 deliberately refuses to infer product permission for an enrolment
record created before the authority signed `authorised_product_audiences`.
The current strict Keychain decoder consequently rejects that old record.
This is fail-closed for authentication but makes the record invisible and
leaves create-once storage occupied, so the user cannot perform the required
new enrolment.

ADR 0030 permits local forgetting only when a record cannot authorise. It also
requires the app to distinguish local deletion from authority-side revocation.
The migration must preserve those rules without reactivating or silently
upgrading an old record.

## Decision

### Closed legacy decoding

The app may decode exactly the preceding installation-trust field set into a
separate `LegacyInstallationTrustRecord`. It must not decode into the current
authorising type, add a product audience, or pass through the active-enrolment
accessor. Unknown, missing, duplicated, malformed, or future fields still fail
closed.

Inventory labels the record **Re-enrolment required** and shows its
installation, provider identity, expiry, and fingerprint where those values
were already authenticated. It never labels the record active or available
for approval.

### Explicit local retirement

Because current software cannot use the legacy profile to authorise, the
installation detail offers an accessible destructive control labelled
**Slide to remove incompatible enrolment**. Confirmation states that this
removes only the phone's local credential and does not revoke authority-side
state or sessions. The operator must revoke the old authority credential or
use a fresh authority before re-enrolment.

The transaction re-reads and matches the exact installation and external
identity identifiers, writes minimised diagnostic history, removes the exact
Keychain record, and then deletes only the associated Secure Enclave key.
Loss of diagnostic history cannot block credential removal. If key deletion
fails, absent trust still prevents authorisation and history reports that key
cleanup is required.

Current-profile active trust remains subject to ADR 0030 and cannot use this
local-only path.

## Consequences

- A protocol migration no longer appears as an empty or missing installation.
- No product permission is inferred, and no legacy record can authenticate.
- Local retirement does not claim server revocation; production operators
  must complete authority-side cleanup.
- The immediate evaluation may use a fresh authority and re-enrol after the
  incompatible phone record is retired.

## Required evidence

- exact legacy records are visible but never returned for authorisation;
- current records retain their existing active and removal behaviour;
- malformed and mixed-version records fail closed;
- exact local retirement removes trust even when history or key cleanup fails;
- a physical iPhone retires the old record, completes a schema-v11 enrolment,
  and cannot use the retired credential afterwards.
