# Closed continuity approval source

This additive source targets the allocated `pistis-ios` 0.26.0+73 coordinate.
It preserves all legacy QR, COSE, signing purposes, enrolled key namespaces,
production flows and Rust package versions. It does not authorise an installed
phone, restore TLS or provide a current authority session.

The exact R3 specification digest is
`0b8047ec6cc5e3e6906af1163057895857800b69c54fa219d4bf93a34208b8ea`.
PistisCore parses canonical PCIA27/PCCB21/PCMS18/PCII12 fields using a separate
fixed-array/bytes/u64 codec. It checks exact profile P/A/specification,
allocation, scope, role keys, intervals, capacity and descriptor/origin/selection
joins. Signature verification uses the accepted domain plus one NUL octet,
exact canonical body and one SHA-256 prehash with strict P-256 raw low-S
signatures. No old consent or COSE envelope is accepted as continuity approval.

`ValidatedContinuityPresentation` contains immutable public facts and signature
evidence. It is **not** enrolled policy, verified generation provenance or an
operation authorisation token. Complete generation records remain untrusted;
a hash alone cannot establish custody. The read-only app review view displays
only derived tuple fields and exposes no signing or biometric action.

The three closed producer functions enforce descriptor → mode selection →
issuer ordering. PCII is derived from the exact committed allocation; an
arbitrary issuer message is not accepted. Exact identity/body reservation,
durable pre-invocation fencing, current revalidation and verified result
retention precede success. A possibly invoked operation without a durable
exact result stays unresolved and cannot be re-signed. Changed bodies conflict;
exact retrieval reauthenticates and returns original bytes without signing.

## Runtime boundary

The public/default producer fails closed. There is no public constructor for
an accepted operation context or incoming serialisable trusted token. Its
current authority, typed phone driver and protected ledger adapters remain
module-internal pending an independently reviewed real bridge. Tests use
explicit models and original signed R3 public TEST vectors, never a real Site
credential or generated production key.

The exact missing runtime inputs are independently authenticated current Site
credential **new-purpose** enrolment/lifecycle/revocation, authenticated exact
phone/server ingress, complete production public-generation provenance,
protected established ledger/floor and fresh attended authentication. R3 does
not define an authenticated cross-process trusted-context transport; it
explicitly forbids one until separately accepted. Existing possession of the
`site-root-delegation-v1` key, old delegation/PXRA consent, App Attest or an
incoming caller Boolean cannot fill these gaps. No adapter invents a wire
format or maps the synthetic TEST generation schema to production.

There is no missing-store initialisation or recovery fallback. A concrete
protected ledger adapter must preserve the atomic identity/body/state contract
and independent monotonic context before it can be installed. These source
models do not prove native crash durability, rollback protection or genuine
credential provenance. Actual source qualification, native phone/platform
review, protected publication and any signing/build/device exception remain
separate governed gates.
