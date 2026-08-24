# ADR 0039: DAS replacement-receipt attended ceremony

## Status

Accepted for the production Site Trust activation path.

## Context

DASObjectStore must retire its legacy local-authority surface only after
Prosopikon has established the signed `dasobjectstore/Administer` entitlement.
Thesaurophylax purpose four signs the replacement receipt, but its protected
P-256 scalar remains unavailable until the enrolled iPhone proves current
custody and rewraps that scalar to a fresh, server-held session key.

The operation is a continuation of the attended Site Root bootstrap. A second
QR, a user-selected server, a password, or a trust exception would create an
unreviewed authority path. Returning HTTP success after only the custody proof
would also misrepresent the state: receipt signing and delivery occur later on
the same Unix-domain-socket stream.

## Decision

Pistis performs purpose four immediately after Site X.509 root/issuer unlock
and initial leaf approval over the same pinned, ephemeral, no-cookie Monas
transport. It reuses only the bounded `FaceIDCeremonyContext` already evaluated
for this exact multi-key activation operation, so the user receives one fresh
Face ID prompt rather than another indistinguishable prompt.

The presentation POST body is exactly:

```json
{"schema":"monas.das-replacement-receipt-begin.v1"}
```

The routes are fixed as:

- `/api/v1/pistis/das-replacement-receipt/presentation`
- `/api/v1/pistis/das-replacement-receipt/submission`

Presentation and submission use closed camel-case JSON schemas and canonical
lowercase hexadecimal byte strings. The presentation carries distinct
`existingHostPublicSec1` and fresh `hostPublicSec1` values. Pistis uses the
former to open the retained record and the latter to seal the rewrapped record;
the points must be valid and different. The canonical challenge is reconstructed
from the exact purpose-four TLV profile before any proof or rewrap is produced.
The `custodyGeneration` is the exact retained first-device custody generation
bound into the accepted Site Root record. Consumers validate its closed
identifier grammar and full challenge binding; they do not synthesize or
require a purpose-local namespace prefix.

The submission POST remains open while Monas retains the single UDS stream
through `TDRA01`, `TDRQ01`, `TDRR01`, and receipt delivery to waiting DAS.
Pistis advances only for the exact correlated response state `receipt_signed`.
Plain `accepted`, asynchronous polling, retries, resumptions and alternate
routes are not accepted.

## Consequences

Stream loss or any mismatch leaves the bootstrap incomplete and produces only
a coarse custody-unavailable failure. The iPhone never receives the receipt
signing key, stores scalar material, chooses authority parameters, or claims
that DAS retirement itself completed. The final retirement and service
activation gates remain authoritative server-side checks.
