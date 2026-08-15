# App Attest key replacement v1

This additive Pistis capability stages a fresh Apple App Attest key for the
same already-enrolled physical iPhone when the currently admitted key is no
longer usable. It is not device enrolment, Prosopikon membership replacement,
or a trust bootstrap. Monas owns the durable request and acceptance state.

The wire protocol is
`pistis.apple-app-attest-key-replacement.v1`; its only purpose is
`site-root-app-attest-key-replacement`. Presentation and submission files are
bounded canonical JSON using JCS-compatible sorted keys and no insignificant
whitespace. Pistis rejects unknown, missing, duplicate, reordered,
noncanonical, trailing, stale, future, or malformed input.

The presentation contains exactly `protocol`, `purpose`, `transaction_id`,
`installation_id`, `device_id`, `site_trust_domain`,
`old_key_id_b64url`, `old_generation`, `new_generation`,
`challenge_b64url`, `site_root_key_id`,
`site_root_public_key_sec1_b64url`, `issued_at_unix_millis`, and
`expires_at_unix_millis`. The UUID is canonical lowercase text; binary values
are canonical unpadded Base64url; the App Attest key and challenge are 32
bytes; the compressed P-256 Site-root key is 33 bytes; the generation advances
by exactly one; and the lifetime is at most 15 minutes.

After one fresh Face ID evaluation, Pistis verifies the existing Site-root
public key, asks Apple for a distinct new App Attest key, and stores the opaque
candidate key ID as pending before requesting its attestation. A retry for the
exact transaction reuses that candidate; a different pending transaction is
denied. The admitted primary key remains byte-identical. The Monas challenge
is the exact 32-byte App Attest client-data hash.

Pistis then constructs the exact approval object: `protocol`, `purpose`,
transaction, installation, device, Site domain, old and new App Attest key
IDs, SHA-256 of the Apple attestation object, challenge, and new generation.
The existing Face-ID-protected Site-root key signs the JCS bytes and emits a
raw 64-byte P-256 `r || s` signature. The canonical submission nests the
unchanged `pistis.apple-app-attest-registration.v1` Apple registration request,
the original presentation, the approval object, and the Base64url signature.
The potentially large submission is a file payload; this slice makes no claim
that it fits a QR carrier.

Pistis promotes the pending key to the primary Keychain slot only after a
separately authenticated Monas result is canonical JSON with state
`accepted` and exact transaction, installation, generations, and old/new key
bindings. A crash after primary publication is reconciled idempotently from
the retained pending record. Rejection may discard only the exact pending
transaction while the old key remains primary. No private key, generic URL,
origin override, trust exception, password, or fallback is exposed.
