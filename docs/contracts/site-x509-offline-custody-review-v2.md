# Offline Site X.509 custody review V2

## Scope and authority

Pistis #532 and ADR0044 add a phone consumer for existing attended unlock V2.
The exclusive iOS allocation is 0.26.0, build 70, with Kanon source preparation
recorded in [the allocator receipt](https://github.com/sagrudd/pistis/issues/532#issuecomment-5972868895).
Monas owns the protected caller and registration; Thesaurophylax owns custody,
claims and acceptance. A response file establishes no backend readiness.

## Operator sequence

1. Obtain the complete canonical challenge SHA-256 through strict known-host
   SSH and the fixed protected Monas-to-Thesaurophylax peer.
2. Import the unchanged presentation and explicitly select its expected role.
3. Enter the independently obtained 64 hexadecimal characters separately.
4. Validate and review the exact role, Site, generation and fresh recipient.
5. Create the response with fresh Face ID and return the opaque JSON to the
   same retained host attempt. Reconcile actual backend acceptance separately.

The phone interface alone cannot perform the installed operation. A separately
reviewed Monas adapter must retain the genuine stream and protected bindings.
The actual 30-second server timeout requires a coordinated accepted amendment
before manual operation is qualified. No current challenge or physical approval
is supplied by this source change.

## Verification boundary

The importer bounds the file and rejects duplicate JSON before the existing
role-specific V2 decoder. Unknown, trailing, malformed or oversized input denies.
The existing strict parser also limits individual strings to 4,096 bytes. Exactly
32 independent digest bytes must match SHA-256 of the fully reconstructed
challenge before any Secure Enclave operation or scalar decryption. Imported
bytes can never populate that digest.

The challenge binds the fresh recipient and encrypted-record digest. It does
not bind the old host point. That point is shape checked and authenticated by
existing purpose-specific AEAD after signing and ECDH; failure prevents fresh
rewrap or export.

The current protected ACK record needs a positive generation and canonical
nonzero Site UUID. Its exact 32-byte target ID is SHA-256 of the enrolled
Site-root compressed SEC1 key. Its separate ACK public key never supplies the
X.509 device identifier. Reload the exact record around production, require the
existing Site-root key, and verify its actual hash after Face ID. Never create
or repair a key or registration.

Retain one immutable validated presentation through review. Cancellation,
replacement, expiry or changed registration invalidates the operation. Recheck
expiry after authentication before invoking the unchanged producer. Hold only
opaque response bytes in memory and discard them on cancellation or replacement.
Sharing transfers sensitive encrypted data to the operator; no plaintext scalar
or private key is exported. There is no HTTP submission or caller-selected route.

## Evidence and limits

Unit and simulator checks cover import and sequencing controls. They establish
no physical Face ID, Secure Enclave, App Attest, native backend, package, lockset
or release evidence. Existing cryptography and root-then-issuer dual-ready rules
remain authoritative. Preserve claims and consumed first-install transactions.
An exported or lost response is not acceptance and never reopens a claim.
