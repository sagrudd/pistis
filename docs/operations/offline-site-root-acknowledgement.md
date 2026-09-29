# Offline Site Root acknowledgement

Pistis supports a bounded local import/export path for a Proxenos-signed
`PXRP/v1` presentation and a Secure Enclave-signed `PXRA/v2` response. The
offline verifier accepts only the exact canonical file profile: detached
Ed25519 COSE signature, fixed content type and key-generation header, full
input consumption, current expiry, the enrolled Site, registered target, and
registered ACK generation. It makes no network request and does not change
the online compiled Monas HTTPS origin path.

The presentation key comes only from the signed application profile. The
profile binds the Site UUID, closed `site-root-ack-presentation` purpose,
positive Proxenos signing generation, public key, and SHA-256 digest. An
imported file cannot provide or rotate the pin. The current generic Pistis
profile leaves every pin field empty, so offline signing is unavailable until
the Proxenos-owned key custody source and exact public-key fingerprint have
been independently verified and approved for a signed release. Synthetic
fixture keys are test-only.

Before signing, Pistis checks that the exact unsigned PXRA matches the current
registered Site, target and ACK generation, remains unexpired after Face ID,
and names the root fingerprint and generation in the signed Site Root app
profile. Signing also requires a local verifier for the exact original signed
PXRB authorization and its durable native-mutation observation, including the
mapping between the native target and enrolled ACK device. That evidence is
not retained or verified by the current Pistis source. The app therefore
constructs this screen without an authorization verifier and displays
“Signing unavailable”; even a future valid PXRP pin alone cannot enable Face
ID. This release has no production pin and no implementation of the historical
PXRB/mutation verifier. Proxenos also does not currently retain the original
signed `PXNO/v1` bytes or an independently signed physical mutation time for
this transaction. The app and operator must not infer that time from
`updated_at` or dispatch timestamps. A future companion proof and its
Proxenos-attested or independently native evidence model require a reviewed
cross-service decision. The missing pin and evidence sources fail closed.

After both gates are independently implemented and accepted, Pistis uses only
the existing `site-root-convergence-ack-v2` Secure Enclave key tag and the
existing Site Root key tag. The response is held in memory for export; the
offline path has no transport or submission method. Proxenos remains
responsible for validating the original PXRB authorization at the durable
native-mutation time, current registration, freshness, replay and atomic
ACK/commit state.

If a challenge is expired, Pistis rejects it. A separate explicit Proxenos
operator action must inspect the exact current `AckPending` record, renew the
same transaction through its owner-approved route, then export the fresh
signed PXRP file through the read-only operation. Inspection and read-only
export do not trigger renewal. No Site Root, PXRB authorization, ACK key, or
native observation is replaced by the refresh.

## In-place update continuity

The local ACK continuity check generates a fresh domain-separated challenge
containing the Site, registered generation and random nonce after explicit
Face ID. It signs with the already-present ACK key, verifies against the
pre-update public key and generation, and discards the signature. The
challenge and signature are never taken from or sent to Proxenos.

App Attest continuity is a separate gate. Pistis may ask the existing App
Attest key to sign a distinct local challenge only when its pre-update key ID
is unchanged. An independent App Attest verifier must accept that assertion;
it does not create a production login session or approval. Neither check
replaces the other or establishes Site Root authority.

The protocol and pin lifecycle remain proposal-only pending owner, Proxenos,
Thesaurophylax, Kanon and specialist security review. The current signed
release contains no Proxenos pin, and no app update, phone operation or live
Site Root ceremony is authorized by this source change.
