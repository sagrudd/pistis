# Assurance model

Pistis records assurance as explicit claims. It never turns heterogeneous
devices into a single “trusted” boolean. A verifier evaluates the claims
against local policy for the requested purpose.

## Enrolment claims

Every device registration records:

- the stable external-provider issuer and subject authenticated during the
  enrolment ceremony;
- when that authentication occurred and its provider authentication context;
- the local user and installation to which the binding was issued;
- whether the application generated the device key;
- whether hardware-backed key storage is `verified`, `reported`, `unavailable`,
  or `unknown`;
- whether biometric or device-credential authorization was required;
- whether platform attestation was verified, unavailable, or not requested;
- whether a device-integrity signal was verified, unavailable, or not
  requested; and
- the evidence and verifier versions supporting each claim.

Email addresses, GitHub usernames, display names, and device names are
descriptive metadata, never stable identity keys.

For Google, the durable external identity is the canonical issuer
`https://accounts.google.com` plus the exact, case-sensitive `sub`. The
documented legacy issuer spelling canonicalizes to the same authority. Email,
email-verification state, and hosted-domain claims remain descriptive or
policy inputs and cannot independently establish the account identity.

Google authentication evidence records successful local verification of the
ID-token signature, issuer, audience, authorized presenter where applicable,
expiry, issued-at time, and one-use nonce. It identifies the discovery and
verifier policy versions used, but never retains the ID token or other bearer
credentials. A missing or failed check cannot be represented as positive
assurance.

## Per-signature claims

An authentication or approval response records the registered key identifier,
device registration, authorization mechanism, observed hardware and integrity
state, signing time, challenge identifier, purpose, user, and installation.
Absence of a signal is represented as `unknown` or `unavailable`; it is not
silently upgraded to a positive claim.

## Policy evaluation

Policy is purpose-specific. Login, administrative approval, and artefact
signing may require different assurance. A verifier:

1. validates the signed protocol object and exact challenge binding;
2. loads the registration and revocation state valid at the relevant time;
3. evaluates every required assurance claim;
4. rejects missing required claims; and
5. retains the evaluated claims and policy result as evidence.

Historic evidence preserves the assurance observed at signing time. Later
revocation changes current authorization but does not rewrite a previously
valid historic record.

## Platform interpretation

- Apple Secure Enclave or Android StrongBox/TEE evidence may establish
  hardware-backed storage only when verified by a supported attestation path.
- An application statement without verifiable attestation is `reported`.
- Biometric-set changes, device restoration, key migration, or loss of
  attestation continuity require re-enrolment or an explicit policy downgrade.
- Rooted or jailbroken-device signals are advisory unless policy makes them
  mandatory; unavailable signals remain visible.
