# Mobile enrolment operations

This runbook describes the operator obligations accepted by
[ADR 0023](../adr/0023-authenticated-mobile-enrolment-exchange.md). The
exchange must remain disabled until its implementation passes cross-project
review and the evidence gates in that ADR.

## Bootstrap

1. Validate the Prosopikon database, reviewed GitHub App configuration digest,
   exact ADR 0025 Device Flow endpoints, HTTPS termination, installation
   signer, authority receipt signer, and current policy and revocation
   generations.
2. Obtain the canonical authority descriptor from the configured public key.
   Confirm that its key identifier is derived from that key and record the
   descriptor digest through the approved administrator channel.
3. Issue a short-lived, installation- and audience-specific invitation for the
   intended immutable Prosopikon principal. Accepted ADR 0028 pipes the
   canonical producer directly into a Pistis
   alternate-screen QR presenter and permits scanning only from the app's
   explicit enrolment surface. Never place the invitation in argv, an
   environment value, file, URL, clipboard, ticket, log, or retained
   screenshot.
4. Have the user complete the foreground GitHub App Device Flow. The phone
   calls only the signed-origin begin/status/cancel/confirm routes. The
   installation-local adapter owns GitHub polling and clears its transient
   device code, user code, and provider token on every terminal path.
   A successful provider poll is not enrolment: the signed device registration
   and Prosopikon transaction must also complete.
5. Confirm only the coarse enrolment outcome and generated audit correlation.
   Do not ask for or record the invitation, device/user code, provider token,
   registration envelope, or device private key.

The app must show an installation as trusted only after verifying the
invitation's authority-descriptor commitment, authority signature, exact
registration digest, complete binding, generations, times, audience, and
allowed hosts, followed by one atomic Keychain update.

The current implementation reaches verified provider status and constructs
the canonical device-signed binding. Final receipt verification and Keychain
mutation remain disabled pending a reviewed two-key descriptor bundle:
ADR 0028 currently commits the initial-invitation key, while ADR 0023 requires
the distinct mobile-receipt key. Never reuse one key for both purposes.

## Rotation

Authority-key rotation is an administrator-mediated trust-bootstrap event.
Issue a new invitation committing the new authority descriptor and re-enrol;
never accept a key announced only by the server response.

Installation signing-key rotation requires the separately reviewed
authenticated refresh protocol or re-enrolment. Device-key replacement is a
new device registration and never migrates private key material.

## Revocation and recovery

For a lost or replaced phone, revoke the device and key, invalidate affected
sessions, preserve the non-secret evidence record, and issue a fresh
invitation. Do not restore a Secure Enclave private key from backup.

If the exchange fails, use only the coarse correlation identifier to inspect
minimized authority audit records. An exact retry is safe only with the same
invitation and byte-identical registration envelope. A changed device key or
registration requires a fresh invitation.

Backups include the Prosopikon database, public authority material, signed
receipts, and audit records under the normal protected backup procedure.
They exclude invitation secrets, provider tokens, device/user codes, browser
state, cookies, and device private keys.

## Acceptance evidence

Before enabling the route, retain a Jenkins dossier pinning exact Pistis,
Prosopikon, Monas, and DASObjectStore revisions and the shared Rust/Swift
fixtures. Separately retain a redacted, signed physical-iPhone record for
foreground Device Flow, Secure Enclave, Face ID, authority exchange,
verification, and Keychain mutation. A test using a synthetic software key
does not replace that device record.
