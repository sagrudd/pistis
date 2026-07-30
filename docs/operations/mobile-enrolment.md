# Mobile enrolment operations

This runbook describes the operator obligations accepted by
[ADR 0023](../adr/0023-authenticated-mobile-enrolment-exchange.md) and the
first-host trust ceremony accepted by
[ADR 0029](../adr/0029-qr-bound-app-scoped-host-trust.md). The
exchange must remain disabled until its implementation passes cross-project
review and the evidence gates in that ADR.

## Bootstrap

1. Validate the Prosopikon database, reviewed GitHub App configuration digest,
   exact ADR 0025 Device Flow endpoints, HTTPS termination, installation
   signer, authority receipt signer, and current policy and revocation
   generations.
2. Obtain the canonical two-purpose authority bundle. Confirm that both key
   identifiers derive from their public keys, that the initial-invitation and
   mobile-receipt keys differ, and record the exact bundle digest through the
   approved administrator channel.
3. Calculate SHA-256 over the HTTPS leaf certificate's exact DER
   SubjectPublicKeyInfo and supply that reviewed 32-byte digest to the
   Prosopikon presentation producer. Do not hash the complete certificate, a
   PEM rendering, a raw EC point, or a textual fingerprint.
4. Issue a short-lived, installation- and audience-specific invitation for the
   intended immutable Prosopikon principal. Accepted ADR 0028 pipes the
   canonical producer directly into a Pistis
   alternate-screen QR presenter and permits scanning only from the app's
   explicit enrolment surface. Never place the invitation in argv, an
   environment value, file, URL, clipboard, ticket, log, or retained
   screenshot.
5. On the phone, scan the QR, check the displayed installation and origin,
   type the three words shown independently by the CLI, and select **Trust
   this host**. No certificate profile, Certificate Trust Settings change,
   browser warning, or public certificate authority is required. A mismatch
   is a stop condition: do not retry with words supplied by the phone or the
   network host.
6. Have the user complete the foreground GitHub App Device Flow. The phone
   calls only the signed-origin begin/status/cancel/confirm routes. The
   installation-local adapter owns GitHub polling and clears its transient
   device code, user code, and provider token on every terminal path.
   A successful provider poll is not enrolment: the signed device registration
   and Prosopikon transaction must also complete.
7. Confirm only the coarse enrolment outcome and generated audit correlation.
   Do not ask for or record the invitation, device/user code, provider token,
   registration envelope, or device private key.

The app must show an installation as trusted only after verifying the
invitation's authority-descriptor commitment, authority signature, exact
registration digest, complete binding, generations, times, audience, and
allowed hosts, followed by one atomic Keychain update.

The app verifies the exact returned bundle and byte-identical registration,
independently verifies the canonical ADR 0025 registration under the Secure
Enclave device key, verifies the receipt only under the committed
mobile-receipt key, and then performs one create-once Keychain installation.
An exact replay is idempotent; a different stored enrolment is never replaced.

GitHub success first renders the immutable login and numeric subject together
with the installation context. The user must press the separate confirmation
control before Face ID, device signing, authority confirmation, or Keychain
installation can occur.

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

Cancel, denial, expiry, or begin failure deletes only the exact namespaced
Secure Enclave key when no enrolment record exists. Pending and transient
failures retain it for retry. A consumed operation retains it for receipt
recovery because the authority may already have committed. Installed keys and
keys referenced by any stored enrolment are never deleted by cleanup.

Backups include the Prosopikon database, public authority material, signed
receipts, and audit records under the normal protected backup procedure.
They exclude invitation secrets, provider tokens, device/user codes, browser
state, cookies, and device private keys.

## Acceptance evidence

Before enabling the route, retain a Jenkins dossier pinning exact Pistis,
Prosopikon, Monas, and DASObjectStore revisions and the shared Rust/Swift
fixtures. Evidence must record the non-secret origin, SPKI digest, trust-word
derivation version, and confirmation outcome, but never the invitation.
Separately retain a redacted, signed physical-iPhone record for
foreground Device Flow, Secure Enclave, Face ID, authority exchange,
verification, and Keychain mutation. A test using a synthetic software key
does not replace that device record.
