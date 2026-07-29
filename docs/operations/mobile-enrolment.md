# Mobile enrolment operations

This runbook describes the operator obligations accepted by
[ADR 0023](../adr/0023-authenticated-mobile-enrolment-exchange.md). The
exchange must remain disabled until its implementation passes cross-project
review and the evidence gates in that ADR.

## Bootstrap

1. Validate the Prosopikon database, configured GitHub application, exact
   callback allow-list, HTTPS termination, installation signer, authority
   receipt signer, and current policy and revocation generations.
2. Obtain the canonical authority descriptor from the configured public key.
   Confirm that its key identifier is derived from that key and record the
   descriptor digest through the approved administrator channel.
3. Issue a short-lived, installation- and audience-specific invitation for the
   intended immutable Prosopikon principal. Deliver its exact bytes only to the
   intended enrolment device. Never place the invitation in a URL or ticket.
4. Have the user complete GitHub authentication in the system browser. GitHub
   returns only to Monas over the registered HTTPS callback. Monas gives the
   app only a one-use opaque correlation through `pistis://oauth/callback`; it
   never sends the GitHub code, token, or PKCE verifier to the phone. A
   successful provider callback is not enrolment: the device registration and
   Prosopikon transaction must also complete.
5. Confirm only the coarse enrolment outcome and generated audit correlation.
   Do not ask for or record the invitation, OAuth code/token, PKCE verifier,
   registration envelope, or device private key.

The app must show an installation as trusted only after verifying the
invitation's authority-descriptor commitment, authority signature, exact
registration digest, complete binding, generations, times, audience, and
allowed hosts, followed by one atomic Keychain update.

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
They exclude invitation secrets, provider tokens, OAuth codes, PKCE verifiers,
cookies, and device private keys.

## Acceptance evidence

Before enabling the route, retain a Jenkins dossier pinning exact Pistis,
Prosopikon, Monas, and DASObjectStore revisions and the shared Rust/Swift
fixtures. Separately retain a redacted, signed physical-iPhone record for the
system-browser, Secure Enclave, Face ID, exchange, verification, and Keychain
path. A test using a synthetic software key does not replace that device
record.
