# MVP deployment profile

This page is the operator-facing summary of
[ADR 0026](../adr/0026-mvp-deployment-and-product-profile.md). ADR 0026 and the
protocol ADRs remain authoritative where this checklist is abbreviated.

## Site shape

Deploy Pistis, Prosopikon, Monas, Jenkins and/or DASObjectStore inside the
customer-controlled Linux environment. Give each customer a distinct tenant,
installation identity, Prosopikon database, audit log, and site-local CA.
Never route authentication through `pistis.mnemosyne.co.uk`.

Expose authentication only on explicitly configured private interfaces using
certificate-pinned HTTPS. Advertise the installation-scoped mDNS service
without user, action, or decision data. Keep QR available as the offline and
discovery-failure fallback.

## First administrator

For the initial Mnemosyne evaluation, the administrator invitation binds:

| Field | Reviewed value |
| --- | --- |
| Provider | `github.com` |
| Numeric provider subject | `3848500` |
| Prosopikon principal display value | `stephen@mnemosyne.co.uk` |
| GitHub App owner | `MnemosyneBiosciences` |
| GitHub App slug | `mnemosyne-pistis` |
| Public Client ID | `Iv23lievHWZTGyot0BXa` |

The email is not an identity key. Before production enablement, verify the
reviewed GitHub App configuration digest required by ADR 0025. Do not put a
client secret, App key, user token, personal access token, password, or
passphrase in source control or a command argument.

Create the one-time local bootstrap invitation, complete it within ten minutes
on the foreground phone application, and confirm the displayed tenant,
installation, principal, numeric GitHub identity, device, and role. Confirm
that Prosopikon committed the receipt before disabling bootstrap.

## Evaluation path

1. Open Pistis on the enrolled iPhone.
2. Start a DASObjectStore remote EasyConnect login or a supervised Jenkins CLI
   command.
3. Select the nearby pending request or scan its QR fallback.
4. Verify the exact installation, product, principal, and requested action.
5. Complete the fresh operating-system authentication prompt.
6. Confirm that Monas exchanges the completed transaction for the correct
   audience-bound Prosopikon session.
7. Confirm that the product accepts only its short-lived session and that no
   GitHub or Pistis credential reaches the product.
8. Repeat an exchange, replay, expiry, denial, cancellation, restart, and
   revocation negative test.
9. Export only the redacted evidence dossier.

## Operational defaults

- authentication challenge: two minutes;
- exact-action approval: 60 seconds;
- enrolment/bootstrap invitation: ten minutes;
- browser session: 15-minute idle, eight-hour absolute;
- unused CLI credential: five minutes and one operation;
- entitlement offline grace: 30 days;
- authority backup: daily, 30 daily plus 12 monthly;
- recovery: two of three shares, held by two customer custodians and
  Mnemosyne; and
- minimized audit retention: seven years unless changed by signed policy.

An expired entitlement must not prevent authentication, read/export, audit,
backup, or recovery. It does prevent new privileged operations after grace.

## Release gates

Personal Apple-team builds are development-only. A TestFlight or release
candidate requires Mnemosyne Biosciences Apple approval, organisation signing,
physical-iPhone evidence, accessibility evidence, and the authoritative
Jenkins dossier. Android remains protocol/conformance tested but is not a
physical v0.1 release gate.

Formal legal and privacy review remains required before external production
for the mobile proprietary-source plan, EULA, Terms, Privacy, Security, and
Support pages.
