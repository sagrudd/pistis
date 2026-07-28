# ADR 0024: MVP deployment, product, and mobile profile

- Status: Accepted
- Date: 2026-07-28
- Decision owner: Project owner
- Related issue: PIS-E26 / #309
- Depends on: ADRs 0011, 0012, 0015, 0016, 0020, and 0023
- Supersedes: conflicting scope statements in `MVP_RELEASE_CANDIDATE.md`

## Context

The MVP planning review resolved a connected set of deployment, identity,
mobile, product-session, recovery, privacy, and commercial questions. Leaving
those answers only in a conversational record would allow individually
reasonable implementations to produce an incoherent system. This ADR records
the approved product profile. It does not change canonical encodings or replace
the detailed protocol decisions on which it depends.

## Decision

### Identity and first administration

The v0.1 provider registration is the organisation-owned GitHub App
`Mnemosyne Pistis`, owner `MnemosyneBiosciences`, App ID `4413299`, slug
`mnemosyne-pistis`, and public Client ID `Iv23lievHWZTGyot0BXa`. Device Flow
and expiring user authorization tokens are enabled. Installation-time user
authorization, webhooks, subscribed events, and explicit account,
organisation, and repository permissions are disabled. GitHub's implicit
Metadata read permission is the only registration permission. The App may be
used by any GitHub account, but Pistis enrolment remains invitation-only.
Client secrets, App private keys, provider tokens, and earlier OAuth client
identifiers are not release configuration.

The first approved binding is GitHub authority `github.com`, numeric subject
`3848500`, to the existing Prosopikon principal
`stephen@mnemosyne.co.uk`. Email and login are display values, never identity
keys. This principal initially has system-administrator responsibility across
the MVP installation; narrower roles remain required after MVP evaluation.

Each installation permits one one-time, ten-minute, local CLI bootstrap
invitation. It requires a foreground GitHub Device Flow, explicit identity and
installation confirmation, fresh device-key proof, and fresh platform
authentication. Prosopikon commits the invitation, provider binding, device,
generations, receipt, and audit atomically, after which first-bootstrap is
disabled. An invitation for an unknown provider subject pauses for explicit
administrator confirmation rather than inferring identity.

GitHub is online only for enrolment and explicit re-enrolment. Routine
authentication and exact-action approval are site-local and do not require
GitHub, a Mnemosyne service, or a public web application.

### Customer-site deployment

Every customer installation has a distinct tenant, installation identity,
site-local Prosopikon authority, device registry, audit log, and site-local
certificate authority. Pistis, Prosopikon, Monas, and DASObjectStore execute on
the site's Linux environment. `pistis.mnemosyne.co.uk` is an informational and
support site, not an authentication broker or OAuth callback.

Commissioning uses a Mnemosyne-signed installation certificate bound to the
tenant, durable installation identifier, host public key, permitted products,
and expiry. No shared installation secret is used. Renewable entitlements are
separate from durable installation identity. An expired entitlement has a
30-day offline grace period with warnings. After grace, authentication,
read/export, audit, backup, and governed recovery remain available; creation
of new privileged operations is disabled.

The site-local CA is bound into the installation certificate. Authentication
endpoints listen only on explicitly configured private LAN interfaces, use
certificate-pinned HTTPS, and advertise a unique installation-scoped mDNS
service. Discovery advertises only an opaque transaction reference and
authenticated endpoint, never a principal, email, action description, or
decision.

Mnemosyne may retain installation registration and minimized evidence digests.
Customer authority state and product data remain site-local. A global
Mnemosyne administrator may commission a site and participate in governed
recovery, but has no implicit routine access to customer data.

### Authentication and product sessions

QR and open-app LAN discovery are transports for the same durable
Prosopikon-owned transaction. The first valid completion closes every
transport; replay, disagreement, expiry, denial, or cancellation fails closed.
The MVP phone application may show nearby pending requests while open. QR is
the mandatory fallback. Bluetooth and closed-app/background notification are
deferred.

Routine authentication challenges expire after two minutes, exact-action
approvals after 60 seconds, and enrolment/bootstrap invitations after ten
minutes. All are non-renewable and use monotonic local expiry in addition to
authority time checks. Browser sessions have a 15-minute idle and eight-hour
absolute lifetime. CLI credentials authorize exactly one operation and expire
unused after five minutes. A job already started under recorded authority may
finish according to product policy; the credential cannot start another job.

Monas is the browser gateway. It exchanges a completed Pistis transaction for
an audience-bound Prosopikon session and gives Jenkins or DASObjectStore only
the resulting short-lived product session. GitHub credentials never reach
Monas, Jenkins, or DASObjectStore. The supported Jenkins CLI shape is
`pistis auth exec -- jenkins-cli ...`; it obtains an operation-scoped
credential after phone approval and never persists a reusable Jenkins API
token. DASObjectStore uses the same Pistis session boundary for routine access
and requires a fresh exact-action approval for destructive or
security-sensitive operations.

### Mobile assurance and lifecycle

The first MVP release requires physical-iPhone evidence. iOS 17 is the minimum
supported version and `org.mnemosynebiosciences.pistis` is the permanent bundle
identifier. Personal-team development builds are development evidence only;
TestFlight and release-candidate evidence require the approved Mnemosyne
Biosciences Apple organisation.

Android implements the same protocol and remains build- and
conformance-tested, with Android 12 / API 31 minimum and target API 36.
Physical Android qualification is not a v0.1 release gate. Debug signing is
not release evidence; organisation-controlled Play signing is required before
distribution.

Every authentication, approval, enrolment, or recovery signature requires a
fresh operating-system authentication prompt. Device passcode fallback is
permitted only with a recorded lower-assurance result; policy may require
biometrics. Pistis makes no jailbreak, root, remote-attestation, App Attest, or
Play Integrity claim in v0.1.

Users can revoke the current device and erase its local state. A lost device is
revoked through another administrator device or governed recovery; authority
sessions terminate and the revocation generation advances without cooperation
from the phone. Suspected provider compromise additionally requires GitHub
authorization revocation. Immutable minimized audit remains.

British English is the initial language. VoiceOver/TalkBack labels, dynamic
type/font scaling, contrast, reduced-motion behavior, and non-colour-only
states are release requirements.

### Recovery, evidence, and privacy

Site authority backups are encrypted daily and retain 30 daily plus 12 monthly
recovery points. They exclude mobile private keys and transient credentials.
Governed recovery uses two of three independently held shares: two customer
holders and Mnemosyne. Recovery and policy changes require dual control.

Audit retains immutable opaque identifiers, decisions, timestamps, result
codes, and necessary digests. It excludes provider tokens, QR contents,
biometric material, full action/content bodies, email, and login. The default
retention period is seven years. A signed policy change may alter retention;
authorized deletion leaves an immutable tombstone.

Mobile applications use no third-party analytics, advertising, telemetry, or
cloud crash-reporting SDK. Diagnostics are local, redacted, and exported only
by an explicit user action. The public site provides static Privacy, Security,
Support, and Terms pages without authentication or tracking. Drafts require
owner review now and legal/privacy approval before external production.
Security and support contacts are `security@mnemosyne.co.uk` and
`support@mnemosyne.co.uk`.

### Distribution, source, and brand

Pistis Core and its public protocols remain MPL-2.0. Already published mobile
source retains its existing MPL rights. Future iOS and Android application
repositories are intended to be proprietary Mnemosyne software, subject to
formal legal review; source may be shared under a separate commercial or
evaluation agreement. Mobile contributions require written IP assignment.
Public-core contributions use MPL-2.0 and the Developer Certificate of Origin.

The Pistis and Mnemosyne names, logos, application icons, and other brand
assets are reserved and are not granted by the source-code licence. The iOS
application is a free companion application monetized through enterprise/site
entitlements and support. It moves from TestFlight to an unlisted App Store
listing. Android moves from closed testing to free public or managed
enterprise distribution only after qualification. Apple’s Standard EULA is
the initial distribution contract; a custom EULA requires legal review.

## Deferred decisions

The following are explicitly outside the v0.1 profile and require new review:

- APNs, Firebase, or another closed-app notification path;
- Bluetooth discovery;
- a hosted authentication broker or WAN discovery service;
- routine Mnemosyne remote support or customer-data access;
- App Attest, Play Integrity, jailbreak, or root attestation claims;
- physical Android release qualification;
- narrower post-MVP administrator roles; and
- a confidential GitHub callback/PKCE transport.

## Consequences

- A customer installation remains useful offline and does not depend on a
  Mnemosyne authentication service.
- Discovery improves open-app usability without becoming an authority or
  disclosing pending action data.
- Jenkins and DASObjectStore receive product sessions, never upstream identity
  credentials.
- Legal/privacy approval, Apple organisation approval, and physical-device
  evidence remain release gates rather than software defects.
- Product implementation and test issues must cite this ADR when they
  implement one of these decisions.

