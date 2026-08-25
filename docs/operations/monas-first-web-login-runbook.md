# Pistis first-device onboarding and first Monas web login

This runbook is the attended, gate-by-gate procedure for onboarding one Pistis
iPhone and using it to create the first formal Monas web session. Complete one
gate at a time. Record its evidence and stop on any mismatch; do not improvise
a second QR route, edit authority databases, copy private keys or repeatedly
restart services.

The procedure distinguishes three different events:

1. **Local Pistis reset** erases this iPhone's Pistis state only.
2. **Formal first install** creates the installation, Site Trust, custody,
   GitHub identity and initial administrator evidence.
3. **Normal Monas login** creates a short-lived, exact-audience web session.

None is evidence that another one completed.

Administrator departure, a lost/destroyed/stolen phone and accidental deletion
of the only phone-bound credentials are supported recovery triggers. A
phone-local reset must not be treated as authority to destroy the organisation's
server-side installation. Recovery with continuity requires an independent
organisational recovery authority established outside that phone; when none
exists, the run must explicitly choose destructive rebuild and record that the
new installation has no continuity with the old one.

## Run record

Create one run record before starting:

| Field | Recorded value |
|---|---|
| Date and operator | 25 August 2026; `sagrudd` |
| NUC hostname and address | No network hostname assigned; `192.168.0.193`. The observed OS-local label `stephen-NUC12DCMi9` is not a Site Trust identity. |
| Monas package version and source revision | `0.116.3`; `d22199afc0a9b2c3b1650961291fcbffe5732a6a` |
| Recovery dependency versions and source revisions | Proxenos `0.53.1` at `cab0ae0a2832690c346b93184c839f56368f6657`; Thesaurophylax `0.70.0` at `fa61a3af3eacf1730f7978326fb5eacd24ccdc69` |
| Dependent package rebuilt for the closure | Expedition Base Camp/Jenkins `0.85.20` at `c08e45ea04fdcf43ca831a1093b167cf55fd8fb1` |
| Kanon lockset ID and digest | `monas-terraform-products-closure-20260825-r143`; `sha256:e0bb0917045484cd7d07fdb4f7af80573bc2b6b15d7c93735f1edd359c95f403`; registry revision `1b4836e7464785f0e691eeb2e23aa701fddd1c69` (canonical merge `2b7a61644da32cb056628255d0958194505d5aab`) |
| Terraform version and source revision | `0.4.49`; `371dbde324d093aa14c375db909fb3c24338801b` (r143 projection) |
| Pistis version, build and source revision | `0.23.0` (`47`); `3c7d9b5a5c77445fd3aa54cf249b65dd7c61790c`; signed IPA SHA-256 `84d3246dbf4bae0b482ba8d1699b322727741368bc536b4b3e84098dc2a1dc79` |
| iPhone model and iOS version | iPhone 14 Pro Max (`iPhone15,3`); iOS `26.6.1` (`23G83`) |
| Native Monas HTTPS origin | Not issued. The prior `https://192.168.0.193:8443` generation is ineligible after Gate 0; a new origin is recorded only when the new installation issues it. |
| Outcome of each gate | **Gate 0: PASS** (attended reset and idempotent live acceptance passed). **Gate 1: PASS** (operator observed Pistis `0.23.0 (47)` in About). **Gate 2: PASS** (operator reports local Pistis reset complete). Gate 3: implementation qualified; awaiting operator revalidation after r143 deployment. Gates 4–10: not started. |

Do not record QR payloads, bootstrap codes, browser capabilities, cookies,
provider tokens, private keys or complete signed proofs.

## Gate 0 — Choose retained recovery or genuine fresh development state

**Purpose:** prove that the development NUC is at an authoritative bare-earth
Monas identity state before a new phone or installation generation is issued.

For this run the phone reset has already completed. Do not start a ceremony,
issue a bootstrap code or display a QR until the NUC reset and every Gate 0
postcondition below have passed.

First inspect the retained state and preview the complete reset. Both commands
must be non-mutating:

```bash
sudo monas-first-install --status
sudo monas-first-install --destroy-all
```

The preview must name every installation/identity authority boundary that will
be reset, every service that will be stopped, and every class of data that will
be preserved. It must make no change and must print the exact confirmation
command. Review the plan, then run exactly:

```bash
sudo monas-first-install --destroy-all --confirm
```

### Gate 0 evidence for this run

The operator ran the attended destructive command on `192.168.0.193`. The
first execution retired the live installation and recorded this output:

```text
Proxenos destroy-all preflight: ready.
Thesaurophylax destroy-all preflight: ready.
The failed, unconsumed first-install broker lease was cancelled.
Proxenos active Site Trust generation destroyed.
Thesaurophylax first-install authority generation destroyed.
Monas teardown complete.
Monas configuration and active onboarding/runtime state are absent.
Installed packages and dependency-owned trust/custody/data were preserved.
Next route: sudo monas-first-install
Proxenos destroy-all postcondition: pass.
Thesaurophylax destroy-all postcondition: pass.
Monas destroy-all complete.
Prior installation, identity, trust and custody generations are ineligible.
DASObjectStore object data, installed packages and unrelated host data were preserved.
No ceremony was started. Record status evidence before running sudo monas-first-install.
```

The required already-reset execution then exposed two independent regression
defects instead of being waived: Monas `0.116.1` tried to contact an
unavailable broker after every local postcondition had passed, and Proxenos
`0.53.0` treated its package-created empty leaf-claims directory as active
authority state. They were corrected in Monas `0.116.2` and Proxenos `0.53.1`,
with fixture, execution, package-boundary and negative fail-closed tests. The
exact dependency closure was rebuilt through Kanon r142 and Terraform 0.4.48.

Qualification on the NUC passed all of the following before the retry:

- all 39 Terraform contract tests, exact Kanon lock export, lock validator and
  catalogue validator;
- Proxenos reset contract, execution and Debian-package tests on Linux;
- source-provenance fetch for every manifest and Cargo pin;
- all 20 DEBs carry the r142 lockset and content digest recorded above;
- installed Monas, Proxenos, Thesaurophylax and Base Camp packages carry the
  exact versions and source revisions in this run record;
- `dpkg --audit` prints nothing;
- the broker lease and root-console reset intent are absent;
- the package-owned Proxenos leaf-claims boundary exists as
  `mnemosyne-proxenos:mnemosyne-proxenos`, mode `0700`, and is empty;
- Monas broker/provider and Proxenos authority units are inactive;
- `dasobjectstored.service` and `dasobjectstore-server.service` remain active;
- the four DASObjectStore configuration digests, all eight mounted filesystem
  UUIDs and their top-level entry counts match their pre-reset values.

The acceptance-required second confirmed invocation passed live:

```text
Proxenos destroy-all preflight: ready.
Thesaurophylax destroy-all preflight: ready.
Monas destroy-all already complete.
Prior installation, identity, trust and custody generations remain ineligible.
DASObjectStore object data, installed packages and unrelated host data remain preserved.
No broker operation or ceremony was started. Next route: sudo monas-first-install
```

The Monas and Proxenos root-owned mode-`0600` reset evidence retained identical
hashes and modification times across this second execution. The broker lease
and reset intent remained absent. A final `--status` showed no issued bootstrap
presentation, no retained installation or identity, inactive custody and
authority, and every later route guarded or waiting. The final `dpkg --audit`
again printed nothing. No code, QR, broker operation or ceremony was started.

`--destroy-all` is the supported last-resort administrative rebuild without
continuity. It must use the reviewed package-owned reset interfaces for Monas,
Thesaurophylax and Proxenos; a missing dependency, unsafe path, active protected
operation or failed postcondition is a hard failure. It must expire any active
broker lease and render prior Site Root, Site X.509, App Attest, installation,
first-device, GitHub-provider and sealed-profile generations ineligible. It
must preserve installed packages, source/build artefacts, DASObjectStore object
data and unrelated host data.

After the confirmed command returns success, run:

```bash
sudo monas-first-install --status
sudo dpkg --audit
```

The release is not qualified for this run unless its acceptance suite invokes
both `monas-first-install --destroy-all` and
`monas-first-install --destroy-all --confirm`, proves that preview is
non-mutating, proves the exact dependency ordering and postconditions, and
proves idempotence on an already-reset fixture. That second execution is the
required regression for a phone whose only bound credentials were accidentally
deleted before server recovery began.

### Pass condition

The command completed successfully and the status/postcondition evidence says
that every prior development installation/device generation is retired or
destroyed, no broker lease remains, and a new Site Root may be issued. Monas,
Proxenos and Thesaurophylax agree with that state. `dpkg --audit` prints
nothing; DASObjectStore object data is still present and was not rewritten.

### Stop conditions

Stop if `--destroy-all` is unknown, if its preview mutates state, if status says
that a Site Root or signed first-device receipt is retained, if the installation
is committed, or if any package-owned reset/postcondition is unavailable. The
older `monas-first-install teardown --confirm` deliberately preserves Proxenos
and Thesaurophylax and is not a substitute. Do not bypass a refusal manually.

## Gate 1 — Install and identify the qualified Pistis build

**Purpose:** ensure the phone contains the build whose reset and QR contracts
were tested.

Install the reviewed, distribution-signed Pistis build. In **Settings → About
Pistis**, record the application version and build. Match its source revision
and archive digest to the run record.

### Gate 1 evidence for this run

The operator observed **Pistis `0.23.0 (47)`** in **Settings → About Pistis**.
This exactly matches the qualified build record above and source revision
`3c7d9b5a5c77445fd3aa54cf249b65dd7c61790c`. At that revision, both release
build configurations declare marketing version `0.23.0`, build `47` and bundle
identifier `org.mnemosynebiosciences.pistis`; the application entitlement sets
App Attest to `production`. The signed IPA digest remains the SHA-256 recorded
in the run record. The operator's already-completed Gate 2 reset also confirms
that this installed build presents **Settings → Reset this iPhone → Reset
Pistis on this iPhone**.

**Gate 1 outcome: PASS.**

### Pass condition

- The bundle identifier is `org.mnemosynebiosciences.pistis`.
- Production App Attest entitlement and distribution signing are present.
- The build contains **Settings → Reset this iPhone → Reset Pistis on this
  iPhone**.

### Stop conditions

Stop for a development signer, a different bundle identifier, an unknown
archive digest or a build without the reset regression evidence.

## Gate 2 — Reset Pistis locally

**Purpose:** erase the old Pistis identities, installations and app-owned local
cryptographic state only after Gate 0 has made that safe.

1. Open **Pistis → Settings**.
2. Scroll to **Reset this iPhone**.
3. Tap **Reset Pistis on this iPhone**.
4. Read the **Are you really sure?** dialogue.
5. First tap **Cancel**. Verify that the existing Pistis screens remain. This
   witnesses the non-mutating cancellation path.
6. Open the dialogue again.
7. Tap **Reset identities and installations**.
8. Complete the fresh Face ID prompt once.
9. Wait for Pistis to return to its initial onboarding screen.
10. Force-quit and relaunch Pistis.

### Pass condition

- The initial onboarding screen remains after relaunch.
- After entering the app, **Identities**, **Installations** and **History** are
  empty.
- No **Pistis reset is incomplete** alert appeared.

The reset does not log out GitHub in Safari, revoke Monas sessions, delete
authority audit evidence or remove Apple's opaque App Attest private key. It
removes Pistis's reference to that App Attest credential.

### Stop conditions

Stop if the app reports an incomplete reset, relaunch skips onboarding, or any
identity/installation remains. Do not begin first install from a partially
reset phone.

## Gate 3 — Verify the NUC package and dependency baseline

**Purpose:** prove that a new ceremony starts from one supported host build.

Run:

```bash
sudo dpkg --audit
sudo monas-first-install --status
```

Also verify the installed Monas, Thesaurophylax, Proxenos and DASObjectStore
packages against the exact Kanon lockset and Terraform projection recorded for
this run.

### Pass condition

- `dpkg --audit` prints nothing.
- Status prints `Gate 3 baseline: bare-earth-ready`.
- DAS is active. Proxenos authority is inactive and explicitly reported as
  `not activated`.
- Thesaurophylax custody is `not-issued` and reports the pre-enrolment
  bare-earth state as expected.
- Site X.509 first provision is `not-issued`; its descriptor is absent because
  the new iPhone has not yet established its Site Root key.
- The root-owned Monas, Proxenos and Thesaurophylax reset records are safe,
  machine-bound, complete and agree that the former generations were
  destroyed.
- Prior installation, identity, authority, custody, Site X.509 result and
  broker-lease state are absent. Merely reading status starts no service,
  lease, code, QR or ceremony.

Inactive Proxenos authority, unissued custody and an absent Site X.509
descriptor are required at this gate. Requiring them to be active or present
would be circular: the new Site Root and its attended approvals are created
only by Gates 6 and 7. Gate 3 proves the reset baseline; it does not prepare or
simulate later ceremony outputs.

### Stop conditions

Stop if `bare-earth-ready` is absent; if any reset record is missing, unsafe,
for a different machine or has substituted content; if DAS is inactive; or if
Proxenos authority, enrolled custody, a Site X.509 descriptor/result, retained
identity/installation, formal commit or broker lease is present. Also stop on
`identity-receipt-retained`, `committed`, `reconciliation-required`, a retained
Site Root, a source/lockset mismatch or an unexpected failed package.

### Gate 3 defect qualification for this run

The original Gate 3 checklist incorrectly required active Proxenos authority,
accepted enrolled custody and an existing Site X.509 descriptor immediately
after Gate 0 had deliberately destroyed those generations. The descriptor
contains the enrolled Site Root public key, so it cannot exist before the new
iPhone creates that key. This was a circular acceptance contract, not evidence
that the bare-earth reset had failed.

Monas `0.116.3` fixes the status projection narrowly. It labels a host
`bare-earth-ready` only when all three root-owned reset records have exact
schema, ownership, mode, machine binding and destroyed result; DAS is active;
Proxenos authority is inactive; and every resumable installation, identity,
custody, descriptor/result and broker-lease path is absent. Its executable
reset acceptance now proceeds directly from confirmed `--destroy-all` through
the real read-only `--status`, proves that no service, lease, code, QR or
ceremony was started, and proves that substituted reset-record content is
rejected. The focused Monas package tests, Kanon r143 canonical closure test
and all 39 Terraform projection/catalogue tests pass. Live NUC evidence and
the operator's independent revalidation are recorded before this gate closes.

The r143 package set was then built on the x86_64 NUC from Terraform
`371dbde324d093aa14c375db909fb3c24338801b`. All 20 generated and installed
DEBs carry the r143 lockset ID, content digest and their exact component source
revision. Linux compiled the Monas and DASObjectStore paths successfully,
including the DAS GUI API path that is not portable to macOS. After install:

- `dpkg --audit` printed nothing;
- two consecutive `sudo monas-first-install --status` reads reported
  `Gate 3 baseline: bare-earth-ready` with DAS active, Proxenos not activated,
  custody not issued and the Site X.509 descriptor correctly not issued;
- the three reset-record SHA-256 digests, owner/mode and mtimes were identical
  before and after both status reads;
- Proxenos lifecycle, the Monas broker and Thesaurophylax custody remained
  inactive, while both DAS services remained active;
- broker lease, genesis configuration, Site X.509 descriptor and formal
  installation marker remained absent; and
- the four DAS configuration hashes, eight mount UUIDs and all eight
  top-level entry counts exactly matched the pre-deployment baseline.

No code, QR, broker rendezvous or ceremony was issued. **Gate 3 remains open
only for the operator's independent revalidation. Do not start Gate 4 yet.**

## Gate 4 — Start the single supported first-install command

**Purpose:** create one attached host rendezvous.

In one SSH terminal on the NUC run:

```bash
sudo monas-first-install
```

Keep that terminal open. Do not run another copy of the command and do not
start individual Monas or Thesaurophylax units manually.

### Pass condition

The terminal prints:

- the ordered route state;
- `https://install.mnemosyne.co.uk`;
- one short-lived code and its expiry; and
- an instruction to keep the terminal attached.

### Stop conditions

Stop if the command selects reconciliation without a new code, reports an
inactive or incompatible protected route, or cannot start its broker
rendezvous. If the code expires unused, let the command settle and then start
one new run; never reuse or transcribe an expired code.

## Gate 5 — Redeem the code and verify GitHub

**Purpose:** bind the browser ceremony to the attended host and the verified
GitHub identity.

1. Open `https://install.mnemosyne.co.uk` in one browser window.
2. Enter the exact code printed by the attached NUC terminal.
3. Authenticate with GitHub when redirected.
4. Review the GitHub account and submit once.
5. Return to the same install window.

### Pass condition

The browser says the code was accepted and advances to the first protected
Pistis event. The terminal independently reports broker acceptance. GitHub
display text is not treated as the immutable identity; the authority binds the
numeric GitHub subject.

### Stop conditions

Stop on an unknown/expired code, a second browser attempting the same code, a
different GitHub account, a page outside the fixed install origin, or a browser
that offers only discard/cancel after provider approval.

## Gate 6 — Approve the protected Site Root genesis QR

**Purpose:** create the first iPhone Site Root key and App Attest binding.

The install browser must display exactly one protected **Site Root genesis** QR
for a genuinely fresh installation.

1. In Pistis, open **Scan**.
2. Scan the QR directly from the install browser.
3. Review the installation, destination, expiry and first-device purpose.
4. Approve once with Face ID.
5. Leave both browser and NUC terminal open.

### Pass condition

Pistis reports accepted proof submission, the browser advances, and the NUC
records the exact Site Root/App Attest fact. The phone shows one setup-in-
progress installation and does not yet show an authenticated GitHub identity.

### Stop conditions

Stop for **unsupported Pistis QR code**, **Site Root authority unavailable**,
an expired QR, an unexpected retained-authority recovery presentation, a
second Site Root QR, or endless Face ID waiting. Do not rescan the same QR after
an ambiguous submission; first inspect the host's durable state.

## Gate 7 — Approve the protected Site X.509 QR

**Purpose:** authorise the initial native HTTPS root, issuer and exact service
leaf set without reissuing Site Root.

The same install browser must next show one protected **Site X.509 first
provision** QR.

1. Scan it from the Pistis **Scan** tab.
2. Verify the displayed Monas/DAS services, addresses and generation.
3. Approve once with Face ID.
4. Keep the browser and terminal attached while custody continuation,
   acknowledgement registration and paired-leaf activation complete.

### Pass condition

- Pistis accepts the protected Site X.509 result.
- The browser does not request a second Site Root QR.
- Root custody, issuer custody, acknowledgement registration and initial leaf
  approval complete in their documented order.
- The NUC accepts the native TLS manifest for the Monas and DAS pair.

### Stop conditions

Stop for an unprotected/root QR, **custody ceremony unavailable**, **waiting
for Face ID** after Face ID already completed, an unsupported QR, an authority
generation mismatch or a host-side partial transaction. Do not start custody
units manually.

## Gate 8 — Commit the GitHub identity and initial administrator

**Purpose:** turn verified provider identity and signed iPhone registration
into the formal installation evidence.

Follow the browser and Pistis instructions for the provider-enrolment review.
Approve only the GitHub numeric subject and installation shown for this run.

### Pass condition

- Prosopikon durably commits one signed first-device enrolment receipt.
- Pistis shows one trusted installation and one GitHub identity.
- The authority projects exactly one `dasobjectstore/Administer` owner grant.
- The NUC profile commit is idempotently complete.

### Stop conditions

Stop if the phone says an identity already occupies the device, if the
provider subject differs, if identity trust appears before the signed receipt,
or if Monas reports success from files/systemd state without revalidating the
receipt.

## Gate 9 — Activate the protected authority and web surface

**Purpose:** expose normal Monas only after formal enrolment.

The original `sudo monas-first-install` process performs this automatically.
Do not run another command while it is progressing.

### Pass condition

- The terminal reports formal installation complete.
- `monas-pistis-authority.service` is active and owns the fixed Jenkins
  authority socket.
- `monas-pistis.service` is active on the native HTTPS origin.
- Oikodome reaches its package-owned readiness gate if it is part of the
  recorded release graph.
- No bootstrap/genesis listener remains active.

### Stop conditions

Stop on **production authority profile is invalid**, a stale authority socket,
bootstrap/authority overlap, activation from an unverified profile, or a
listener on an unapproved origin. A socket inode without a listener is stale
state, not an authority.

## Gate 10 — Perform the first normal Monas web login

**Purpose:** prove that onboarding produced credentials usable for a distinct,
normal authentication ceremony.

1. In a new browser tab, open the recorded native Monas HTTPS origin at
   `/login`.
2. Select **Continue with Pistis** if the login page offers multiple methods.
3. Confirm that the browser reaches `/auth/pistis/v3/login` and displays
   **Approve sign-in with Pistis**, one QR, **Cancel**, and **Waiting for your
   phone…**.
4. In Pistis, open **Scan** and scan that browser QR.
5. Verify the Monas installation, GitHub identity, exact audience and expiry.
6. Approve once with Face ID.
7. Leave the browser open while it polls and finalises the ceremony.

### Pass condition

- The browser redirects to `/home` over the same native HTTPS origin.
- The page shows the authorised product cards for the committed principal.
- The same-origin session projection is available and contains the expected
  principal, authority revision and `dasobjectstore/Administer` entitlement.
- Refresh preserves the session; logout revokes it.

The browser's ceremony capability remains HttpOnly and is not encoded in the
QR. The QR contains only the one-use signed Pistis challenge.

### Stop conditions

Stop if no QR is rendered, Pistis classifies it as onboarding or Site Root,
the audience is wrong, the browser says authentication unavailable, the phone
approves but the browser never finalises, or `/home` appears without a verified
Pistis session.

## Gate 11 — Prove exact-audience product entry

**Purpose:** demonstrate that a Monas home session does not silently grant a
product session.

Select DASObjectStore from `/home`. A fresh product-specific Pistis QR must be
issued. Scan, review the `dasobjectstore` audience, approve with Face ID and
verify that the resulting product session cannot be replayed for Jenkins,
Oikodome or another audience.

### Pass condition

The DASObjectStore web application opens with the exact authorised role, and a
different product still requires its own ceremony.

### Stop conditions

Stop if a home cookie directly opens DASObjectStore, if one product QR grants
another audience, or if product access is inferred from a username, email,
local Unix account or legacy password.

## Completion record

The run is complete only when every gate has a recorded pass. Retain:

- exact build/source/lockset identifiers;
- coarse timestamps and unit states;
- redacted receipt/evidence digests;
- the GitHub numeric-subject confirmation;
- the authority revision and exact product entitlement; and
- test results for reset, first install, normal login and audience separation.

Do not retain codes, QR payloads, browser capabilities, session cookies,
provider tokens, private keys or raw App Attest objects.
