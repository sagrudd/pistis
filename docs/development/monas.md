# Monas standalone integration development

EPIC-10 is an integration milestone, not a relabelling of Monas's existing
password login. The sibling Monas repository currently provides an Axum/Yew
standalone host whose login, local users, sessions, and authenticated product
forwarding are owned by Prosopikon. It does not currently depend on Pistis,
mount Pistis routes, or provide a Pistis CLI.

Pistis currently provides reusable identity, authentication, device-registry,
cryptographic, QR-reference, and verifier crates. It does not yet provide the
M8 standalone service, embedding facade, CLI binary, evidence store, or Monas
adapter. Those absences are delivery blockers and must not be described as a
working standalone integration.

## Host and dependency boundary

[ADR 0010](../adr/0010-monas-standalone-integration-boundary.md) is normative.
[ADR 0020](../adr/0020-prosopikon-pistis-authority-transaction.md) specifies
the accepted shared durable completion port required by the production route.
Individual implementation pull requests remain subject to its review and
exact-revision evidence requirements.
Implementation must retain these repository boundaries:

- Pistis owns challenge semantics, device-key and binding verification,
  single-use consumption, trust policy, and Pistis verification evidence.
- Monas remains the standalone HTTP and product host.
- Prosopikon remains Monas's authority for local accounts, password
  verification, normal browser sessions, and immutable principals unless an
  explicit cross-project decision changes that ownership.
- A successful Pistis verification result is input to a separately authorised
  Monas session-issuance operation. It is not itself a Monas cookie, role, or
  product authorisation.
- Pistis crates do not import Monas, Prosopikon, Axum, Yew, or product-specific
  types. A narrow Monas adapter depends on stable Pistis interfaces.

Do not mount a second generic `/api/auth/*` implementation over Monas's
existing Prosopikon compatibility routes. Select a versioned, host-owned Pistis
route namespace only after the ADR fixes the HTTP contract. Monas bootstrap
metadata stating `device token requirement: NotRequired` is current Monas
product-host evidence; it is not evidence that Pistis is enabled or ready.

## Required standalone profile

The M8 service profile is incomplete until one deployable composition provides
and tests:

- local installation configuration and trust policy;
- durable device registry and migrations;
- durable, bounded, single-use challenges;
- response verification and atomic challenge consumption;
- redacted evidence retention;
- administration and readiness interfaces; and
- SQLite lifecycle, backup, upgrade, and rollback behaviour.

The existing `pistis-device-registry` SQLite implementation satisfies only the
device-registry slice. In-memory repositories and reference QR envelopes are
test tools, not a deployable service profile. No service may report ready while
its durable challenge, binding, policy, evidence, or migration adapter is
absent.

## CLI contract

The milestone command inventory remains the target interface:

```text
pistis init
pistis user add
pistis trust add-github
pistis trust add-google
pistis device list
pistis device revoke
pistis challenge create
pistis response verify
pistis evidence inspect
pistis evidence verify
pistis trust export
pistis doctor
```

Command names do not establish completion. Each command needs stable exit
codes, structured non-secret errors, bounded input, deterministic tests, and
operator documentation. Mutating commands require explicit scope and must not
silently create replacement keys, reopen bootstrap, accept expired challenges,
or downgrade assurance.

`pistis response verify` and `pistis evidence verify` must work without a
public network service. Offline verification still requires explicit trusted
inputs and does not prove challenge freshness or consumption unless an
authoritative local repository participates. Inspection is never equivalent to
cryptographic verification.

A CLI login demonstration must use generated identities and documented
fixtures. It may demonstrate the reviewed reference envelope, but it must not
claim production mobile interoperability until the COSE profile and shared
Rust/iOS/Android fixtures are accepted.

## Required tests

Use fixed identifiers and clocks. Cover at minimum:

- unknown, suspended, revoked, substituted, and mismatched devices;
- wrong installation, user, external identity, purpose, key, and binding;
- expiry, replay, duplicate submission, and concurrent consumption;
- corrupt or unavailable SQLite state and interrupted migration;
- malformed, oversized, non-canonical, and trailing input;
- verification with no network access;
- Monas receiving no host principal or session on any failed Pistis outcome;
- Prosopikon and Pistis identifiers not being treated as interchangeable; and
- redaction of capabilities, nonces, responses, signatures, provider
  credentials, cookies, session tokens, and private material.

Cross-repository tests pin exact Pistis and Monas revisions. A test that builds
only one repository is not Monas integration evidence.

## Jenkins contract

Jenkins should retain a separate cross-repository contract dossier in addition
to normal Pistis and Monas repository CI. The approved task must:

- obtain both repositories as exact policy-pinned sources rather than cloning
  an unpinned branch in repository-controlled shell;
- run offline CLI verification fixtures and negative cases;
- run the narrow Monas adapter/server contract tests;
- record both commit IDs, lockfile hashes, task/container digest, command log,
  and machine-readable test results; and
- contain no provider, signing, browser-session, or production-user secret.

Do not add a Jenkins task that merely checks Monas's existing
`/api/auth/login`; that path proves Prosopikon password authentication, not
Pistis integration. Native packaging, systemd, container, RPM/SRPM, migration,
and appliance-profile acceptance require separate retained evidence.

## End-to-end demonstration contract

This section defines only a bounded
**Pistis → Monas → DASObjectStore → Oikodome → Jenkins** lane. It is a
demonstration profile, not the complete programme demonstration and not a
shortcut around the standalone readiness gates above. The authoritative full
chain is documented in the [programme architecture](https://github.com/sagrudd/mnemosyne-programme/blob/main/ARCHITECTURE.md)
and [demonstration plan](https://github.com/sagrudd/mnemosyne-programme/blob/main/DEMONSTRATION_PLAN.md):
Pistis → Kyberneterion → Proxenos → Thesaurophylax → Monas → DASObjectStore →
Oikodome → Phoreus Registry → Phoreus Forge → Jenkins.

The lane assumes the upstream Kyberneterion entitlement projection, Proxenos
Site Trust Domain, and Thesaurophylax intrinsic treasury/signature work. It
does not define Phoreus Registry or Forge publication, or Monas/Praxis work
admission and Kubernetes Job materialisation. Those boundaries and their
evidence remain required for the full programme demonstration. The run MUST
use generated identities and an isolated state root, and MUST record exact
source revisions, package digests, and the redacted evidence identifiers for
each step:

1. Prosopikon provisions one immutable local principal, an explicit Pistis
   principal binding, a trusted device, and the installation trust descriptor.
2. Monas creates a purpose-bound Pistis challenge, the device signs the
   challenge after local user verification, and the host verifies and consumes
   it exactly once before requesting a Prosopikon session.
3. The resulting audience-bound session enters the Monas product shell and
   authorises a DASObjectStore operation. The operation MUST persist its
   input, output, and redacted approval evidence in DASObjectStore; a browser
   cookie, product visibility flag, or actor name is not an authority input.
4. Oikodome registers or verifies the private local Kubernetes seed offering
   and returns a bounded compute admission. The host MUST retain the offering
   identity, capacity observation, admission decision, and failure reason; it
   MUST NOT launch an unmanaged process or silently expand beyond the offering.
5. Jenkins obtains a fresh, exact-audience approval for its owner-local
   authority, submits a pinned Expedition task, and records the Pistis,
   Monas, Oikodome, and DASObjectStore revisions in the retained dossier.
   Jenkins task input and output evidence MUST reference the corresponding
   DASObjectStore objects and the Oikodome admission; no secret or browser
   session is passed to the worker.
6. A negative replay, wrong-audience, revoked-device, and unavailable-seed
   case is run alongside the happy path. Each MUST fail closed without a
   Monas session, product dispatch, Kubernetes workload, or Jenkins task.

The minimum cross-repository dossier is therefore a single correlation record
linking the Pistis challenge and terminal decision, Prosopikon principal and
session identifiers, Monas audience, DASObjectStore object references,
Oikodome offering/admission identifiers, and Jenkins task/result identifiers.
It MUST contain no challenge capability, nonce, response, signature, cookie,
provider credential, private key, or raw personal data. Until Jenkins retains
this dossier for exact pinned revisions, this lane may be demonstrated but the
ecosystem MUST NOT claim the full programme demonstration.
