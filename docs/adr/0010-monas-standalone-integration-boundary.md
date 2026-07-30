# ADR 0010: Monas standalone integration boundary

- Status: Accepted
- Date: 2026-07-24
- Owners: Pistis protocol, Monas, Prosopikon, security, evidence, CLI, and
  operations

## Context

Monas is the standalone Mnemosyne host. It already owns Axum HTTP routing,
product mounts, TLS termination, browser presentation, and authenticated
product forwarding. Prosopikon is its single authority for local users,
password verification, immutable principals, browser sessions, and device
tokens.

Pistis M8 must add passwordless authentication and portable verification
without making Monas depend on Synoptikon or creating a second session
authority. The current Pistis authentication service is an in-memory reference,
ADR 0006 defers production COSE interoperability and durable ceremony storage,
and ADR 0009's production-readiness gates are not yet satisfied. Detached
evidence, report signing, local discovery, release packaging, and recovery are
owned by later milestones.

The issue wording for EPIC 10 is intentionally concise, while M8 in
`MILESTONE.md` describes a broader standalone service, embedding API, CLI,
reference application, and packaging surface. An explicit boundary is required
before adding security-sensitive host or command-line behaviour.

## Decision

### Dependency direction and authorities

Pistis provides a framework-neutral `pistis-monas` integration contract and
standalone application capabilities. These depend only on inward Pistis domain
crates and contain no Axum, Yew, Prosopikon, Monas, product, cookie, or host
auditor types.

Monas implements the host ports and owns HTTP, browser presentation, TLS,
configuration, service lifecycle, and product forwarding. Prosopikon remains
the sole authority for local principals and Monas browser sessions. Pistis
authenticates a previously bound principal; it grants no role, product
permission, operating-system authority, or storage authority.

Monas must consume Pistis from a reviewed, immutable remote revision recorded
in its dependency policy. Pistis must not depend on Monas or Prosopikon.

### Delivery profiles

The integration exposes distinct profiles so partial delivery cannot be
mistaken for production readiness:

- **contract** describes typed host ports and blockers and may be delivered
  before a host adapter;
- **reference** demonstrates deterministic flows with generated identities and
  in-memory components and must identify itself as non-production;
- **standalone** requires durable SQLite state, production protocol fixtures,
  protected sessions, transactional audit, backup and upgrade evidence; and
- **offline verifier** accepts only detached public evidence, performs no
  network access, and creates no authentication session.

Enabling one profile never implies that another profile is ready.

### Production readiness

The standalone profile fails closed unless reviewed evidence proves all of:

- an accepted COSE profile and shared Rust/iOS/Android positive and negative
  fixtures;
- durable SQLite repositories and migrations for trust policy, device registry,
  challenge lifecycle, evidence metadata, and audit;
- installation signatures over the exact persisted canonical challenge;
- complete installation, principal, external-identity, device, key, binding,
  policy-generation, and revocation-generation resolution;
- one rollback-capable completion transaction that re-evaluates bindings,
  consumes the challenge, invalidates pre-authentication state, requests a
  Prosopikon session, and appends audit;
- an opaque session delivered only through a `Secure`, `HttpOnly`,
  appropriately `SameSite` cookie and never returned through a Pistis API;
- tested invalidation for logout, expiry, device/key/binding revocation,
  recovery, and authorisation-generation changes;
- backup, restore, migration, file-permission, and corruption-recovery
  acceptance evidence; and
- a pinned Jenkins build proving the applicable tests, documentation, package
  contents, and provenance.

Missing or unknown evidence returns a deterministic typed blocker before any
host mutation or session request. Reference components, UI presence, or a
locally successful login cannot satisfy these requirements.

### Standalone service and embedding API

Pistis owns protocol challenge construction, canonical payload rendering,
response parsing and verification, challenge state transitions, trust policy,
device state, and portable public evidence. The Monas adapter maps an immutable
Prosopikon principal to the exact Pistis binding and supplies host-owned
transaction, session, and audit ports.

The embedding API uses explicit request, response, purpose, and outcome types.
It does not expose raw session tokens, cookies, private keys, database handles,
HTTP responses, or product authorisation claims. Authentication, consequential
approval, and artefact signing are separate purposes with separate policies.
Only authentication may request a browser session.

Bootstrap and enrolment cannot reuse Monas password registration, an
environment variable, a URL query value, or an API bearer as durable authority.
Until the accepted recovery and bootstrap designs are implemented, the Monas
adapter remains unavailable rather than silently falling back to a default
credential.

### CLI boundary

Commands are split by authority:

- mutation commands require an explicit local installation directory, acquire
  an exclusive lock, validate ownership and permissions, and commit through the
  same repositories and audit rules as the service;
- online ceremony commands use the embedding API and cannot bypass challenge
  purpose, expiry, binding, replay, or readiness checks;
- `evidence inspect` parses bounded untrusted input without asserting validity;
- `evidence verify` is offline, accepts explicit trust material, verifies the
  canonical signed content and policy time, and reports structured reasons; and
- `doctor` is read-only by default, redacts secrets and personal data, and
  distinguishes warnings from security blockers.

Human-readable and machine-readable output are separate stable interfaces.
Secret, capability, cookie, nonce, raw signature, provider credential, private
key, and full personal-data fields are excluded from normal output and logs.
Exit codes distinguish success, invalid evidence, blocked configuration, input
error, and internal failure.

The EPIC-10 CLI verifier is a command surface over the verifier available at
that milestone. It cannot claim the M10 detached-evidence acceptance criteria
before EPIC 12 supplies the schema, trust bundle, signing claims, and fixtures.

### Reference application

The Monas reference application extends the existing Monas login surface; it
does not introduce another server or session store. Generated test identities
and isolated state roots are mandatory for acceptance fixtures. QR and direct
transfer enter one bounded verification path. Polling reports only coarse state
and never verifies, consumes, or issues a session.

Local discovery remains an optional untrusted transport under EPIC 11.
Report-signing and detached-verification demonstrations remain blocked on EPIC
12. Absence of either capability is shown explicitly and never replaced by a
mock that appears production-ready.

### Storage, packaging, and operation

The standalone service uses SQLite with foreign keys, transactions, bounded
busy handling, schema versioning, and operator-controlled storage paths. State
files and secret-bearing configuration must be non-symlink regular files with
private permissions. Installation identity must survive documented backup and
restore, while restoration onto a second active installation is rejected or
requires an explicit recovery procedure.

The binary, configuration, systemd unit, container, and RPM/SRPM path are
release surfaces. They require versioned configuration, least-privilege
filesystem ownership, graceful shutdown, migration commands, health checks
that disclose no sensitive state, SBOM/provenance evidence, and rollback
instructions. Packaging is not complete merely because `cargo run` succeeds.

### Audit and privacy

Security mutations and audit append share one transaction. Audit follows the
minimization boundary in ADR 0009 and uses independent non-secret correlation
identifiers. Monas may project a bounded event into its operator log, but
Pistis standalone state remains the authoritative cryptographic event record.
Product applications receive only the verified host context needed for their
own authorisation and never receive a Pistis response, session token, cookie,
provider credential, or raw evidence package.

## Consequences

- A non-Synoptikon application can integrate through Pistis types without
  importing Synoptikon, Monas, or Prosopikon types.
- Monas and Synoptikon remain independent relying applications sharing inward
  Pistis contracts.
- Prosopikon remains Monas's sole local-principal and browser-session authority.
- Contract and offline-verifier work can proceed while production gates remain
  explicit and fail closed.
- EPIC 10 cannot close until EPIC 9's prerequisite protocol/session gates and
  all M8 acceptance evidence exist.
- Local discovery, detached evidence/report signing, recovery, and release
  packaging cannot be closed early under EPIC 10; their owning milestones must
  provide the required accepted decisions and fixtures.

## Alternatives considered

- Embed the in-memory Pistis authentication service in Monas: rejected because
  it lacks durable atomic completion and would create a second session map.
- Replace Prosopikon sessions with Pistis sessions: rejected because Pistis
  authentication must not become host authorisation or session authority.
- Treat the existing password CLI or HTTP routes as the Pistis demo: rejected
  because they prove a different trust and ceremony model.
- Mark report signing and offline detached verification complete with an
  ad-hoc JSON envelope: rejected because EPIC 12 owns their schema and fixtures.
- Bundle local discovery into the server without a transport review: rejected
  because discovery is untrusted and EPIC 11 owns that decision.
- Declare packaging complete from a development binary: rejected because the
  M8 release artefact includes configuration, service, migration, backup, and
  provenance obligations.

## Review evidence

The architecture review inspected EPIC 10 issues 129–134, M8 acceptance
criteria, existing Pistis ADRs and crates, and the Monas `main` branch. It
identified Monas's Axum/Yew/TLS/product authority, Prosopikon's principal and
session authority, process-scoped session invalidation, the current password
login routes, and the absence of a Pistis dependency or standalone deployment
contract.
