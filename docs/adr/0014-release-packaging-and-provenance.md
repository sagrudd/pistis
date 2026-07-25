# ADR 0014: Release packaging, publication, and provenance

- Status: Accepted
- Date: 2026-07-24
- Owners: Pistis release, Rust, iOS, Android, operations, security, Jenkins,
  Synoptikon, Monas, and documentation

## Context

EPIC 15 contains release artefacts, publication, acceptance, tagging, and
continuous maintenance tasks. The repository currently identifies itself as
version `0.0.0`, has no RPM specification, systemd unit, release SBOM, signed
release manifest, crate publication configuration, or protected mobile
publication pipeline. Jenkins runs pinned source checks and documentation
publication, but its current Pistis integration is a development CI manifest,
not a credential-isolated release pipeline.

Rust, iOS, and Android development artefacts exist, but unsigned or debug
mobile builds are not store releases. A dependency listing is not a release
SBOM. A locally built binary is not an RPM. A Git commit or unverified tag is
not release provenance.

EPIC 15 is downstream of every product milestone and ADR 0013's independent
security gate. Publishing incomplete or unapproved artefacts under `v1.0.0`
would make an irreversible compatibility and trust claim.

## Decision

### Release identity and immutability

A release candidate is identified by:

- one exact full source revision on a clean protected `main`;
- one SemVer version shared by the repository, Rust packages, mobile marketing
  versions, package metadata, documentation, protocol compatibility
  declaration, and release manifest;
- immutable lockfiles and reviewed dependency revisions;
- an exact Jenkins release-pipeline definition and pinned build environments;
  and
- a unique candidate identifier that is never reused after inputs change.

The candidate source tree, generated inputs, toolchain and container digests,
configuration schema, dependency locks, and build instructions are immutable.
Any relevant change creates a new candidate and invalidates affected approval
or reproducibility evidence.

`v1.0.0` is created only after final acceptance. It is an annotated,
cryptographically signed tag resolving to the approved candidate revision.
Tags and published version numbers are never moved or reused.

### Build, approval, signing, and publication are separate

The release workflow has four explicit phases:

1. **assemble** builds unsigned or locally signed candidate artefacts without
   publication credentials;
2. **verify** checks package contents, tests, acceptance evidence,
   reproducibility, SBOMs, checksums, provenance inputs, and security readiness;
3. **approve and sign** verifies required human approvals for the exact
   candidate and signs immutable digests in an isolated protected task; and
4. **publish** transfers only those approved digests to their declared
   repositories or stores and records the resulting immutable references.

Failure or cancellation in one phase cannot silently advance another. Retry is
idempotent for the same digest. A changed artefact returns to assembly.

Pull-request, branch, fork, stale-revision, locally modified, and ordinary
`main` CI never receives release, crate-registry, package-signing, App Store,
TestFlight, Play, upload-key, or tag-signing credentials. Protected release
tasks verify exact `main` or signed-tag ancestry and required approvals before
credential access.

Jenkins is the authoritative release orchestrator. GitHub is source hosting,
release metadata hosting, and static documentation hosting; GitHub Actions are
not introduced for build or publication.

### Release manifest and provenance graph

One machine-checkable release manifest binds:

- version, candidate and source revision;
- repository and clean-tree proof;
- protocol and configuration versions;
- Jenkins pipeline, task, toolchain, SDK, and container digests;
- dependency lock and source-input digests;
- each artefact's kind, platform, architecture, filename, media type, size,
  SHA-256 digest, and signing identity reference;
- package contents and runtime dependency declarations;
- per-artefact SBOM and provenance digests;
- test, acceptance, security, reproducibility, and documentation evidence;
- approval identities and authenticated timestamps;
- publication target and immutable result reference; and
- known limitations and compatibility declaration.

The manifest contains no secret, private key, signing token, store credential,
session cookie, provisioning profile, or production personal data. Provenance
uses an established attestable format where supported and records enough
material to relate source, builder, inputs, commands, and outputs without
claiming a stronger builder trust level than Jenkins provides.

Checksums are generated before signing. Signatures cover immutable digests and
the release manifest, not mutable filenames or web pages alone.

### Artefact matrix

The release inventory distinguishes:

- Rust source crates intended for registry publication;
- standalone and administrative binaries;
- RPM and SRPM packages, specification, migrations, configuration, systemd
  unit, licence, and documentation;
- iOS archive and submitted store/TestFlight build;
- Android signed AAB and submitted Play build;
- pre-rendered Sphinx/Read the Docs HTML;
- protocol schemas and conformance fixtures;
- SBOM, checksum, signature, provenance, compatibility, migration, acceptance,
  and release-note documents.

Every artefact has an explicit owner, version, supported target, installation
boundary, and verification procedure. Development-only crates and reference
components are excluded or clearly marked; workspace membership does not imply
publication.

Rust crates are published in dependency order only after `cargo package`
contents and builds from the package archive pass. Registry metadata,
licensing, README, repository, minimum Rust version, features, and public API
versions are reviewed.

RPM builds occur from the SRPM in a clean supported build root. Installation,
upgrade, rollback, uninstall, file ownership and modes, service hardening,
migration, backup/restore, configuration preservation, and offline package
verification are tested on supported clean hosts. RPM/SRPM work is coordinated
with the Phoreus packaging path but does not make Phoreus a runtime dependency.

Mobile artefacts are built with release configuration on governed native
builders. Source revision, project settings, entitlements/manifest, SDK,
dependency locks, archive/AAB digest, signing identity, store processing,
privacy declarations, export compliance, tester track, and crash-symbol
custody are retained. App Store or Play processing may change the distributable
binary; store-issued identifiers and checksums are recorded rather than
claiming bit-for-bit equivalence to the uploaded archive.

### SBOM and dependency evidence

Each independently deployable artefact receives a machine-readable SBOM using
a documented current SPDX or CycloneDX profile. It includes direct, transitive,
native, bundled, generated, runtime, mobile, container, and documentation
components applicable to that artefact, with versions, sources, licences, and
relationships.

The SBOM is generated from the final packaged contents and reconciled against
lockfiles and package inspection. It is not accepted merely because an SBOM
tool exited successfully. Vulnerability results are time-stamped evidence
separate from the immutable SBOM.

### Reproducibility

Rust, source-package, documentation, fixture, and other deterministic
artefacts target bit-for-bit reproduction in a second clean build environment.
The comparison records both digests and all declared inputs.

Where platform signing, timestamps, store processing, or proprietary native
toolchains prevent byte identity, the release documents the nondeterministic
fields and verifies reproducible unsigned payloads, normalized contents,
source/settings/archive correspondence, and signature/store provenance.
Calling such artefacts reproducible without this qualification is prohibited.

### Acceptance and approval

The M15 matrix runs against the exact packaged candidate, not a developer
checkout. Every scenario records platform, device or host, configuration,
input fixture, expected and observed result, artefact digest, source revision,
time, operator, and retained evidence. Unsupported, blocked, skipped, or
untested is not passed.

Release approval requires authenticated decisions from the product,
Rust/backend, iOS, Android, Synoptikon, security, and release owners named by
M15. Approvals bind the exact manifest digest and expire when relevant inputs
change. The `pistis-assurance` security readiness result must be `Ready`; a
blocked or absent result cannot be overridden by the release pipeline.

### Publication and rollback

Publication order minimizes irreversible claims: documentation and candidate
packages may be staged privately; registry, package, mobile-store, public
release, and signed tag actions occur only after final approval. Each publisher
uses a least-privileged credential isolated to its target.

Partial publication stops and produces a conspicuous incident record. It does
not overwrite a published version. Recovery either completes publication of
the identical approved digests or issues a new version with corrected
artefacts and release notes.

Rollback does not mean revoking historic signatures or moving a tag. Operators
receive tested package downgrade/restore guidance, migration compatibility,
mobile emergency-release procedures, protocol disablement policy, and
revocation or advisory metadata.

### Smallest honest delivery slice

Before product and security gates are complete, EPIC 15 may deliver:

- a framework-neutral release-manifest and readiness contract;
- deterministic version, source-revision, artefact-digest, evidence,
  approval, and publication-state validation;
- credential-free candidate packaging prototypes;
- SBOM generation and package-content reconciliation for existing artefacts;
- RPM specification and service/configuration prototypes explicitly marked
  non-release;
- Jenkins release-task definitions that remain disabled or blocked without
  protected credentials and approvals; and
- installation, upgrade, backup/restore, and reproducibility test harnesses.

This work reports blockers and cannot publish crates, mobile builds, packages,
tags, or `v1.0.0`.

## Consequences

- Every public artefact is traceable to one reviewed candidate and manifest.
- Build success, package creation, signing, and publication remain distinct
  facts.
- Release credentials never enter ordinary CI or pull-request jobs.
- Reproducibility claims account honestly for native signing and store
  processing.
- EPIC 15 cannot close until all prior product and security gates, packaged
  acceptance, external store/account prerequisites, signed approvals,
  publication records, and the final signed tag exist.

## Alternatives considered

- Publish crates and mobile builds incrementally from feature branches:
  rejected because revisions, compatibility, and approvals would diverge.
- Use a GitHub-hosted release workflow: rejected because Jenkins is the
  authoritative project automation and GitHub-hosted CI is out of scope.
- Treat a dependency tree as an SBOM: rejected because it does not describe the
  final packaged artefact or all ecosystems.
- Sign mutable filenames before computing contents: rejected because signatures
  must bind immutable digests.
- Claim mobile store builds are bit-reproducible from uploaded archives:
  rejected because store processing and signing require qualified provenance.
- Tag before acceptance and move the tag later: rejected because release tags
  are immutable trust statements.
- Give release credentials to normal `main` CI: rejected because unapproved
  changes or task compromise could publish irreversibly.

## Review evidence

The architecture audit inspected EPIC 15 issues 163–179, M14 and M15
acceptance criteria, repository versioning and release rules, current Rust,
iOS, Android and documentation artefacts, the pinned Expedition manifest, and
the sibling Jenkins Pistis integration. It found a development CI foundation
but no release package set, SBOM, provenance graph, protected signing and
publication stages, packaged acceptance record, release approvals, or signed
tag. `VERSION` remains `0.0.0`.
