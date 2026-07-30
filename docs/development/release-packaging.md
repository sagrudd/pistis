# Release packaging and provenance

This document defines the engineering evidence required before Pistis can call
an artefact a release. It implements the packaging intent in
[ADR 0014](../adr/0014-release-packaging-and-provenance.md) without claiming
that a release pipeline or signed release currently exists.

## Current repository boundary

The workspace currently builds Rust library crates, an iOS source project, and
an Android source project. It does not yet contain:

- an installable Pistis server or command-line binary;
- an RPM specification, SRPM, service unit, production configuration package,
  or supported database-migration command;
- a release container image;
- an SBOM, checksum manifest, signature bundle, or provenance statement tied
  to a release candidate;
- a signed iOS archive or an Android App Bundle ready for store submission; or
- a Jenkins task authorised to build, sign, tag, or publish product releases.

The documentation image in `docs/Dockerfile` is only an optional local Sphinx
preview environment. It is not a Pistis product image.

Until those gaps are closed and the M14 and M15 acceptance evidence is
reviewed, version `0.1.0` is development metadata and must not be described as
a production release.

## Candidate identity

Every release candidate must be derived from one clean, reviewed commit on
`main`. The candidate record must bind:

- semantic version and immutable commit identifier;
- Rust compiler, Xcode, Swift, Java, Gradle, Android SDK, and packaging tool
  versions;
- resolved dependency lockfiles and base-image digests;
- the complete output inventory and SHA-256 checksums;
- an SPDX or CycloneDX SBOM for each independently distributed component;
- build provenance identifying the reviewed Jenkins task and retained dossier;
  and
- the compatibility matrix, acceptance report, known limitations, and release
  approvals for the same revision.

Rebuilding must never silently replace an artefact under the same version. A
changed byte stream is a new candidate and requires new checksums, provenance,
tests, and approvals.

## Required artefact set

The release manager records each row as produced, deliberately not applicable,
or blocked. “Not applicable” requires a reviewed rationale.

| Surface | Candidate output | Required evidence |
| --- | --- | --- |
| Rust service/CLI | target-specific executable package | tests, supported-host declaration, SBOM, checksum, signature, provenance |
| Rust libraries | publishable crate archives | `cargo package` verification, API docs, licence files, dependency policy |
| Fedora/RHEL family | signed RPM and source RPM | clean-host install, upgrade, erase, file ownership, service-policy tests |
| Container, if required | digest-addressed OCI image | minimal runtime contents, non-root policy, SBOM, vulnerability result |
| iOS | Xcode archive and store submission | native tests, signing identity, entitlements, privacy metadata, TestFlight evidence |
| Android | signed AAB and store submission | release tests, signing identity, manifest review, Play-track evidence |
| Documentation | pre-rendered Sphinx HTML | warning-free Jenkins build and retained `docs-html.tar.gz` |

Crates are not publishable merely because they compile. Every public crate
needs an accurate description, repository and licence metadata, a deliberate
public API, documentation, and a successful `cargo package --list` and
`cargo package` inspection. Internal crates should remain unpublished until
their distribution role is explicitly approved.

## Host lifecycle acceptance

Test installation on a clean instance of every supported operating-system
version. The retained log must show:

1. package signature and checksum verification;
2. creation of the dedicated runtime identity, directories, permissions, and
   configuration with no embedded secret;
3. database initialization and schema-version verification;
4. service startup plus health and readiness checks;
5. an authentication and offline-evidence verification smoke test; and
6. removal behaviour, including which operator data is deliberately retained.

The upgrade exercise starts from the immediately preceding candidate with
representative enrolled devices, trust bindings, policies, challenges, and
evidence. Back up before migration, apply the upgrade, verify the migrated
state, and exercise rollback or restore. A successful process must preserve
device and evidence semantics, not merely start a process.

Backup and restore testing must define the transactional boundary between the
database, installation identity and keys, configuration, and retained audit
evidence. Restore into a clean host, verify ownership and permissions, and
prove authentication, revocation, and historic evidence verification. Never
copy an active SQLite database without the persistence layer's supported
snapshot procedure.

## Mobile distribution

iOS and Android candidates must implement the approved application designs and
pass the shared protocol conformance suite. Portable-core tests on Linux and
source compilation are useful CI evidence, but they do not prove native
framework behaviour, device security, release signing, or store acceptance.

Signing keys, App Store Connect credentials, Play Console credentials, and
recovery material belong in owner-controlled credential stores. They must not
enter the repository, build logs, pull-request jobs, or general-purpose
developer environments. A store submission records the source revision,
marketing/build version, signing identity or certificate fingerprint,
entitlements/manifest, privacy declarations, exported archive checksum, test
track, and resulting store build identifier.

TestFlight and Play internal/closed tracks are acceptance environments, not
public-release proof. Promotion requires the same candidate to have completed
the M15 matrix and received all required approvals.

## Jenkins separation

The existing Expedition/Jenkins task is authoritative for repository CI and
Sphinx publication. Its successful current-`main` documentation publisher may
update `gh-pages`; pull-request and stale-revision builds may not publish.

Product release automation must be introduced as separately reviewed,
centrally controlled tasks:

- an unprivileged candidate task may build, test, package, generate SBOMs and
  checksums, and retain immutable dossier evidence;
- platform signing tasks consume only validated candidate outputs and expose
  narrowly scoped credentials to fixed commands;
- publication and tagging tasks require the exact approved revision, protected
  release-manager authorisation, and successful acceptance evidence; and
- repository-controlled commands and pull-request builds must never receive
  signing or publication credentials.

Do not retrofit product credentials into `.mnemosyne/expedition.json`, the
documentation publisher, or a GitHub Actions workflow. Any future Jenkins
change must be reviewed in the Jenkins repository and tested without implying
that an unexecuted task produced release evidence.

## Release gate

The release manager may propose `v1.0.0` only after all M14 deliverables and
the complete M15 acceptance matrix are revision-bound and retained. The final
record includes all named approvals, security-review disposition, supported
platforms, reproducibility result, artefact inventory, SBOMs, checksums,
signatures, provenance, migration guidance, release notes, and public security
contact.

Creating a tag, uploading a crate, promoting a mobile build, or publishing a
package is a release action. Preparation documents and dry runs do not
authorise those actions.
