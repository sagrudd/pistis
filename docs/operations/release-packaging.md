# Release installation, upgrade, backup, and publication

This runbook describes the operator evidence expected for a Pistis release.
It is intentionally a readiness contract today: no supported production
package or signed `v1.0.0` release exists yet. Do not improvise an installation
from workspace libraries or treat a development mobile build as a release.

## Before accepting a release

Obtain the release manifest through the approved release channel and confirm
that it identifies:

- an immutable Pistis version and source commit;
- the supported host, database, iOS, Android, browser, Synoptikon, and Monas
  versions;
- every artefact filename and SHA-256 checksum;
- signatures and the documented trusted verification keys;
- SBOM and provenance documents for each distributed component;
- release notes, known limitations, migration instructions, and rollback
  constraints; and
- the completed acceptance report and release approvals.

Verify checksums and signatures before unpacking or installing anything. Stop
if an artefact is absent from the manifest, a signature cannot be validated,
the provenance names another revision, or the platform is unsupported.

## Clean-host installation

A released host package must supply the exact commands and paths for the
supported platform. Once that package exists, the clean-host procedure is:

1. start from a supported, fully patched host with a verified clock;
2. verify the package, SBOM, checksum manifest, signatures, and provenance;
3. install through the platform package manager;
4. confirm the package created the documented unprivileged service identity,
   data, configuration, log, and runtime paths with restrictive permissions;
5. provision secrets using the approved secret store, never a command-line
   argument, shell history, image layer, or repository file;
6. initialize the installation identity and database using the packaged
   command;
7. enable and start the service;
8. verify health, readiness, structured logs, database schema, TLS, trust
   policies, and clock-skew policy;
9. run `pistis doctor` when that packaged command becomes available; and
10. perform the documented enrolment, authentication, revocation, and offline
    evidence smoke tests.

The package must define these commands and paths before this procedure can be
executed. Their absence is a release blocker, not an invitation for an
operator-specific substitute.

## Backup and restore

A valid backup is one coherent recovery set containing the database snapshot,
installation identity and required keys, configuration and policy, and the
audit material required by the retention policy. Record the Pistis version,
schema version, creation time, host identity, encryption method, and checksum
manifest.

Use the packaged snapshot or quiesce procedure. Do not file-copy an active
SQLite database. Encrypt backups, restrict access separately from the running
service, and test restoration on a clean isolated host.

For a restore:

1. verify backup provenance, checksums, encryption, version, and schema;
2. install the compatible Pistis package without creating a conflicting
   installation identity;
3. keep the service stopped while restoring the complete recovery set;
4. restore documented ownership and permissions;
5. run the packaged integrity and migration checks;
6. start the service and verify health, readiness, logs, and audit continuity;
7. prove existing devices, revoked devices, trust bindings, and policies have
   the expected state; and
8. verify historic evidence offline as well as a new authentication flow.

A database-only restore is not successful if the installation keys or trust
context no longer match.

## Upgrade and rollback

Read the release-specific migration guide and confirm that the installed
version is a supported upgrade source. Before maintenance, export the current
manifest and schema version, take and verify a coherent backup, establish a
rollback point, and notify affected integrations.

Install the exact approved candidate, run only its packaged migration command,
and retain the output. Verify health, readiness, schema, configuration
compatibility, device state, revocation, provider enrolments, Synoptikon and
Monas integration, mobile reachability, and offline evidence verification.

Rollback is governed by the migration guide. Never downgrade binaries against
a schema that the older version cannot read. If rollback is not supported,
restore the complete pre-upgrade recovery set onto the approved prior version.
Preserve failed-candidate logs and evidence for incident review without
including secrets.

## iOS distribution

Accept only the build identified in the candidate manifest and App Store
Connect/TestFlight record. Verify the application identifier, marketing and
build versions, signing team, entitlements, privacy declaration, supported
devices, and release notes. Complete the native device matrix, Secure Enclave,
LocalAuthentication, camera/QR, universal-link, offline, backup-exclusion, and
accessibility checks required by the iOS design.

TestFlight availability demonstrates Apple accepted a test build; it does not
mean Pistis approved the candidate for production. Store account, signing, and
promotion actions remain owner-controlled.

## Android distribution

Accept only the AAB identified in the candidate manifest and Play Console
record. Verify application ID, version name/code, signing certificate,
manifest permissions and exported components, data-safety declaration,
supported security tiers, and release notes. Complete the physical-device
matrix, hardware-backed key, biometric, camera/QR, app-link, offline,
backup-policy, and accessibility checks required by the Android design.

An internal or closed Play track is an acceptance environment. Production
promotion requires the same revision and the approved release record.

## Documentation publication

Jenkins renders Sphinx with warnings as errors and retains
`docs-html.tar.gz`. After a successful build of the revision currently at
`main`, its isolated publisher updates `gh-pages` with that pre-rendered HTML.
Pull-request, failed, and stale-revision builds must not publish.

GitHub Pages is a static host only. Do not run a Pages build, add GitHub
Actions, upload locally rendered pages, or use the product release process to
bypass the current-`main` check. To audit or recover documentation, retrieve
the retained archive using the procedure in
[Documentation workflow](../development/documentation.md).

## Stop conditions

Stop installation, upgrade, restoration, or publication when:

- any checksum, signature, revision, or provenance comparison fails;
- required backup or rollback evidence is missing;
- a credential appears in a source tree, log, command line, or artefact;
- the package relies on undocumented paths, identities, migrations, or network
  services;
- a mobile package differs from the accepted candidate;
- security acceptance has expired or unresolved critical/high findings exist;
  or
- the exact revision lacks a required owner approval.

Quarantine affected artefacts, preserve non-secret evidence, and follow the
security reporting path in `SECURITY.md`. Never “fix” a published artefact in
place; issue a newly identified candidate.
