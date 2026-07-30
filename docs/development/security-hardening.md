# Security hardening and independent review development

EPIC-14 is a release gate, not a collection of tool invocations. Automated
tests, advisory scans, lint, dependency verification, and fuzz-target
compilation produce useful engineering evidence; they do not constitute an
independent threat-model review, penetration test, privacy assessment, or
cryptographic review.

The repository currently has locked Rust and Android dependency graphs,
`cargo audit`, `cargo deny`, Android checksum verification, deterministic
protocol tests, parser/verifier fuzz targets, mobile source tests, and
fail-closed architectural contracts. There is no completed independent review,
penetration-test report, cryptographic-review report, privacy assessment,
remediation report, residual-risk register, retained live fuzz campaign, or
release-artefact mobile assessment. EPIC-14 remains open.

## Normative boundary

[ADR 0013](../adr/0013-security-assurance-and-independent-review.md) is
normative once merged. Security acceptance must preserve:

- exact source, dependency, toolchain, configuration, and artefact scope;
- separation between implementation, automated evidence, independent review,
  finding triage, risk acceptance, and release approval;
- confidential handling of exploitable findings;
- reproduction and remediation evidence for every finding;
- no open critical or high-severity finding at the release gate;
- owned, time-bounded plans for accepted medium findings; and
- explicit residual risk rather than an aggregate `secure` claim.

An agent, contributor, or CI task may prepare scope, fixtures, and evidence.
It cannot self-declare its implementation independently reviewed.

An independent reviewer is organizationally and operationally separate from
the implementation under review, receives the complete scoped material,
declares material conflicts, follows a documented method, and signs or
otherwise authenticates the final report. The project security owner—not the
implementer or CI system—accepts residual risk and approves release-candidate
progression.

## Threat-model review

Review implementation reality, not only milestone prose. Inventory:

- protected assets: device and installation keys, identity bindings,
  challenges, recovery authority, provider credentials, sessions, evidence,
  audit, policy, and release artefacts;
- actors and authorities: user, device, installation, provider, host,
  Prosopikon, administrator, recovery operator, CI/release operator, and
  relying verifier;
- boundaries: Rust core, host adapters, SQLite, broker, iOS, Android, QR,
  local network, browser, Jenkins, distribution services, and backups; and
- attacker capabilities: local/network/service spoofing, malicious input,
  device loss, dependency compromise, insider misuse, rollback, concurrency,
  replay, and evidence substitution.

Every accepted ADR and delivered adapter updates data flows, trust assumptions,
abuse cases, mitigations, test references, and residual risks. `Unknown` is a
review result requiring disposition, not implicit low risk.

Protocol attack tests include cross-purpose and cross-installation signatures,
replay/race, malformed canonical encoding and QR, signature encoding and
malleability, key-ID collision, time/expiry, OAuth/OIDC callback and token
leakage, CSRF/open redirect, malicious discovery, endpoint substitution,
recovery replay, lifecycle-generation races, and evidence-policy confusion.

## Dependency and supply-chain review

Review every build and release ecosystem:

- Rust workspace, fuzz workspace, Cargo lockfiles, build scripts, native
  libraries, registry/git sources, licences, advisories, and duplicate versions;
- Android Gradle wrapper, plugins, repositories, lockfiles, verification
  metadata, AAR/JAR native content, SDK/build tools, JDK, and container image;
- Swift/Xcode project, Swift packages if introduced, SDK/toolchain, bundled
  resources/frameworks, entitlements, privacy manifests, and signing inputs;
- Sphinx/Python and Markdown/Node documentation toolchains;
- Jenkins/Expedition tasks, installed audit tools, container digests, base
  packages, credentials, publication path, and retained artefacts; and
- external broker, host, mobile-distribution, and packaging dependencies.

`cargo audit` and `cargo deny` passing is not the complete review. Record
dependency purpose, maintenance/provenance, privilege and data access, unsafe
or native code, update policy, alternatives, known advisories, licence/source
decision, and reviewer. Android checksum metadata proves retrieved bytes match
reviewed hashes; it does not prove those bytes are safe.

New or changed dependency metadata is reviewed as source. Do not generate and
accept Gradle verification hashes, Cargo lock changes, wrapper updates, or
container pins solely to make CI green. Verify origin and expected graph first.

An SBOM is an EPIC-15 release deliverable. EPIC-14 must define and review the
complete component inventory, but must not claim that existing Cargo metadata
or a dependency tree is a release SBOM.

## Unsafe code, secrets, errors, and limits

First-party security-sensitive Rust crates currently forbid unsafe code. Review
transitive unsafe/native code separately. Any future first-party unsafe block
requires the repository's safety comment, focused tests, and specialist review.

Audit secret lifetimes and copies across provider flows, recovery, challenge
handling, mobile callbacks, process arguments/environment, memory, storage,
clipboard, screenshots, crash reports, logs, backups, and CI. Zeroization is
applied only where its guarantees and compiler/runtime limitations are
understood; it is not used as a marketing claim.

Test panic/error boundaries, poisoned/corrupt storage, allocation and parser
limits, timeouts, concurrency, rate limits, redaction, and secure defaults.
Production errors expose stable coarse reasons and independent correlation
identifiers, never bearer material or exploit details.

## Mobile security review

iOS review includes:

- Secure Enclave/Keychain access controls and invalidation;
- per-operation LocalAuthentication and fallback evidence;
- URL callback and universal-link handling;
- camera/local-network permissions;
- clipboard, screenshots, logs, crash data, backup, app groups, and storage;
- entitlements, privacy manifest, ATS/network behaviour, and release signing;
- jailbreak policy and honest assurance reporting; and
- real-device reinstall, biometric change, backgrounding, and lockout.

Android review includes:

- Keystore security level, authentication parameters, invalidation, and no
  silent StrongBox/TEE/software downgrade;
- BiometricPrompt `CryptoObject` binding;
- manifest components, exported state, permissions, intents, app links, task
  and process lifecycle, backup, logs, clipboard, screenshots, and storage;
- external-browser OAuth and WebView absence;
- network security configuration and discovery binding;
- rooted-device policy and honest assurance reporting; and
- signed release bundle/APK behaviour on supported physical devices.

Simulator/emulator tests and source lint do not prove hardware key protection,
platform UI behaviour, release signing, jailbreak/root response, backup
exclusion, or binary hardening. Review the exact candidate artefact and map its
digest to reviewed source.

## Penetration-test boundary

Independent penetration testing requires a written rules-of-engagement
agreement naming:

- exact revisions, builds, endpoints, apps, protocol versions, and exclusions;
- isolated accounts/devices/data and authorised test infrastructure;
- allowed techniques, hours, rate/concurrency, social-engineering policy, and
  denial-of-service exclusions;
- stop conditions, emergency contacts, evidence encryption/retention, and
  coordinated disclosure;
- severity methodology, report format, remediation expectations, and retest;
  and
- explicit authorisation from every affected system owner.

Scope covers the Rust service/CLI, Synoptikon and Monas adapters, provider
broker boundary, iOS, Android, QR, local discovery, recovery, evidence, and
operator surfaces that exist in the candidate. Missing production components
are blockers or documented exclusions, never automatically `not vulnerable`.

Do not target production users, provider accounts, GitHub/Google/Keeper,
unowned networks, App Store/Play services, or unrelated Mnemosyne systems.

## Cryptographic review

A qualified reviewer examines algorithms and parameter choices, canonical
encoding, domain separation, nonce/challenge generation, key identifiers,
ECDSA/COSE encoding and low-S policy, signature/verifier status rules, temporal
and revocation semantics, recovery purpose separation, trust-bundle/evidence
semantics, cross-language fixtures, and error behaviour.

Passing known-answer or conformance tests is evidence for the review, not the
review itself. Any change to signed bytes, schema, domain tag, algorithm,
identifier derivation, verification order, or historic-policy semantics
invalidates the affected review scope and requires compatibility analysis.

## Privacy review

Create a data inventory and flow/retention table for stable provider subject,
display metadata, device and assurance metadata, authentication/recovery/audit
events, server network metadata, local phone history, diagnostic/crash data,
support evidence, and CI fixtures.

For each field record purpose, authority, collection source, storage locations,
recipients, retention/deletion, backup behaviour, export, access controls, and
whether it is required or optional. Deletion must preserve legally or
scientifically necessary verification material without retaining unnecessary
profile or bearer data. Privacy review includes mobile declarations and actual
broker/host behaviour, not only application manifests.

## Findings and release gate

Use private security reporting for exploitable findings. Each finding has a
stable private identifier, affected revision/artefact, evidence, severity and
rationale, owner, remediation or explicit risk decision, target release, and
retest result. Public issues and commit messages avoid exploit details until
coordinated disclosure.

Critical/high findings block release. Medium findings require an approved,
time-bounded remediation plan and owner. Low/informational findings remain
tracked. Closing a finding requires exact-fix evidence and independent retest
where applicable; a code diff or passing generic CI alone is insufficient.

## Jenkins evidence

Jenkins should retain machine-readable and human-reviewable outputs for exact
revisions:

- advisory, licence/source, dependency graph and lock verification;
- test, lint, documentation, deterministic attack, and bounded fuzz results;
- tool and container versions/digests and candidate artefact checksums;
- mobile source/native/release-build evidence from appropriately isolated
  workers; and
- references to confidential review/remediation records without publishing
  their contents.

The current repository job installs and runs pinned `cargo-audit` and
`cargo-deny`, compiles fuzz targets, and retains its log, Cargo metadata, and
dependency tree. It does not run a live fuzz campaign, retain dedicated scan
formats, test signed mobile release artefacts, conduct a penetration test, or
approve residual risk.

Do not add a green `penetration-test` or `independent-review` stage that merely
runs existing unit tests or checks for a report filename. Human approval must
reference verified confidential evidence, reviewer identity/independence,
scope, dates, candidate digests, unresolved findings, and retest status.
