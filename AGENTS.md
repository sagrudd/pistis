# AGENTS.md

This file is normative for human and autonomous contributors.

## Repository goal

Build Pistis as a local-first cryptographic identity, authentication, approval,
and evidence system for scientific computing. Preserve the architectural
invariants in `docs/MILESTONE.md`. During bootstrap, do not implement product
features.

## Toolchain and coding standards

- Use Rust edition 2024 and MSRV 1.90.0.
- Use stable Rust, safe Rust by default, and workspace-managed dependencies.
- Any `unsafe` block requires a safety comment, focused tests, and review.
- Prefer explicit domain types, deterministic behavior, structured errors, and
  minimal public APIs.
- Cryptographic code must use reviewed libraries; never invent cryptography.
- Run rustfmt and clippy with warnings denied.

## Code structure and modularity

- Organize product code hierarchically as narrowly responsible crates, modules,
  and domain types with explicit dependency direction.
- Separate protocol, cryptography, policy, persistence, transport, and adapter
  concerns. Do not create broad utility modules or cyclic architectural
  dependencies.
- Split code whenever a file or module has multiple reasons to change,
  unrelated public responsibilities, or independently testable behavior.
- Prefer Rust source files below 1,000 physical lines. CI rejects larger files
  unless their exact path and a concrete, reviewed rationale appear in
  `architecture-exceptions.txt`.
- Treat an exception as exceptional: splitting is the default, generated code
  is not automatically exempt, and temporary exceptions require a follow-up
  issue.
- Follow `docs/development/code-structure.md` and run
  `cargo run --locked -p xtask -- architecture` before review.

## Testing

- Every task includes unit tests.
- Add integration tests at component boundaries and regression tests for every
  defect.
- Protocol behavior requires conformance fixtures and negative cases.
- Security-sensitive parsers and verifiers should be fuzzed.
- Tests must be deterministic and must not depend on public network services.

## Documentation

- Document every public API and security-relevant invariant.
- Update operator and protocol documentation with behavior changes.
- Treat stale or broken documentation as a defect.
- Record architectural and protocol decisions as numbered ADRs in `docs/adr`.
- Maintain the documentation as a Sphinx project using the Read the Docs theme.
- Jenkins is the authoritative documentation builder. Its pinned Expedition
  task must render Sphinx in a container, treat warnings as errors, and retain
  the pre-rendered HTML as dossier evidence.
- The repository's pinned Docker image is for optional local preview only; do
  not depend on globally installed Sphinx or theme packages.
- Publish only pre-rendered HTML to the `gh-pages` branch. GitHub Pages is a
  static host, not a documentation builder.
- Jenkins publishes the retained HTML automatically after every successful
  build of the current `main` revision. Pull-request and stale-revision builds
  must never publish.
- Do not add GitHub Actions or GitHub-hosted documentation build/deployment
  workflows. Jenkins remains the sole build and publication automation.

## Reviews

- All changes land through pull requests; `main` remains releasable.
- Security, cryptography, canonical encoding, protocol, and schema changes
  require specialist review and an accepted ADR before implementation.
- A reviewer verifies tests, docs, compatibility, threat impact, and issue
  acceptance notes.
- For a cross-project decision, the project owner may accept the ADR after a
  documented review that names the affected authority owners and confirms
  authority ownership, transaction atomicity, secret boundaries, negative-path
  behaviour, and exact-revision evidence. That acceptance decides the
  architecture; it does not substitute for implementation review on the
  affected code pull requests. Where repository policy prohibits author
  self-approval, the documented owner decision is the ADR acceptance record.

## Branches and commits

- Use short-lived `feature/`, `fix/`, `docs/`, `refactor/`, `security/`, or
  `release/` branches.
- Make small commits representing one logical change, written in imperative
  mood.
- Push branches, merge promptly, and delete merged local and remote branches.
- Do not accumulate unrelated work in one pull request.

## Versioning and releases

- Follow Semantic Versioning.
- PATCH covers compatible fixes, docs, and internal improvements; MINOR covers
  compatible capabilities; MAJOR covers incompatible APIs, protocols, schemas,
  or canonical encodings.
- Agents must never make a major version increment without explicit agreement
  from the project owner and development agents.
- Update versions only for completed task groups, never merely for commits.
- Releases require a clean main branch, changelog, signed tag, artifacts,
  checksums, SBOM, provenance, and passing release gates.

## Issue and pull request workflow

- Work must start from an assigned, sufficiently detailed issue.
- Issues declare identifiers, dependencies, effort, acceptance notes,
  documentation, labels, milestone, and priority.
- Link PRs with closing keywords where appropriate.
- PRs describe purpose, linked issues, tests, docs, and migrations.
- Before every repository-modifying prompt concludes: run relevant checks,
  update docs, commit, and push.

## Security and supply chain

- Follow `SECURITY.md`; never disclose vulnerabilities in public issues.
- Minimize dependencies, pin CI actions by commit, and keep lockfiles.
- Run dependency vulnerability, license, source, and advisory checks.
- Never commit secrets, credentials, production personal data, or private keys.
- Aim for hermetic, reproducible builds and retain provenance.

## Autonomous-agent expectations

- Read this file and the issue before changing files.
- Preserve user changes and inspect the working tree before staging.
- Stay within the issue scope; stop for security ambiguity or incompatible
  protocol decisions.
- Prefer evidence-backed decisions and record durable decisions in ADRs.
- Do not begin Milestone M1 until repository bootstrap is complete.

## Kanon identity contract

- This repository's Mnemosyne product or component identity must be registered
  in the authoritative Kanon registry at
  `https://github.com/sagrudd/kanon`.
- Changes to the stable identifier, display name, repository location, crate,
  package, container, binary, product-manifest or schema coordinates, supported
  host modes, dependencies, compatibility, lifecycle, aliases, deprecation, or
  replacement must include the corresponding Kanon change in the same delivery
  transaction or an explicitly linked Kanon pull request.
- Before a release, verify that this repository's Kanon identity and dependency
  declarations match the release artefacts. Once Kanon channels and locksets
  are operational, releases and maintained product branches must use the
  applicable supported channel and pin the resolved lockset identifier and
  digest.
- Do not invent, rename, or reuse Mnemosyne product identifiers locally. Do not
  treat registration in Kanon as proof that a component is installed,
  entitled, healthy, or supported by every host profile.
- If live Kanon services are unavailable, use a verified pinned Kanon snapshot
  or lockset. Do not bypass identity or compatibility validation to make a
  release proceed.
