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

## Reviews

- All changes land through pull requests; `main` remains releasable.
- Security, cryptography, canonical encoding, protocol, and schema changes
  require specialist review and an accepted ADR before implementation.
- A reviewer verifies tests, docs, compatibility, threat impact, and issue
  acceptance notes.

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
