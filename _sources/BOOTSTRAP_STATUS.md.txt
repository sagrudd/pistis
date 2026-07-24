# Bootstrap status

Repository bootstrap was executed on 24 July 2026 from the authoritative
charter, milestone plan, TODO, and bootstrap contract.

## Delivered

- Repository governance: `AGENTS.md`, contribution, conduct, security, release,
  versioning, ownership, issue, and pull-request policies.
- Rust 1.90.0 / edition 2024 workspace with a maintenance-only `xtask` target.
- Formatting, clippy, tests, rustdoc, vulnerability, license, source, and
  Markdown gates in the project-owned Mnemosyne Expedition/Jenkins CI.
- Dependabot, weekly security audit, private vulnerability reporting, and
  dependency alerts.
- Branch protection requiring pull requests, code-owner review, resolved
  conversations, linear history, and preventing force-pushes and deletion.
- ADR, development, operations, protocol, and security documentation hierarchy.
- GitHub label taxonomy, M0–M15 milestones, and 178 planning issues comprising
  epics, features, tasks, and bounded subtasks.
- Idempotent planning-corpus reconciliation in
  `scripts/bootstrap_github.py`.

No Pistis product feature was implemented.

## Validation

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
- `cargo audit`
- `cargo deny check`
- `markdownlint-cli2 "**/*.md"`
- GitHub planning reconciliation rerun with zero new resources

The retained Jenkins Expedition dossier is the authoritative CI evidence.

## Conditional GitHub Project

The GitHub CLI credential available during bootstrap lacked the `read:project`
and `project` scopes, so project discovery and creation were unavailable. The
issues, labels, and milestones are complete and usable without a Project. A
project can be added later after an owner authorizes those scopes; this does not
block the contract's conditional “if available” deliverable.
