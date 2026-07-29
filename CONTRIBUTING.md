# Contributing to Pistis

Thank you for helping build Pistis. Read `AGENTS.md`, the project charter, and
the relevant GitHub issue before starting.

## Workflow

1. Discuss substantial or security-sensitive changes in an issue.
2. Create a short-lived branch using the naming rules in `AGENTS.md`.
3. Make one logical change at a time with tests and documentation.
4. Run the local quality gates.
5. Open a pull request using the repository template.

Local gates are the ordinary pull-request feedback loop. Jenkins retains
authoritative provenance for milestone/release candidates, cross-project
acceptance locksets, and explicitly governed native evidence—not every minor
commit. Compatible reviewed changes may be consolidated and qualified once at
their final integration head; their original issues, ADRs, commits, and review
history must remain traceable.

Developer Certificate of Origin sign-off (`git commit -s`) is encouraged.

## Quality gates

```console
cargo fmt --all --check
cargo run --locked -p xtask -- architecture
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo audit
cargo deny check
```

Markdown files must pass markdownlint. Local checks establish ordinary change
readiness; the exact-revision Jenkins dossier is authoritative for milestone
qualification.

Keep code hierarchical and modular according to
`docs/development/code-structure.md`. Rust files over 1,000 physical lines fail
the architecture gate unless a reviewer accepts a concrete entry in
`architecture-exceptions.txt`.

Jenkins must build documentation without Sphinx warnings and retain the
pre-rendered site. The pinned local container described in
`docs/development/documentation.md` is an optional preview. Publication to
Jenkins publishes the pre-rendered site to GitHub Pages only after all gates
pass for the current `main` revision. Do not add GitHub Actions or another
documentation deployment path.

## Compatibility and security

Protocol, schema, canonical encoding, or cryptographic changes require an ADR.
Never introduce a custom cryptographic primitive. Report security problems
privately as described in `SECURITY.md`.

## Conduct

Participation is governed by `CODE_OF_CONDUCT.md`.
