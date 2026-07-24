# Contributing to Pistis

Thank you for helping build Pistis. Read `AGENTS.md`, the project charter, and
the relevant GitHub issue before starting.

## Workflow

1. Discuss substantial or security-sensitive changes in an issue.
2. Create a short-lived branch using the naming rules in `AGENTS.md`.
3. Make one logical change at a time with tests and documentation.
4. Run the local quality gates.
5. Open a pull request using the repository template.

Developer Certificate of Origin sign-off (`git commit -s`) is encouraged.

## Quality gates

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo audit
cargo deny check
```

Markdown files must pass markdownlint. CI is authoritative.

Jenkins must build documentation without Sphinx warnings and retain the
pre-rendered site. The pinned local container described in
`docs/development/documentation.md` is an optional preview. Publication to
GitHub Pages is a separate manual review step; do not add deployment
automation.

## Compatibility and security

Protocol, schema, canonical encoding, or cryptographic changes require an ADR.
Never introduce a custom cryptographic primitive. Report security problems
privately as described in `SECURITY.md`.

## Conduct

Participation is governed by `CODE_OF_CONDUCT.md`.
