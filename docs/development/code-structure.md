# Code structure and modularity

Pistis code is organized as a hierarchy of narrowly responsible crates,
modules, and types. Repository layout communicates ownership and dependency
direction; it is not merely a place to accumulate implementation.

## Required structure

- Put product Rust code in `crates/<crate>/src`.
- Put crate integration tests, benchmarks, and examples in their corresponding
  `tests`, `benches`, and `examples` directories.
- Keep transport, persistence, cryptography, protocol, and policy concerns in
  separate modules or crates with explicit interfaces.
- Prefer cohesive domain modules and private implementation details over broad
  utility modules or shared mutable state.
- Keep dependencies directed from adapters toward stable domain abstractions.
  Domain crates must not depend on web frameworks, storage engines, or CI
  providers.
- Split a module when it gains multiple reasons to change, unrelated public
  responsibilities, or independently testable behavior.

## Source-file size

Rust source files should remain below 1,000 physical lines, including tests and
documentation. The limit is a guardrail, not a target: smaller cohesive files
are preferred.

An exception is permitted only when splitting would materially damage
readability, auditability, generated-code integrity, or a normative table.
Add the exact relative path and a concrete rationale to
`architecture-exceptions.txt`. Exceptions require explicit reviewer approval
and should link to a follow-up issue when the condition is temporary.

Generated sources are not automatically exempt. Prefer generating structured
modules or data assets rather than one oversized compilation unit.

## Local verification

Run:

```console
cargo run --locked -p xtask -- architecture
```

The guardrail scans every Rust source outside build-output directories. It
rejects misplaced source files, files over 1,000 lines without a documented
exception, malformed exceptions, and duplicate exception entries. Jenkins
runs the same command before formatting, linting, and tests.
