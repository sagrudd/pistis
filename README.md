# Pistis

Pistis is a local-first cryptographic identity and trust framework. It binds
trusted external identities to device-held keys for passwordless
authentication, explicit approval, and portable verifiable evidence.

Repository bootstrap and EPIC-0 are complete. EPIC-1 establishes the typed
protocol domain, deterministic encoding, and single-use challenge lifecycle;
EPIC-2 adds ES256 cryptographic verification and the structured verification
pipeline; EPIC-3 adds GitHub PKCE trust enrolment and durable provider-neutral
identity bindings. Later epics add further trust anchors and application
integrations.

## Design principles

- Local-first operation without a mandatory central Pistis service.
- Device private keys never leave the device.
- External identity establishes identity; local policy grants authority.
- Signed, portable evidence is preferred to opaque sessions.
- Protocol and canonical encoding are specified before convenience transports.

## Project status

The canonical planning inputs are:

- [`docs/PROJECT_CHARTER.md`](docs/PROJECT_CHARTER.md)
- [`docs/MILESTONE.md`](docs/MILESTONE.md)
- [`docs/TODO.md`](docs/TODO.md)

Implementation work is tracked in GitHub issues and milestones. Architectural
decisions are recorded in [`docs/adr`](docs/adr).

## Development

The project targets Rust 1.90.0 and the Rust 2024 edition. Protocol crates live
under `crates/` and are introduced only through reviewed implementation issues.

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the normative
[`AGENTS.md`](AGENTS.md) before contributing.

Continuous integration runs on the project-owned Mnemosyne
Expedition/Jenkins infrastructure. See
[`docs/development/jenkins-ci.md`](docs/development/jenkins-ci.md).

## Security

Do not report vulnerabilities in public issues. Follow
[`SECURITY.md`](SECURITY.md) to use GitHub private vulnerability reporting.

## License

Pistis is licensed under the [Mozilla Public License 2.0](LICENSE).
