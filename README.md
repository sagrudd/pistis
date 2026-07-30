# Pistis

Pistis is a local-first cryptographic identity and trust framework. It binds
trusted external identities to device-held keys for passwordless
authentication, explicit approval, and portable verifiable evidence.

Repository bootstrap and EPIC-0 are complete. EPIC-1 establishes the typed
protocol domain, deterministic encoding, and single-use challenge lifecycle;
EPIC-2 adds ES256 cryptographic verification and the structured verification
pipeline; EPIC-3 defines GitHub trust enrolment and durable provider-neutral
identity bindings; EPIC-4 adds locally verified Google OpenID Connect
enrolment keyed by canonical issuer and stable subject. Later epics add device
registration and application integrations. ADR 0025 selects no-broker GitHub
App Device Flow for the v0.1 transport. EPIC-16 makes terminal-native
authentication and approval a release-blocking primary product surface, using
ASCII/Unicode QR exchange with the supported iOS application and requiring no
browser or web application. Android interoperability remains part of the
broader v1.0 commitment.

## Design principles

- Local-first operation without a mandatory central Pistis service.
- Device private keys never leave the device.
- External identity establishes identity; local policy grants authority.
- Signed, portable evidence is preferred to opaque sessions.
- Protocol and canonical encoding are specified before convenience transports.
- CLI users are first-class: login and action approval must work entirely from
  a terminal with a supported mobile signer.

## Project status

The canonical planning inputs are:

- [`docs/PROJECT_CHARTER.md`](docs/PROJECT_CHARTER.md)
- [`docs/MVP_RELEASE_CANDIDATE.md`](docs/MVP_RELEASE_CANDIDATE.md)
- [`docs/MILESTONE.md`](docs/MILESTONE.md)
- [`docs/TODO.md`](docs/TODO.md)

The MVP release-candidate document defines the approved `v0.1.0-rc.1`
vertical slice. [ADR 0026](docs/adr/0026-mvp-deployment-and-product-profile.md)
records the owner-approved deployment, product-session, mobile, recovery,
privacy, distribution, and licensing profile gathered during the MVP decision
review. The milestone document retains the broader `v1.0` commitment.

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
Release packaging, provenance, clean-host lifecycle, and publication gates are
defined in
[`docs/development/release-packaging.md`](docs/development/release-packaging.md)
and the
[`operator release runbook`](docs/operations/release-packaging.md). These
documents are readiness contracts; no production Pistis package or signed
v1.0 release exists yet.

The primary terminal authentication contract, deterministic ASCII/Unicode QR
profiles, and current fail-closed readiness boundary are documented in the
[`CLI development guide`](docs/development/cli-authentication.md),
[`ADR 0015`](docs/adr/0015-cli-native-authentication.md), and
[`CLI operator guide`](docs/operations/cli-authentication.md).
An interactive `pistis auth login` now keeps the QR ceremony open and polls the
owner-only local agent until the durable authority reports approval, denial, or
expiry. This removes any need to paste a response into an ordinary terminal;
deployment still requires the reviewed agent and Prosopikon host adapter.

First-device mobile enrolment uses the accepted
[`ADR 0029`](docs/adr/0029-qr-bound-app-scoped-host-trust.md) ceremony. The
protected CLI QR authenticates the exact HTTPS origin and TLS public-key pin;
the phone requires three independently displayed comparison words before it
creates an app-scoped pinned session. Operators do not install a root
certificate or change iOS Certificate Trust Settings. See the
[`mobile enrolment runbook`](docs/operations/mobile-enrolment.md).
Accepted [`ADR 0031`](docs/adr/0031-enrolment-and-product-audience-separation.md)
also binds the closed set of product audiences authorised by the administrator
at enrolment. A single installation may consequently approve the distinct
`propylaion`, `jenkins`, and `dasobjectstore` routes without confusing any of
them with the fixed enrolment-ceremony audience.

## Security

Do not report vulnerabilities in public issues. Follow
[`SECURITY.md`](SECURITY.md) to use GitHub private vulnerability reporting.

## License

Pistis Core and the public protocol implementation in this repository are
licensed under the [Mozilla Public License 2.0](LICENSE). Mnemosyne names,
logos, and application icons are reserved brand assets and are not licensed by
the MPL. ADR 0026 records the owner-approved intent for future separately
hosted mobile application repositories; that intent is subject to formal legal
review and does not revoke rights already granted for published source.
