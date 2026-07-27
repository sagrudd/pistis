# Development documentation

This directory will contain workspace architecture, local setup, testing,
conformance, fuzzing, and release instructions. `CONTRIBUTING.md` defines the
current bootstrap workflow.

- `code-structure.md`: normative crate/module hierarchy and automated
  source-size guardrails.
- `fuzzing.md`: bounded parser, cryptographic, and verifier fuzz campaigns.
- `provider-conformance.md`: deterministic external-provider adapter fixtures
  and failure cases.
- `ios.md`: portable/native iOS source boundaries and validation gates.
- `android.md`: Android module boundaries, toolchain, tests, and CI gates.
- `synoptikon.md`: host boundary, login/device UX, and contract-test rules.
- `monas.md`: standalone host/CLI boundaries and cross-repository CI contract.
- `discovery.md`: untrusted discovery, secure direct exchange, fallback, and CI
  boundaries.
- `device-lifecycle.md`: multi-device, replacement, recovery, historic
  verification, and acceptance boundaries.
- `security-hardening.md`: threat, supply-chain, mobile, penetration-test,
  privacy, cryptographic-review, and evidence gates.
- `release-packaging.md`: immutable candidates, package and mobile artefacts,
  provenance, Jenkins separation, and release gates.
- `cli-authentication.md`: terminal QR, CLI-only ceremonies, response safety,
  interoperability evidence, and fail-closed delivery boundaries.
- `local-agent.md`: owner-only socket and SQLite authority, installation
  signing-provider contract, and native-adapter readiness.
