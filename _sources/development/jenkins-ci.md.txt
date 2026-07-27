# Jenkins CI

Pistis uses the Mnemosyne Expedition/Jenkins infrastructure in `../jenkins`.
GitHub-hosted Actions are intentionally not used.

The reviewed Expedition contract is `.mnemosyne/expedition.json`. Its
repository stage runs in the digest-pinned Rust 1.90.0 image and retains the CI
log, Cargo metadata, and dependency tree as dossier evidence. The centrally
controlled task installs pinned cargo-audit, cargo-deny, and markdownlint-cli2
tooling before running the gates.

The separate `swift-core-ci-amd64` stage runs `ios/PistisCore` in a
digest-pinned official Swift Linux image and retains its test log. It does not
prove native SwiftUI, iOS SDK, Secure Enclave, LocalAuthentication, camera,
signing, archive, or TestFlight behavior. Those gates require a separately
reviewed macOS Jenkins worker with full Xcode and owner-controlled Apple
resources.

The task requires `network` to fetch those pinned tools and advisory data.
`jenkins-submit-checkout` binds a reviewed clean checkout to an exact revision
and submits it as `trusted_revision`; do not expose this policy through the
untrusted webhook path.

## Validate and submit

From `../jenkins`, validate the contract:

```sh
cargo run -p expedition-basecamp --bin expedition -- resolve \
  --policy integrations/pistis/policy.json \
  --manifest ../pistis/.mnemosyne/expedition.json
```

Submit the exact clean checkout without putting credentials in shell history:

```sh
export EXPEDITION_VAULT_PASSPHRASE
expedition jenkins-submit-checkout \
  --policy integrations/pistis/policy.json \
  --manifest ../pistis/.mnemosyne/expedition.json \
  --task-catalog integrations/pistis/task-catalog.json \
  --source-checkout ../pistis \
  --state-db .expedition/basecamp.db \
  --secrets-vault .expedition/secrets.vault \
  --jenkins-token-secret-id jenkins.api-token
unset EXPEDITION_VAULT_PASSPHRASE
```

Submission refuses a dirty checkout. Expedition derives and retains the exact
HTTPS origin and commit, and Jenkins independently verifies that revision.

For automatic pull-request status, configure Base Camp's authenticated GitHub
webhook adapter. It reports the stable `mnemosyne/expedition` commit status;
branch protection should require that context only after webhook delivery has
been verified. Until then, the retained Expedition dossier is the merge
evidence.

After every successful run, the Jenkins adapter publishes the retained Sphinx
archive only if the tested revision equals the current `main`. Configure the
least-privileged Jenkins secret-text credential `pistis-pages-publisher` with
Contents write access to this repository. The credential is isolated from the
repository-controlled CI command, and no GitHub Actions workflow is used.
