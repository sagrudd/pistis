# Jenkins CI

Pistis uses the Mnemosyne Expedition/Jenkins infrastructure in `../jenkins`.
GitHub-hosted Actions are intentionally not used.

## Qualification strategy

Local validation is the fast feedback loop. Contributors run formatting,
locked tests, warnings-denied lint, architecture, fuzz, applicable mobile
source tests, and containerised Sphinx checks before publishing a candidate.
Do not submit a Jenkins Expedition merely to discover a defect that these
local gates cover.

Retained Jenkins provenance attaches to:

- milestone and release-candidate heads;
- cross-project acceptance locksets; and
- tasks whose acceptance explicitly requires governed native evidence.

Routine documentation, refactoring, and narrowly scoped fixes do not each need
a separate dossier. Compatible reviewed pull requests may be consolidated on
one short-lived milestone integration branch. Preserve their issue, commit,
ADR, and specialist-review trace; run the complete local suite once on the
combined head; then submit one exact-revision Expedition. If that head changes,
cancel the superseded run through the supported audited control path and
qualify only the new final candidate.

This policy reduces redundant queue work. It does not weaken review,
deterministic-test, branch, or security requirements, and it does not permit a
stale or different revision to stand as milestone evidence.

The reviewed Expedition contract is `.mnemosyne/expedition.json`. Its
repository stage runs in the digest-pinned Rust 1.90.0 image and retains the CI
log, Cargo metadata, and dependency tree as dossier evidence. The centrally
controlled task installs pinned cargo-audit, cargo-deny, and markdownlint-cli2
tooling before running the gates.

The separate `swift-core-ci-amd64` stage uses the digest-pinned combined
Rust 1.94.0 and Swift 6.2.3 image at
`127.0.0.1:5000/jenkins-pistis-source`. Its OCI manifest digest is
`sha256:8d2d8019589e8e5839f84f9b7294e1f08b92187c19979ad6547f50bbe2f821ea`.
The approved task catalogue must bind the QR example builds, PistisCore and
RegressionHarness tests, both source simulations, and retained result logs.
Changing the image alone does not establish that catalogue binding or a
successful Expedition. These source checks do not
prove native SwiftUI, iOS SDK, Secure Enclave, LocalAuthentication, camera,
signing, archive, or TestFlight behaviour. Those gates require a separately
reviewed macOS Jenkins worker with full Xcode and owner-controlled Apple
resources.

The image is published in the NUC's local registry. The existing adapter label
`expedition && linux && amd64 && docker` currently selects the sole configured
agent, `das-basecamp-amd64`; the controller has no executors. Before dispatch,
recheck that this topology still selects only the NUC at `192.168.0.193`, and
retain the actual job node and Docker daemon identity. Another eligible host
must not silently resolve its own loopback registry. The source manifest adds
no node-selector field and makes no other-host support claim. Dispatch also
requires a measured disk budget for all four stages and the existing reserve.

The task requires `network` to fetch those pinned tools and advisory data.
The manifest requests `trusted_revision`. The GitHub webhook path is
`untrusted` and cannot qualify this policy or produce its required status.
The old `jenkins-submit-checkout` helper is test-only; it is not a production
command.

## Validate the contract

From `../jenkins`, resolve the contract without submitting an Expedition:

```sh
cargo run -p expedition-basecamp --bin expedition -- resolve \
  --policy integrations/pistis/policy.json \
  --manifest ../pistis/.mnemosyne/expedition.json
```

## Qualify an exact reviewed source

Use Base Camp's [protected ADR-0012 source-qualification flow](https://github.com/sagrudd/jenkins/blob/main/docs/adr/0012-monas-exact-source-qualification.md).
An authorised installation owner must first install an immutable admission for
the exact reviewed repository, commit, tree and review ref. Its protected
evidence binds the original source manifest bytes, reviewed policy and task
catalogue, resolved plan, installation configuration and service-owned clean
checkout. An admission for another revision cannot be reused.

The existing same-origin Base Camp browser session is freshly revalidated
through Monas/Pistis for the `release_owner` role on each protected action.
Inspect and confirm the admission, then separately inspect and confirm its
dispatch. The requests select only the admission ID and the returned
inspection digest; they do not supply a checkout path, manifest, trust level,
credential or verdict. Keep the browser session cookie in the browser.
Jenkins independently verifies and runs the admitted immutable revision.

Only after a real, complete terminal dossier is retained can the separate
protected status inspection and confirmation bind a derived classic
`mnemosyne/expedition` commit-status intent for that exact revision. Delivery
also requires the accepted, installed Thesaurophylax exact-source status
projection and its current provider authority. A queued Expedition, a retained
dossier for another revision or a GitHub Check Run does not satisfy this strict
status requirement. Missing or mismatched admission, review, configuration,
terminal evidence or provider authority leaves the pull request blocked.

After every successful run, the Jenkins adapter publishes the retained Sphinx
archive only if the tested revision equals the current `main`. Configure the
least-privileged Jenkins secret-text credential `pistis-pages-publisher` with
Contents write access to this repository. The credential is isolated from the
repository-controlled CI command, and no GitHub Actions workflow is used.
