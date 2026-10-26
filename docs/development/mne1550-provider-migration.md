# MNE-1550: maintained P-256 provider migration proposal

Status: specialist ADR applicability and the genuine canonical root and
SDK carrier lock outputs were independently accepted by MNE-1534 through
MNE-1525 on 26 October 2026. The exact private provider/COSE candidate passed
the component checks recorded below. Compilation, MSRV, strict, documentation
and security qualification of this canonical join remain pending.

## Source and decision

The first candidate starts from Pistis revision
`ef00ff34efbb9cfeac9298c9c77f1dc9694162cd`, as consumed by the incoming
Expedition collector and source CI graphs. Its `p256` 0.13.2 dependency reaches
`elliptic-curve` 0.13.8 and `crypto-bigint` 0.5.5. The retained collector audit
reports RUSTSEC-2026-0387 against that exact dependency.

Propose `p256` 0.14.0 with its maintained stable dependency family:
`ecdsa` 0.17.0, `primeorder` 0.14.0, `elliptic-curve` 0.14.3 and
`crypto-bigint` 0.7.10. These were observed as non-yanked releases in the
crates.io API on 26 October 2026. The new lock must establish the actual
resolution; this list is not a substitute for a resolved graph or audit.
The current 0.7.10 and elliptic-curve 0.14.3 MSRV is 1.87, within Pistis's
declared Rust 1.90.0 minimum. Do not lower that declaration or silently raise it.

The upstream security release is documented in
[RustCrypto PR 1365](https://github.com/RustCrypto/crypto-bigint/pull/1365).
Do not select the now-yanked 0.7.6 merely because it is the advisory's first
patched version. No advisory suppression or cryptographic backport is proposed.

## ADR applicability for specialist verdict

Accepted ADR 0002 selects ES256, validated SEC1 points, fixed-width signatures
and domain-separated key identifiers. It permits reviewed P-256 libraries
without pinning an implementation version. This proposal interprets a compatible
RustCrypto update as implementation of that existing decision. MNE-1534 confirmed that interpretation for the unchanged invariants below,
which MNE-1525 relayed before implementation. This verdict grants no
implementation, MSRV or security acceptance.

Preserve the public `pistis-crypto` interface: its `PublicKey` contains a private
upstream verifying key; public parsing, canonical bytes, key identifiers and
verification use Pistis types and byte slices. No upstream key type is exported
by those functions. Preserve ES256 algorithm -7, compressed 33-byte canonical
SEC1, accepted valid 33/65-byte input points, the full SHA-256 key identifier,
64-byte COSE r||s signatures, rejection of DER/high-S/invalid input, exact message
verification and non-disclosing errors. No production signing API, authority,
schema, phone ceremony, key-store or storage change is proposed.

## Smallest first implementation and qualification

After the specialist verdict, change the workspace dependency and resolved lock,
adapt only compiler-proven provider or consuming test call sites, and patch
versions of affected published crates. The intended first provider patch is
`pistis-crypto` 0.1.1; a `pistis-cose` patch is required if its dependency or
source changes. Confirm workspace constraints before choosing other versions.
Coordinate exact source/dependency coordinates with the designated Kanon writer
through MNE-1525; no local registry revision or lockset is invented here.

The first native operation must use the existing maintained AlmaLinux transport,
pinned image/toolchain, capacity checks, exclusive lease and retained terminal
evidence. It requires a separate coordinator GO. Do not run Cargo on macOS.
Set `CARGO_CACHE_AUTO_CLEAN_FREQUENCY=never` for every shared-host Cargo command.
Resolve the changed dependency graph inside that route, then run the first
meaningful provider/consumer checks before editing any further repository:

```text
cargo test --locked -p pistis-crypto -p pistis-cose
cargo check --locked -p pistis-crypto --all-targets
cargo clippy --locked -p pistis-crypto -p pistis-cose --all-targets -- -D warnings
```

Retain command start/end/exit, exact source and lock digest. Reuse the existing
RFC 6979 P-256/SHA-256 known answer, stable generator key-ID, compressed versus
uncompressed identity, wrong-message, DER, wrong-width and high-S denial tests;
exercise the actual COSE consumer tests. Add a regression only for a discovered
gap. Failure means diagnose and repair this boundary before stacking changes.
Final review also requires applicable formatting, architecture, language,
documentation, MSRV and dependency policy gates. Audit and all four deny
categories remain required on the eventual actual incoming Expedition graph.

This provider result alone cannot clear Expedition: old direct p256 consumers
and multiple pinned Prosopikon/Thesaurophylax revisions remain in its graph.
Further source scopes and the final actual consumer qualification require
explicit coordinated handoffs. Source acceptance grants no binary, release,
installation or whole Main-flow acceptance.

## Accepted lock candidate

The genuine AlmaLinux Cargo 1.94.0 selective resolution retained every original
external package identity, checksum and dependency edge. It adds 26 maintained
RustCrypto-family packages and patches only `pistis-crypto` and `pistis-cose` to
0.1.1. The exact adopted lock SHA-256 is
`2dbe74de816b6b6d025a1d7e85bd346a9b57a3f4f15372d43e5559dd131c44b4`.
Independent acceptance covers this lock's minimality, not source compilation or
security qualification. Earlier unsuccessful attempts and broad candidate locks
remain retained in MNE-1550's evidence.

The original offline cache lacked old locked archives, which caused Cargo to
prefer unrelated downloaded alternatives even with a conservative package
selection. Restoring exactly the 21 original missing archives whose versions
moved allowed the same selective command to preserve the old graph. No lock
entries, checksums or advisory policy were fabricated or suppressed.

The complete workspace still includes `crypto-bigint` 0.5.5 through unchanged
Thesaurophylax and P-256 0.13 dependencies. This first provider candidate does
not clear that path or the incoming Expedition promotion blocker.

## Canonical current-main integration

The production supplier adaptation is reused from PR 544 / revision
833993e82553be65a36bca83597ee8f88465d7b5 and its accepted ADR 0043. MNE-1550
adds the point/scalar rejection regressions and genuine minimal lock evidence.
Private revision bbd9fb29 passed 23 provider/COSE tests on both Rust 1.94 and
1.90; strict Clippy, formatting, architecture and language checks also passed.
That evidence is scoped to the exact private component inputs.

This canonical candidate retains current main aec7d036, including QR 0.1.2 and
its image dependencies, iOS code and contracts. Its root lock was genuinely generated
from that main lock; the older private 2dbe74 lock does not replace it. Existing
crypto/COSE 0.1.1 and protocol 0.2.2 allocations are retained for coordinated
review. Four-SDK/importing-consumer, affected workspace and security gates on
this new join remain required before normal delivery. No phone, installed key,
public wire format or production authority changes are included.

## Accepted canonical resolver outputs and limits

The native AlmaLinux Cargo 1.94.0 operation at 21:05:55–21:06:04 UTC on
26 October 2026 used prepared merge index tree
07b8e79a55d2f10bf6c126fbd528ba5e8671d6ac, joining current main
aec7d036fe260cab80970b8d3fa52b8fb06f1c02 and SDK parent
833993e82553be65a36bca83597ee8f88465d7b5. Both actual Cargo update commands
exited successfully. The adopted root lock is 60,581 bytes, SHA-256
52bc2a69f9ea81889078c4a10bc33191fdcc53fb9a6f97480c0f8baf4702d387.
Its 261 packages preserve every main external identity, checksum and normalised
dependency edge, retain QR 0.1.2 and add only the 26 maintained provider packages
and the existing crypto/COSE 0.1.1 and protocol 0.2.2 allocations.

The actual independent importing carrier lock was generated from that root
seed, rather than hand-edited. It is 20,845 bytes, SHA-256
add65165f00db9a80e723056e85fd2bcde957cea39629387414c7b90bae4ef64.
All 90 carrier package identities and external checksums match the root
closure, and each normalised carrier dependency edge is present in the root.
Its narrower feature selection omits optional edges in digest 0.10.7,
generic-array 0.14.9, serde 1.0.229 and zeroize 1.9.0. It imports canonical
0.1.1, crypto 0.1.1, COSE 0.1.1 and protocol 0.2.2, and contains only
crypto-bigint 0.7.10.

The original resolver wrapper remains recorded as failed: its carrier guard
incorrectly required edge equality across different feature selections.
Independent review accepted the actual retained outputs under identity and
checksum equality with normalised edge subset, without rerunning Cargo or
relabelling the failed wrapper as passed. Cleanup and protected input checks
passed. This is dependency-resolution evidence only. No canonical four-SDK,
carrier, workspace, strict, MSRV, documentation or security result is claimed.
The full root still contains crypto-bigint 0.5.5 through the unchanged
Thesaurophylax API 0.86 path.

The version/dependency coordinates remain linked to the coordinated
[Kanon SDK registration change](https://github.com/sagrudd/kanon/pull/803);
the programme coordinator and designated Kanon writer own the final integration
registration. No release lockset, installed support or release authority is
asserted by this source merge.

## Carrier hierarchy correction

The first canonical Rust 1.94 checks compiled all four SDK crates and passed
45 tests, with only the existing ignored fixture exporter. Both formatting
checks passed. The remaining operation passed the importing carrier test,
both all-target strict Clippy checks and the challenge example run, then the
architecture gate rejected the original qualification/sdk-carrier placement.
Both failed wrappers and every successful command remain retained separately.

Move the independent development carrier to tests/sdk-carrier. The existing
valid_rust_location rule in xtask/src/main.rs permits tests/**; this follows
the documented integration hierarchy without an exception or guard change.
The directory depth is unchanged, so all carrier source, manifests, fixture
imports and both generated lock files retain exactly the accepted bytes.
No additional package version is allocated for this layout-only correction;
the compatible provider task group retains the coordinated 0.1.1/0.2.2
versions. Architecture, language and Rust 1.90 checks on the final source
remain pending; earlier results keep their original source scope.

## Whole-workspace QR test adaptation

The actual all-target workspace check on source 8807b6a7 reached the QR
production_v2 test and reported two p256 0.14 API changes in its signing
fixture helper: to_encoded_point(false) becomes to_sec1_point(false), and
normalize_s returns the signature directly, so unwrap_or is removed from
the existing normalize_s call. Change only those two test calls. QR production
code, fixed fixture bytes, schemas, iOS and the qualified SDK sources remain
unchanged. Coordinate QR 0.1.3 with the designated Kanon writer; this is a
compatible test-only patch. The root lock must be genuinely regenerated from
52bc2a69, with only the workspace QR version changing; do not hand-edit it.
The actual failed workspace command and unrun Rust API documentation gate
remain recorded. QR tests and the corrected workspace/docs gates are pending.

## Agent test consumer adaptation

The genuine QR 0.1.3 root lock 23096ca4 and all 31 QR tests were independently
accepted. The subsequent workspace check reported the same two p256 0.14 API
changes in crates/pistis-agent/tests/challenge_signing.rs. Change only those
test fixture calls: use to_sec1_point(true) and the direct normalize_s result.
Coordinate the compatible agent 0.1.2 patch with the designated Kanon writer.
Agent production and platform adapters, SDK Rust bytes, QR production, schemas
and iOS remain unchanged. Apple-specific source is not qualified by the
AlmaLinux checks.

Generate the agent-own-version-only root lock from the accepted 23096ca4
input, retain the unchanged carrier lock, run the changed agent tests and
collect remaining actual workspace diagnostics using --keep-going. Do not
repeat the accepted SDK or QR tests. Rust API documentation remains unrun
until the workspace compiles; authoritative Sphinx remains a Jenkins gate.

## Batched authentication and Monas consumer adaptation

The independently accepted agent-only root lock bacc0166, formatting and all
34 agent tests retain their exact staged-source evidence. Its keep-going
workspace compile collected the remaining authentication test and Monas
workspace-p256 0.14 call failures together. Adapt only the reported SEC1 point
and signature normalisation calls; use ToSec1Point for the typed p256 PublicKey
projection. Compression choices, canonical SEC1 lengths and key identifiers
remain unchanged. Do not alter the separate Thesaurophylax API 0.86 reexport,
its old provider types, Apple source, public schemas or authority boundaries.

The Monas verifier must reject when s.normalize_s() != s, exactly matching
the already qualified SDK check. Verify the original signature; never
normalise an incoming signature into acceptance. The new focused regression
first accepts the valid low-S binding, then constructs its high-S twin using
the qualified SDK test pattern and requires the same coarse Denied error.
All existing exact-byte and hostile-path tests remain required.

Coordinate authentication 0.1.1 and Monas 0.12.1 as compatible patches with the
designated Kanon writer. Genuinely resolve only these two workspace version
changes from bacc0166, preserving all other identities, checksums and
normalised dependency edges and the carrier lock. Changed authentication and
Monas tests, the keep-going whole-workspace compile and Rust API documentation
remain pending. SDK, QR and agent successes are not rerun for wrapper status;
the full legacy-provider graph and authoritative Sphinx remain uncleared.

## Pending maintained API 0.86.1 dependency adoption

The preceding qualified stages retained API 0.86.0 at e72598aa. The next
isolated maintenance candidate uses the existing API 0.86.1 coordinate at
ad40c6d2cf1f9fbb9507c4ee687132c783e92889; no new major version or Thes source
change is introduced. Its immutable API manifest directly pins p256 0.14.0,
although the unused root application's workspace p256 remains 0.13.2.
Selected API/Core/Policy/Store dependency identity must be determined from
the actual generated consumer graph, not that root application manifest.

Monas directly imports and publicly reexports the offline_v2 types, constants,
service and byte helpers. That used production module prefix is byte-identical
to e72598aa, and the used wire_v1 module is entirely identical. Core, Policy
and Store source subtrees are also unchanged. Nevertheless the new Git revision
and package version change the nominal Rust origin of those public reexports.
Do not claim type identity or absence of externally visible changes merely
from equal bytes. Existing Monas byte bridges and canonical fixture parity
remain the intended compatibility route, subject to actual importer tests,
downstream compile, independent review and supported-promotion checks.

Keep the unreleased Monas 0.12.1 task-group allocation already coordinated
with Kanon. Generate the actual root lock from accepted 6a04789b; unify all
four selected Thes Git packages to the exact ad40/0.86.1 family and require
that old e725 and crypto-bigint 0.5.5 are absent. Do not copy a private carrier
lock, remove a dependency to hide the advisory, or suppress policy. Current
strict/MSRV evidence remains frozen against bda2d2b8; this new dependency
candidate is a separate unqualified input. Authoritative Sphinx, dependency
security and final supported delivery remain required.
