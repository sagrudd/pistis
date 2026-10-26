# MNE-1550: maintained P-256 provider migration proposal

Status: proposed; specialist applicability review pending. No implementation
or qualification is claimed by this document.

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
RustCrypto update as implementation of that existing decision. The specialist
must confirm that interpretation before source implementation, or require a
separate accepted migration ADR. Author interpretation alone is insufficient.

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
