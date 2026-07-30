# First-device presentation fixtures

These synthetic, secret-free test fixtures freeze accepted ADR 0028's
deterministic-CBOR version-3/kind-3 outer frame, signed presentation,
authority descriptor, and `PISTIS1` text. The P-256 scalar is deliberately
public and compromised.

Rust and Swift consume `presentation-positive.json`. Negative cases are
defined as deterministic mutations of those exact bytes so both
implementations test identical downgrade, kind-confusion, signature,
truncation, configuration, and exclusive-expiry failures.

No fixture QR is a valid administrator invitation and it must never be
presented as deployment evidence.
