# Exact installed Monas receipt HTTP boundary

The contract values are transcribed from canonical Monas 0.124.9
`03f7877440581b41d83e333fbadb52a1d8c3f020`, file
`crates/monas-server/src/site_root_bundle_receipt_unlock_relay.rs`:

- line44: `SUBMISSION_SCHEMA`;
- lines147–160: `SubmissionRequest`, `deny_unknown_fields`, nine `String` fields;
- lines236–250: exact media-type check and JSON decoding precede `slot.take()`;
- lines436–440: `is_json` compares the header to `Some("application/json")`.

The whole-file SHA-256 in `contract.json` was measured with:

```sh
git show 03f7877440581b41d83e333fbadb52a1d8c3f020:crates/monas-server/src/site_root_bundle_receipt_unlock_relay.rs | shasum -a 256
```

The native Swift test captures the actual `submitBundleReceiptUnlock` request.
Its isolated URLProtocol adapter admits only this exact media type, field set,
string value types and schema; it returns a synthetic202 or rejection400/403.
The previous charset-bearing header is rejected400. Missing/extra fields deny.
No public network, host, real proof or custody state is involved.

This is source-referenced HTTP admission conformance, not execution of the Rust
server, cryptographic verification, complete duplicate-field parser equivalence,
or physical unlock qualification. Schema mismatch is403 after structural JSON
admission in the real server; a media-type/JSON rejection400 precedes pending
state consumption. The test must not interpret synthetic202 as custody evidence.
