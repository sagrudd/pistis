# Synthetic native ACK encoder vector

`RetainedSiteRootAcknowledgementTests` embeds output from the actual public
Proxenos `encode_site_root_acknowledgement_presentation_v2` encoder, not a Swift
reimplementation. Source revision `60ec3ae9657c0ea92b72e330cdfc399d678465a8`
(reviewed 0.60.1 source), `src/site_root_convergence_wire_v1.rs` SHA256
`9fd9d178bae666c56dc58ce7eccd1cb636081719721d31a3825274fb842e98c4`.

The retained emitter was executed with the existing compiled library:

```text
rustc emit.rs --edition=2024 -L dependency=/private/tmp/proxenos-convergence-primary-group/target/debug/deps --extern proxenos=/private/tmp/proxenos-convergence-primary-group/target/debug/deps/libproxenos-a2723802b1365d7a.rlib -o /private/tmp/pistis-ack-vector
/private/tmp/pistis-ack-vector
```

All inputs are synthetic. Swift tests use software P256 keys, verify the emitted
COSE signature over the unchanged native assertion, and reject mismatched
retained records before signing. A source-route assertion separately checks
existing-key/record guards and absence of creation or registration fallback.
This does not exercise physical Secure Enclave access, claim that the phone has
a retained record, or establish native transaction acceptance. The owner-side
Proxenos pending-transaction verifier remains authoritative for the native target.
