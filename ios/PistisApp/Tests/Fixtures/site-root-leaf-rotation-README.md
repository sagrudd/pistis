# Site Root leaf-rotation certificates

These public DER certificates are synthetic test fixtures generated on
2026-10-02 with temporary P-256 private keys. The private keys were discarded
and are not required by the tests.

Both generation-7 and generation-8 roots start on 2026-10-02 and expire on
2036-09-29, within Proxenos ADR 0012's ten-year maximum. The generation-7 and
generation-8 leaves start on 2026-10-02 and expire on 2026-11-01, within its
thirty-day maximum. The wrong-host leaf is signed by generation 7 and carries
only `other.example.test` in its subject alternative name.

The expired-leaf test verifies at 2027-01-01: that date is after the leaf's
expiry and before the generation-7 root's expiry. The test also reads the DER
validity bounds and asserts this relationship, so the denial isolates leaf
expiry while the configured root remains valid.

The certificates exercise local TLS trust logic only. They are not deployment
certificates and do not establish a live authority or phone trust state.
