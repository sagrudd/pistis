# Base Camp vault cross-product fixture

`contract.json` is the closed, secret-free interoperability manifest for
Pistis issue #501, Thesaurophylax successor revision `eff757e`, and the linked
Monas routes. It is suitable for direct consumption by each product's contract
tests.

The two `qr` objects are the complete QR payloads. They intentionally contain
no origin, reference, capability, challenge, proof or ciphertext. The ordered
tag arrays name the exact canonical TLVs after each ASCII/NUL prefix. The
presentation and submission arrays exclude the outer transport `schema`, so
their counts remain exactly thirteen and eight.

`migration-vector.json` and `successor-vector.json` are executable, explicitly
test-only vectors. Each contains the exact canonical QR JSON, presentation
JSON, submission JSON, deterministic P-256 inputs, canonical challenge,
COSE signing structure and valid raw signature, old 60-byte record, record
digest, fixed AES-GCM nonces, rewrapped 60-byte record and expected empty-204
result. Pistis loads these checked-in files and compares every produced byte;
the tests never rewrite or regenerate repository fixtures.

Pinned SHA-256 digests for cross-product vendoring are:

- `migration-vector.json`:
  `d9de2ec82a1c3fec93134f06aa5e2b4345bb7575631feeee3eaf0d12d5e59773`
- `successor-vector.json`:
  `5bc90b25325a2f43229524325c12f41542e70034e18bc70fe357e63bf7e8cbd1`

The vectors exercise QR classification, retained origin/SPKI fixed-path GET,
complete challenge validation, deterministic signing/unwrap/rewrap and
empty-204 POST. They do not claim physical Secure Enclave, Face ID, App
Attest or Thesaurophylax durable-delivery acceptance, and their private test
scalars and plaintext bytes must never be reused outside automated tests.
