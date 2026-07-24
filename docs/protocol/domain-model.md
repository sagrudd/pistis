# Domain identifiers

Pistis uses distinct Rust types for identifiers that belong to different
domain concepts. An installation identifier cannot be passed where a device,
user, challenge, evidence, key, or external-identity identifier is required.
The types live in the `pistis-domain` crate and contain no transport-specific
logic.

## Canonical text

Every identifier consists of a type prefix followed by exactly 32 lowercase
ASCII hexadecimal characters:

| Type | Prefix | Example |
| --- | --- | --- |
| `InstallationId` | `installation_` | `installation_000112233445566778899aabbccddeff` |
| `UserId` | `user_` | `user_000112233445566778899aabbccddeff` |
| `DeviceId` | `device_` | `device_000112233445566778899aabbccddeff` |
| `ChallengeId` | `challenge_` | `challenge_000112233445566778899aabbccddeff` |
| `EvidenceId` | `evidence_` | `evidence_000112233445566778899aabbccddeff` |
| `KeyId` | `key_` | `key_` followed by 64 lowercase hex characters |
| `ExternalIdentityId` | `external_identity_` | `external_identity_000112233445566778899aabbccddeff` |

The prefix is part of the canonical value. Entity identifiers contain 128-bit
opaque payloads. `KeyId` contains the complete 256-bit domain-separated
SHA-256 digest defined by `pistis-crypto`, preserving the suite's 128-bit
collision-security target. Parsers reject a missing or incorrect prefix,
uppercase hexadecimal, whitespace, separators, and payloads of the wrong
length. There is no permissive or normalising parser. This fail-closed behavior
prevents identifier classes from being substituted at stringly typed
boundaries and ensures each accepted string has one representation.

Serde encodes and decodes identifiers using the canonical string form. Raw
byte-array serialization is intentionally not supported by these types.

## Payload semantics

The 128-bit payload is opaque. Constructing an identifier from bytes does not
assert that the bytes were generated safely or that the referenced entity
exists. Identifier generation, persistence, uniqueness enforcement, and
provider-specific external subject binding belong to later protocol and
storage components.

In particular, `ExternalIdentityId` is the Pistis record identifier. It does
not replace the stable provider key: GitHub identities must still retain the
provider user identifier, and Google identities must still retain the issuer
and `sub` claims.

`KeyId` identifies public key material but is not itself a key, fingerprint,
or proof of possession. The cryptographic component defines and tests the
derivation procedure before generated key identifiers are accepted.

## Error handling

Parsing errors report only the failed invariant and, when relevant, a byte
position or length. They do not retain or echo attacker-controlled input.
Callers should treat every parse failure as rejection and must not silently
replace invalid values.
