# Security documentation

Threat models, trust boundaries, cryptographic review records, privacy reviews,
and penetration-test scopes belong here. Vulnerabilities must be reported using
`SECURITY.md`, not committed here before coordinated disclosure.

## External enrolment trust boundary

GitHub OAuth and Google OpenID Connect are online only during external-identity
enrolment and explicit reauthentication. They do not participate in routine
local authentication. A provider response creates no trust until callback
correlation, provider-specific identity validation, device-key binding, and
durable commit all succeed.

Google enrolment additionally depends on authenticated discovery and rotating
public signing keys. Discovery starts at a fixed Google URI; issuer, endpoint,
algorithm, signature, audience, authorized presenter, time, and nonce checks
fail closed. Cached public metadata may improve availability but must not
extend token validity or permit an unknown key indefinitely.

Authorization codes, bearer and ID tokens, PKCE verifiers, state, nonce, and
complete provider responses cross the transient-enrolment boundary only. They
must be redacted, cleared on every terminal path, and excluded from persistent
evidence. Provider email, login, and hosted-domain values are mutable metadata,
not identity keys.

## Device-registry persistence boundary

The local device registry is security-sensitive authorization state. It stores
canonical public verification keys, derived key identifiers, assurance claims,
opaque external-identity references, and immutable lifecycle history. It has no
field or supported path for a private key. Private device keys remain on the
device and must not appear in registry files, backups, logs, or diagnostics.

Registry errors fail closed. An unavailable or corrupt database, invalid
public-key material, unknown assurance or lifecycle values, unsupported schema
version, migration inconsistency, lock failure, or stale concurrent transition
must not be interpreted as an empty registry or active device.

Suspension blocks current use and can be reversed only by an explicit,
auditable resume transition. Revocation is terminal and blocks new
authentication and approval while retaining the record needed to interpret
historic evidence. Whole-record replacement, deletion, or direct SQL must not
be used to bypass these transitions.

External identity bindings remain in a separate store. Enrolment must resolve
the binding before inserting the device and must surface cross-store failure;
an unresolved reference never establishes trust. Operational backup and
forward-only migration procedures are documented in
[Device registry operations](../operations/device-registry.md).
