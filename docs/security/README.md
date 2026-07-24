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
