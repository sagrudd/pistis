# Exact-action approval protocol

ADR 0016 defines the additive version 2 protocol used to approve a command
without weakening version 1 login. V1 always means `authenticate-session`; it
cannot be interpreted as action authority.

## Canonical action descriptor

`pistis.action-descriptor.v2` is a closed deterministic-CBOR map:

| Field | Meaning |
| --- | --- |
| `0` | version `2` |
| `1` | exact purpose `pistis.action-descriptor.v2` |
| `2` | resolved absolute POSIX executable path |
| `3` | 32-byte SHA-256 executable-content digest |
| `4` | ordered argument text array, including argument zero |
| `5` | resolved absolute POSIX working directory |
| `6` | sorted environment-binding array |
| `7` | sorted resource-binding array |

An environment binding is the closed map `{0: name, 1: value}`. Names use
portable uppercase environment syntax. Values are explicitly disclosed and
must not contain secrets. At most 32 bindings are allowed.

A resource binding is the closed map `{0: kind, 1: identifier, 2: digest}`.
Kinds are input `1`, output `2`, and reference `3`. The digest is either a
32-byte SHA-256 value or null when content does not yet exist or cannot be
immutably bound. At most 64 sorted unique resources are allowed.

There must be between 1 and 128 arguments. Text, path, collection, nesting, and
total canonical-message bounds are enforced before any signature or policy
decision. Arguments are data, never a reconstructed shell command.

## Challenge

`pistis.action-approval-challenge.v2` is a closed map:

| Field | Meaning |
| --- | --- |
| `0`, `1` | version `2` and exact challenge purpose |
| `2`, `3` | issuer-controlled issue and exclusive expiry times |
| `4`, `5` | installation and installation signing-key identifiers |
| `6`, `7` | single-use challenge identifier and 256-bit nonce |
| `8`, `9` | local user and required external identity |
| `10` | installation-scoped audience |
| `11`, `12` | installation and local-user display names |
| `13` | installation fingerprint |
| `14` | exact canonical descriptor bytes |

The installation signature covers the complete canonical challenge. Mobile
clients must decode field 14 as the closed descriptor above and show its
complete security-relevant meaning before accepting biometric approval.

## Response

`pistis.action-approval-response.v2` parallels the authentication response but
uses a distinct version and purpose. It contains response and user-verification
times, installation and device-key identifiers, challenge identifier, nonce,
SHA-256 of the exact canonical challenge, local user, device, external
identity, and explicit `approved` or `denied` decision.

The response never supplies authoritative expiry. The durable host verifier
uses its stored challenge and consumes approval atomically. A v1 login response,
different descriptor, changed argument boundary, executable, directory,
environment, resource, nonce, user, installation, or challenge fails binding.

## Execution boundary

Approval is not a bearer token and does not cause the CLI to run a shell.
Immediately before execution, the local agent:

1. atomically consumes the verified single-use approval;
2. checks its exclusive expiry;
3. compares the approved and requested descriptors;
4. re-resolves and re-hashes all mutable platform bindings; and
5. invokes the resolved executable directly with the exact argument vector and
   allow-listed environment.

Consumption happens before revalidation. A failed or changed attempt cannot be
replayed after modifying the host. Platform adapters must fail when they cannot
establish stable executable or resource identity.

The portable implementation provides schema and execution-boundary tests. It
does not yet constitute a durable agent or mobile implementation.
