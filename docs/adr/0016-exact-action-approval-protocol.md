# ADR 0016: Exact-action approval protocol

- Status: Accepted
- Date: 2026-07-26
- Decision owners: Pistis maintainers
- Security review: required before mobile enablement

## Context

Authentication version 1 has the fixed action `authenticate-session`. Its
display-context digest cannot tell a mobile user which command, executable,
working directory, environment, or resources will be used. Reinterpreting that
challenge as action approval would permit consent substitution.

Hashing only an argument vector is also insufficient. Path lookup can select a
different executable, a binary can change after approval, working directory and
environment can change behaviour, and separately opened resources create
time-of-check/time-of-use gaps.

## Decision

Pistis adds an independent version 2 exact-action protocol. It does not modify,
downgrade to, or share purpose constants with version 1 session
authentication.

The signed challenge contains a closed canonical action descriptor and the
existing installation, user, identity, nonce, expiry, fingerprint, and
audience bindings. The descriptor contains:

- an absolute resolved executable path and SHA-256 digest;
- the ordered argument vector with argument boundaries preserved;
- an absolute resolved working directory;
- an ordered allow-list of explicitly disclosed, non-secret environment
  bindings; and
- ordered typed resource bindings with stable identifiers and optional
  SHA-256 content digests.

All collections are bounded, sorted where order is not semantic, duplicate
free, control-character free, and encoded as deterministic CBOR under the
purpose `pistis.action-descriptor.v2`. Challenge and response purposes are
`pistis.action-approval-challenge.v2` and
`pistis.action-approval-response.v2`. The response binds the SHA-256 digest of
the exact canonical challenge. Unknown fields and version or purpose
substitution fail closed.

Approval grants authority only to an agent-controlled execution attempt. The
agent re-resolves and re-hashes the executable, verifies the working directory,
environment allow-list, resources, challenge identity, expiry, and single-use
state immediately before execution. The CLI never executes an approved command
by reconstructing a shell string. Arguments remain an exact vector and shell
expansion is never implicit.

Environment values in a descriptor are displayed and signed, so secrets are
forbidden. Secret injection requires a separately governed local agent
facility and is outside this protocol.

Mobile applications must render the complete descriptor, distinguish login
from action approval, require explicit approval, and reject unknown or v1
action forms before production enablement.

## Consequences

- Existing v1 login fixtures and implementations remain compatible.
- A v1 response cannot satisfy a v2 action challenge.
- Argument, executable, directory, environment, resource, purpose, and
  challenge substitution are independently detectable.
- Approval can be denied when stable resource identity or executable hashing
  is unavailable; convenience does not weaken the binding.
- Platform agents need careful, platform-specific execution and file-identity
  adapters. The portable crate defines and tests the fail-closed boundary but
  does not claim operating-system process containment.
- Production use remains blocked until both mobile clients and the durable
  single-use backend implement this accepted schema.
