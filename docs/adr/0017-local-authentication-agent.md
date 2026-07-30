# ADR 0017: Local authentication agent and installation signer

- Status: Accepted
- Date: 2026-07-26
- Decision owners: Pistis maintainers
- Security review: required for each production signing provider

## Context

The CLI cannot safely own an installation private key, durable replay state, or
session authority. Passing those values through arguments, environment
variables, standard output, or an ordinary shared file would expose them to
shell history, process inspection, diagnostics, or unrelated local users.

Authentication and action approval must survive CLI process exit and agent
restart without permitting a challenge or approval to be consumed twice.
Headless scientific systems also need a transport that does not depend on a
browser or public network.

## Decision

Pistis uses one per-user local agent reached through an owner-only Unix-domain
socket. The CLI is an untrusted presentation adapter. It sends bounded canonical
requests and receives public challenge presentation plus coarse lifecycle
results. Private keys, raw session capabilities, signed mobile responses, and
complete audit records are never returned to the CLI.

The agent stores challenge state in SQLite using immediate transactions,
foreign-key enforcement, WAL durability, explicit schema ownership, and
owner-only database and directory permissions. Challenge identifiers are
unique. State transitions use expected-state predicates, and successful
approval consumption is atomic and terminal. Restart cannot restore a
consumed, cancelled, denied, failed, or expired challenge to pending.

Schema version 2 adds non-secret completion receipts and redacted audit tables
linked uniquely to the consumed challenge. It deliberately has no session
table. Signature, schema, device, binding, decision, and policy verification
complete before the commit call. The immediate commit transaction rechecks
the exact staged response and expiry, records the host correlation outcome and
audit event, and makes the ceremony consumed. Substitution, replay,
idempotency collision, audit failure, or a concurrent winner rolls the
transaction back.

One `CompletionCoordinator` loads the staged bytes, calls the mutation-free
shared-verifier adapter, generates a fresh operating-system-random idempotency
key, and supplies the unchanged bytes and verified identity facts to the
host-owned completion port. Verification and randomness failures create no
authority. The returned outcome contains only non-secret correlation facts.

Socket requests use a length-prefixed bounded canonical envelope rather than
newline or shell syntax. The server rejects unknown operations, unknown fields,
non-canonical data, oversized frames, partial frames, trailing bytes, and peer
identity or filesystem permission failures. The socket directory is never
group- or world-writable. On platforms that expose peer credentials, the
adapter verifies that the peer effective user matches the agent owner.

Installation signing is accessed only through an `InstallationSigner` trait.
The API accepts canonical bytes and returns the public key identifier and
signature; it has no private-key export method. Production macOS uses a
Keychain/Security-framework provider configured by an opaque key label. The
portable crate contains no software fallback and fails closed when no reviewed
provider is configured. Linux hardware, kernel-keyring, or Secret Service
providers require separate review and must implement the same non-export
contract.

The socket and persistence crates are framework-neutral libraries. The daemon
loop uses non-blocking acceptance, bounded per-client I/O, a lifecycle-control
port, and native peer credentials before parsing. On macOS and BSD it uses
`getpeereid`; on Linux and Android it uses `SO_PEERCRED`. Unsupported platforms
reject every peer. OS signal bridging, Keychain entitlement and access-control
configuration, and service installation remain platform packaging concerns.

Semantic dispatch depends on exactly one `AuthoritativeCeremonies` adapter.
Production completion uses one `HostCompletionPort` implemented beside the
Prosopikon authority. That host transaction owns reference lookup, generation
and revocation rechecks, single-use consumption, Prosopikon session or
exact-action authority issuance, idempotency, and both audit appends. The agent
never issues, stores, or returns session material. Composing the in-memory
reference service with the durable repository as two state machines is
prohibited.

## Consequences

- A compromised CLI process cannot request private-key export.
- A local process running as the same user remains within the threat boundary;
  biometric policy and mobile signatures still protect consequential actions.
- Owner-only permissions and bounded framing are mandatory, not deployment
  advice.
- Durable single-use behaviour can be tested across repository reopen and
  concurrent consumption.
- Host authority issuance, audit retention, and ceremony consumption cannot
  commit as partially successful operations.
- Portable tests use an explicit test signer. It is impossible to accidentally
  select that signer in production builds.
- A production daemon is not enabled until its platform peer-credential and
  signing-provider tests pass.
- Slow or incomplete clients are bounded and cannot silently disable peer
  authorisation for later requests.
