# Local authentication agent

ADR 0017 separates the terminal process from durable authentication authority.
The `pistis-agent` crate provides portable building blocks; it is not yet an
installed daemon.

## Storage contract

`CeremonyRepository` requires an existing owner-only directory and creates its
SQLite database mode `0600`. It rejects symlink paths, group/world permissions,
duplicate identifiers, invalid bounds, corrupt rows, and unsupported schema
state. It enables foreign keys, WAL journalling, and full synchronous commits.

Challenges begin pending. One signed response can transition a challenge to
response-available. Consumption uses an immediate transaction, clears the
response, increments the revision, and makes the state terminal. Expiry,
cancellation, replay, and duplicate insertion fail closed. Reopening the
repository cannot resurrect consumed authority.

The repository stores signed response bytes because the agent must verify and
consume them, but presentation APIs must never return those bytes to the CLI.
Production filesystem encryption and backup policy are operational controls,
not substitutes for signature or replay verification.

## Socket contract

`AgentSocket` binds only beneath a non-symlinked directory with no group or
world permissions. It never removes an existing path, sets the socket to mode
`0600`, and removes only its own socket node on clean drop. Clients independently
reject symlinks, non-sockets, and permissive modes.

Messages are four-byte big-endian length-prefixed canonical Pistis values,
bounded to 64 KiB. Empty, excessive, truncated, non-canonical, unknown-schema,
and trailing input must fail before dispatch. A production daemon additionally
checks platform peer credentials; filesystem mode alone does not distinguish
processes running under the same account.

The semantic protocol is a closed, versioned canonical envelope supporting
begin-login, begin-exact-action, status, response submission, and cancellation.
Responses are limited to pending metadata, status, acknowledgement, or a typed
failure. `dispatch_one` authorizes the peer before reading, accepts exactly one
request, invokes a narrow handler, writes exactly one response, and closes the
connection.

`SameUserAuthorizer` uses the native effective-user credential exposed by the
connected socket. Unsupported operating systems reject all peers. `serve_until`
uses non-blocking acceptance, five-second read/write bounds per connection, and
an injected lifecycle controller. Dispatch failures affect only that client;
listener failures terminate the service for its supervisor to handle.

`AuthoritativeHandler` routes each closed operation to one
`AuthoritativeCeremonies` implementation. Its contract requires response
verification, single-use consumption, session insertion, and audit insertion
to commit atomically. It explicitly forbids combining the in-memory reference
service and durable repository as parallel ceremony state machines.

## Verified completion transaction

The version 2 repository schema owns sessions and redacted audit events
alongside ceremonies. `complete_verified` accepts only facts produced by the
shared verifier. Inside one immediate transaction it reloads the ceremony,
checks the exclusive expiry, compares the exact staged response with the bytes
that were verified, inserts a unique fresh session, inserts one challenge-bound
audit event, and changes the ceremony to consumed.

No mutation precedes the exact-response and expiry checks. Session or audit
constraint failures roll back both inserts and leave the response available
for a correctly generated fresh session identifier. Concurrent attempts yield
exactly one session and audit event. Restart preserves all three committed
facts. Audit retrieval excludes session capabilities and response bytes.

`CompletionCoordinator` is the only verifier-to-commit path. It loads the exact
staged response, invokes a mutation-free `StagedResponseVerifier`, obtains a
fresh operating-system-random session capability, and passes those same bytes
and verified identity facts to `complete_verified`. Verification or randomness
failure leaves the response staged and creates no session or audit authority.

## Signing provider

`InstallationSigner` accepts canonical bytes and returns only a public key
identifier and signature. It has no private-key export method. `KeychainSigner`
validates an opaque label and delegates signing to a narrow `KeychainBackend`.
It never launches the `security` command-line utility or asks for key bytes.

On macOS, `MacOsKeychainBackend` searches for exactly one private key by its
configured Keychain label and calls the native Security-framework
`SecKeyCreateSignature` API with ECDSA/SHA-256. It requests only the public
key's external representation, derives the Pistis key identifier, converts the
returned DER signature to fixed-width low-S form, and verifies it before
returning. Missing and duplicate labels fail without a software fallback.

The backend deliberately does not create or delete keys. Provisioning must set
the reviewed Keychain access controls, code-signing identity, and entitlements
before the agent can use the label. Native tests must run on the supported
macOS worker; Linux Jenkins can prove only that the dependency is target-gated.

## Current integration status

The durable repository, socket ownership, canonical framing, closed dispatch,
non-export signer interfaces, CLI socket backend, and protected terminal
adapter are implemented and tested. The `pistis` executable discovers the
owner-only agent socket and uses these boundaries, but remains fail-closed
because these platform components are still absent:

- the protocol-specific `StagedResponseVerifier` implementation over the
  enrolled device directory and accepted login/action schemas; and
- Linux signing-provider policy.

The native macOS signing operation is implemented, but production enablement
still depends on reviewed key provisioning and the remaining items above.
Those are implementation blockers, not configuration instructions.
