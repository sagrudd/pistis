# Local-agent operations

No production Pistis agent service is installed by this revision. The
`pistis-agent` crate defines tested persistence, socket, framing, closed
semantic request/response dispatch, and signing
contracts for the future service. Operators must not construct an improvised
daemon around test signers or place an installation private key in a file,
argument, environment variable, shell script, or Jenkins credential.

ADR 0022 is Proposed and its Rust types do not activate a daemon. Packages and
service managers must leave any future `pistis-agent` unit disabled. Startup
must fail, rather than select a reduced mode, unless configuration identifies
an owner-only absolute socket, the accepted host adapter and exact Prosopikon
revision, initialized private authority database, reviewed installation signer,
enrolled-device verifier source, and fixed Monas audience.

Never put a bearer, cookie, signed response, private key or credential in an
environment file or systemd command line. A future `EnvironmentFile=` may
contain non-secret absolute paths and identifiers only. Until the ADR gate is
satisfied, RPM/systemd packaging may install documentation and a masked or
disabled placeholder, but must not create a socket or use an in-memory
authority. Prosopikon PR 10, Monas PR 5 and mobile ADR 0021 are review inputs,
not production pins.

The intended per-user layout is:

```text
~/.local/share/pistis/agent.sqlite3
${XDG_RUNTIME_DIR}/pistis/agent.sock
```

On macOS the service adapter may select equivalent Application Support and
per-user runtime locations. Both parent directories and the database/socket
nodes must remain owner-only. The library rejects permissive paths rather than
repairing an ambiguous deployment.

Before enabling a future service, verify:

- the daemon is code-signed and runs as the intended user;
- the socket parent is non-symlinked, owned by the daemon's effective user,
  and mode `0700`;
- the socket is owned by that same user and the socket and database are mode
  `0600`;
- the CLI verifies the connected server's native peer credential after
  validating the socket pathname;
- peer credentials are checked before request parsing;
- the Keychain key is non-exportable and has reviewed access control;
- restart, concurrent consumption, cancellation, expiry, and database-corrupt
  cases fail closed;
- backups never roll replay state backwards; and
- logs contain no canonical challenge/response, private key, session
  capability, nonce, or complete challenge identifier.

Repository schema version 2 migrates version 1 ceremony databases in an
immediate transaction. Back up the owner-only database before deployment and
never downgrade a migrated database. The local reference adapter records one
consumed ceremony, one non-secret completion receipt, and one redacted audit
row; it never stores a session. Production completion is valid only when the
Prosopikon host atomically issues its authority and appends both audit records.
Treat any partial or duplicate observation as corruption and stop the service.

The CLI now connects to this socket and performs one closed request per fresh
connection. Server dispatch checks native same-user credentials before reading
any request, applies bounded client I/O, and supports controlled shutdown.
Its unavailable exit remains expected until the shared verifier is connected
to the durable completion transaction and OS service packaging has passed its
gates.

The macOS backend selects an existing private key by exact Keychain label. It
does not create a key automatically, accept private bytes, invoke the
`security` command-line program, or fall back to a file key. Provisioning that
key is intentionally withheld until the agent code-signing identifier, access
group, user-presence policy, rotation procedure, and recovery consequences are
reviewed together.
