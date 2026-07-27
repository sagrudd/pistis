# Local-agent operations

No production Pistis agent service is installed by this revision. The
`pistis-agent` crate defines tested persistence, socket, framing, closed
semantic request/response dispatch, and signing
contracts for the future service. Operators must not construct an improvised
daemon around test signers or place an installation private key in a file,
argument, environment variable, shell script, or Jenkins credential.

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
- the socket parent is non-symlinked and mode `0700`;
- the socket and database are mode `0600`;
- peer credentials are checked before request parsing;
- the Keychain key is non-exportable and has reviewed access control;
- restart, concurrent consumption, cancellation, expiry, and database-corrupt
  cases fail closed;
- backups never roll replay state backwards; and
- logs contain no canonical challenge/response, private key, session
  capability, nonce, or complete challenge identifier.

Repository schema version 2 migrates version 1 ceremony databases in an
immediate transaction. Back up the owner-only database before deployment and
never downgrade a migrated database. A completed login must produce exactly
one consumed ceremony, one session row, and one redacted audit row. Treat any
partial or duplicate observation as corruption and stop the service.

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
