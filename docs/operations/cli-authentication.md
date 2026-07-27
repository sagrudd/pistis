# CLI authentication operations

EPIC-16 introduces the supported command names and portable security
boundaries for terminal authentication. The checked-in `pistis` binary connects
to the owner-only local-agent socket, but it remains fail-closed unless a
reviewed authoritative agent is running. It does not issue a session by itself.
Do not describe this client boundary as production authentication.

## Commands

Request terminal login with:

```console
pistis auth login
```

Select a deterministic presentation explicitly when diagnosing a terminal:

```console
pistis auth login --ascii
pistis auth login --unicode --invert
```

The reserved exact-action form is:

```console
pistis auth approve -- samtools view sample.bam
```

Arguments after `--` are bound in order and with their original boundaries.
They are not executed by the current CLI. ADR 0016 defines the versioned
descriptor and agent execution boundary, but production action approval
remains disabled until the durable verifier and mobile display/signing
adapters implement it.

Never put a signed response, session handle, credential, or private key on the
command line or in an environment variable. Those locations can leak through
shell history, process inspection, crash reports, or diagnostics.

The non-secret socket pathname is selected from `PISTIS_AGENT_SOCKET`, which
must be absolute, or defaults to `${XDG_RUNTIME_DIR}/pistis/agent.sock`. A
relative, missing, malformed, symlinked, permissive, or non-socket path fails
closed. `COLUMNS` may select a width from 40 through 1,000 columns; other
values use the conservative 80-column default and may refuse a larger QR.

## Terminal requirements

The rendering library accepts an explicit terminal width, ASCII or Unicode
glyph profile, polarity, and scale. It refuses output that would be cropped.
ASCII output uses only spaces, `#`, and newlines. Unicode output additionally
uses block glyphs and requires a correctly configured UTF-8 terminal.

Use ASCII over uncertain SSH, serial-console, locale, or multiplexer paths.
Use `--invert` only when the default polarity does not scan against the actual
background. Increase terminal width rather than reducing the four-module quiet
zone.

## Response handling

The fallback reader accepts exactly one bounded ASCII `PISTIS1` response
transfer, optionally terminated by LF or CRLF. It rejects escape sequences,
other controls, non-ASCII input, excessive input, malformed checksums, and the
wrong transfer kind before the authoritative verifier sees the bytes. This is
transport validation, not authentication: signature, installation, expiry,
action, and replay checks still belong to the shared verifier.

Standard input must be a protected, non-echoing source. The CLI refuses framed
response entry from an interactive terminal because the portable client cannot
prove that echo has been disabled. Pipe a response from a dedicated protected
descriptor; never type or paste it at an ordinary shell prompt.

On denial, expiry, interruption, malformed input, adapter failure, or
presentation failure, the ceremony fails closed and cancels its pending
reference. Operators must never bypass that result by constructing a session
manually.

## Evidence and readiness

Jenkins should run the workspace unit and regression tests, Clippy, rustdoc,
architecture guard, and strict Sphinx build for every exact revision. Closing
EPIC-16 additionally requires retained evidence from:

- a configured authoritative local backend;
- supported physical or simulator iOS and Android scan-and-sign clients;
- ASCII and Unicode scanning across the documented terminal matrix;
- direct-local and framed responses entering the same verifier;
- exact-action display and downgrade-negative cases;
- secure child-session hand-off; and
- both supported CLI architectures.

Until those artefacts exist, the portable implementation is useful,
testable groundwork but not a production authentication deployment.
