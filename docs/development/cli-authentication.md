# CLI-native authentication

EPIC-16 makes the command line a primary Pistis product surface for
bioinformatics, scientific computing, automation, remote shells, and headless
workstations. It is not a thin launcher for a browser. A supported ceremony
must require only:

1. the Pistis CLI in a terminal;
2. an enrolled Pistis iOS application; and
3. either QR-only exchange or the already authenticated direct-local response
   transport.

## Required user ceremonies

`pistis auth login` creates a short-lived, single-use challenge and renders it
as an ASCII or Unicode QR code in the terminal. Alongside the QR, the CLI
displays the installation identity, authentication purpose, expiry, and a
human-verifiable fingerprint. The mobile application scans the same EPIC-6
frame used by other presentation surfaces, shows the bound request, obtains
biometric approval where policy requires it, and signs the response.

`pistis auth exec` uses the same protocol boundary but binds the challenge
to the exact action, relevant resource identifiers, and canonical command or
workflow digest. The phone must show those signed semantics before approval.
Generic login approval must never be silently promoted into action approval.

ADR 0016 now defines the additive v2 exact-action schema and the portable
agent-controlled execution boundary. Its closed descriptor binds the resolved
executable and digest, ordered argument vector, working directory, explicit
non-secret environment allow-list, and typed resources. This completes the
portable protocol blocker; production enablement remains fail-closed until the
durable backend and both mobile clients implement that exact schema.

ADR 0017 and `pistis-agent` provide the durable-backend foundation: owner-only
Unix socket and SQLite boundaries, restart-safe single-use response
consumption, canonical message framing, and a non-export installation-signing
interface. The macOS Security-framework signing operation, closed semantic
dispatch, and CLI socket client are implemented. Remaining native work is the
service lifecycle and peer-credential adapter, authoritative verifier/session
handler, and reviewed Keychain provisioning.

The signed response returns through direct-local submission when available.
The universal fallback is a bounded, checksummed, terminal-safe response frame
entered on standard input or another explicitly protected input channel. Both
routes converge on the existing single-use verifier and produce the same
principal, policy, audit, and evidence outcomes.

## Terminal rendering contract

The renderer shall:

- detect TTY, dimensions, colour capability, and known multiplexers without
  trusting terminal-provided text as protocol input;
- provide deterministic ASCII and Unicode profiles with a preserved quiet
  zone, square modules, configurable scale, and dark-on-light inversion;
- refuse an unscannable terminal width rather than silently crop the QR;
- avoid cursor movement, hyperlinks, OSC sequences, and untrusted control
  characters;
- provide a non-QR textual explanation, expiry countdown or status, and
  accessible recovery instructions; and
- behave predictably over SSH, tmux, screen, monochrome consoles, redirected
  output, and terminals without UTF-8.

The supported rendering profiles are explicit inputs to the transport adapter;
terminal environment strings never become QR or control-sequence content.
Both profiles include the four-module quiet zone and an integer scale from one
through four:

- `Unicode` uses UTF-8 block elements, one character cell per scaled module
  column, and packs two scaled module rows into each terminal line;
- `ASCII` uses only pairs of `#` characters and spaces, so one scaled module
  occupies two character cells and one terminal line; and
- either profile supports dark-on-light or light-on-dark polarity without
  emitting colour or cursor escape sequences.

The renderer reports the exact required columns and refuses widths below that
bound. Its output alphabet is limited to space, `#`, line feed, and (for the
Unicode profile) `▀`, `▄`, and `█`. Explanatory labels are rendered separately
after sanitisation and cannot be interpolated into the QR output.

ASCII QR is a presentation of the canonical EPIC-6 frame, not a new protocol
encoding. Rendering changes therefore cannot alter signed bytes, checksums,
fragment ordering, or verifier behavior.

## Credential and session boundary

Secrets, signed responses, bearer material, and session handles must not be
placed in command-line arguments, shell history, process titles, diagnostic
logs, terminal escape sequences, or inherited environment variables by
default. Session hand-off to a child bioinformatics command uses the approved
supervised `pistis auth exec -- <command>` boundary and a protected local
channel carrying a short-lived, audience- and exact-action-bound capability.
The CLI must erase transient buffers where practical and must fail closed on
denial, expiry, cancellation, replay, wrong installation, wrong action,
malformed framing, terminal interruption, and lost transport.

## Acceptance evidence

Jenkins must retain for the MVP:

- deterministic renderer and QR decode fixtures for ASCII and Unicode modes;
- supported iOS scan interoperability results;
- login and exact-action approval end-to-end tests without a web service;
- narrow-terminal, SSH, multiplexer, monochrome, redirected-output, and
  offline cases;
- replay, substitution, terminal-injection, malformed-frame, and secret-leak
  negative tests; and
- dual-architecture CLI builds plus warnings-as-errors Sphinx output.

Android scan interoperability remains a v1.0 gate and is not an MVP acceptance
substitute.

Protocol, session-transfer, or evidence-schema changes require an accepted ADR
and specialist review before implementation. GitHub issue
[`PIS-E16`](https://github.com/sagrudd/pistis/issues/203) is the planning
authority for this epic.
