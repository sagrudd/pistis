# ADR 0028: Protected CLI-to-phone first-invitation QR

- Status: Proposed
- Date: 2026-07-30
- Decision owners: Pistis CLI, protocol, QR, iOS and Android, Prosopikon
  authority, Monas transport, and security
- Tracking issue: [#318](https://github.com/sagrudd/pistis/issues/318)
- Depends on: accepted Pistis ADRs 0018, 0021, and 0023; acceptance of ADR
  0027; and acceptance of Prosopikon ADRs 0002 and 0003

## Context

ADR 0023 makes the exact invitation sensitive bearer material delivered
through an administrator-approved enrolment channel, but it does not define
that channel. The bare-earth workflow must move one CLI-commissioned
invitation to a foreground iOS or Android app without copying a bearer,
writing a file, placing a secret in argv, an environment variable, or a URL,
or depending on a Mnemosyne broker or push service.

The accepted `PISTIS1` version-2 QR is for an already enrolled phone verifying
an installation-signed authentication challenge. A first device has no
installed authority or installation trust, so reusing that kind or offering
“trust this QR” would be a downgrade.

## Proposed decision

The MVP shall use one attended, single-symbol QR rendered by a Pistis CLI
presenter. Prosopikon produces a canonical, purpose-signed presentation
through a protected pipe. The phone accepts it only from Pistis's explicit
**Enrol first device** surface.

The physical administrator-approved terminal is the bootstrap trust channel.
The signature binds the invitation, authority descriptor, identity, and exact
HTTPS origin against partial substitution. It cannot make an
attacker-generated QR from an untrusted screen legitimate.

### Version-3 enrolment transport

Retain the ASCII `PISTIS1:` prefix, base64url-without-padding body, lowercase
16-hex-character checksum, 2,331-byte text bound, and version-40/M QR limit.
The checksum detects corruption and grants no authority.

Define a distinct deterministic-CBOR outer frame:

```text
{
  0: 3,                         / transport version /
  1: 3,                         / first-device presentation kind /
  2: bstr .cbor presentation,   / exact untagged COSE Sign1 bytes /
  3: bstr .cbor descriptor      / exact authority descriptor bytes /
}
```

Version 3 and kind 3 are accepted only by the enrolment scanner.
Authentication paths reject them; enrolment rejects versions 1 and 2. The
complete text must fit one symbol. Oversize input fails before rendering, with
no animated QR, URL shortening, fetch, truncation, or manual-copy fallback.

### Signed presentation payload

Field 2 is an ADR-0018 COSE Sign1 envelope whose protected `kid` is the current
Prosopikon `initial_invitation` authority key. Its canonical payload is:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `version` | unsigned, exactly `1` |
| 1 | `purpose` | exactly `pistis.first-device-presentation.v1` |
| 2 | `presentation_id` | 16 random bytes |
| 3 | `issued_at_ms` | unsigned authority-clock milliseconds |
| 4 | `expires_at_ms` | greater than key 3 and no later than invitation expiry |
| 5 | `invitation` | exact ADR-0023 bytes, at most 512 bytes |
| 6 | `authority_id` | 16-byte Prosopikon UUID |
| 7 | `tenant_id` | 16-byte tenant UUID |
| 8 | `principal_id` | 16-byte intended principal UUID |
| 9 | `installation_id` | 16 bytes, exactly the invitation value |
| 10 | `installation_name` | trimmed display text, 1..128 UTF-8 bytes |
| 11 | `audience` | exactly the invitation audience |
| 12 | `https_origin` | canonical HTTPS origin, 1..255 ASCII bytes |
| 13 | `app_configuration_digest` | reviewed 32-byte GitHub App digest |
| 14 | `authority_descriptor_digest` | exactly the invitation commitment |

No key is optional, null, duplicated, unknown, or caller-extensible.

The origin has scheme exactly `https`, a lower-case ASCII DNS or A-label host,
and an optional non-default port. It has no user information, path, query,
fragment, wildcard, trailing dot, IP literal, percent encoding, or Unicode
spelling. Enrolment paths are fixed by protocol and never supplied by the QR.

Outer field 3 is the exact ADR-0023 authority descriptor. Its digest equals
invitation key 8 and presentation key 14. Its derived key ID equals the COSE
`kid`, and its public key verifies the signature. The presentation ID is
unique and one-use. Prosopikon stores only presentation and invitation digests,
not another invitation secret.

### Producer and protected pipe

After the dependent decisions are accepted and implemented, the attended
administrator uses one pipeline:

```text
prosopikon issue-pistis-enrolment-presentation ... --output-fd 1 |
  pistis enrolment present --stdin
```

The final spelling is implementation-owned, but the boundary is normative:

- Prosopikon writes one bounded binary presentation and nothing else to the
  output descriptor;
- diagnostics use standard error and contain no sensitive value;
- Pistis accepts only a pipe or explicitly inherited descriptor, never a
  bearer argument, environment value, path, URL, or terminal paste;
- Pistis rejects trailing messages, verifies every canonical, signature,
  identity, origin, and time constraint, then renders;
- neither process uses a temporary file, shell variable, clipboard, log, crash
  report, evidence artifact, or subprocess; and
- broken pipe, signal, terminal loss, expiry, or verification failure yields
  only a coarse error and no automatic replacement invitation.

The producer requires the governed local administrator authority and peer
credential check. Unrelated shell access is not enrolment authorization.

### Terminal behavior

The presenter uses the alternate screen, hides the cursor, and renders the QR,
a prominent sensitive-invitation label, verified installation and origin,
redacted identity references, expiry countdown, and phone instructions. It
emits no transfer text outside that screen. Every exit clears the screen and
restores cursor and terminal modes.

Remote administration, cameras, screen recording, and shoulder surfing can
capture pixels. Operators use a controlled attended terminal, disable session
recording, keep expiry at five minutes or less, clear immediately after scan,
and never retain the QR as evidence.

### Mobile verification and network use

The phone checks bounds, ASCII, prefix, checksum, canonical CBOR, version,
kind, COSE, descriptor, and invitation before opening a connection. It then:

1. verifies invitation purpose, time, installation, audience, and descriptor;
2. derives the descriptor key ID and verifies COSE profile and signature;
3. verifies presentation purpose, time, identity, installation, audience,
   origin, configuration digest, and all repeated facts; and
4. requires platform TLS trust for the exact signed origin.

For evaluation, the development CA is installed and compared out of band. The
QR never disables TLS validation or installs a CA.

Only after local verification does the phone show the installation,
tenant/principal context, origin, and expiry for explicit confirmation. It
posts the exact invitation only to the fixed begin route on the signed origin,
never to redirects, alternate hosts, browser, analytics, or crash reporting.

The later provider ceremony follows ADR 0027: the installation-local adapter
owns GitHub Device Flow; the phone receives only the user code, fixed GitHub
verification URI, expiry, and polling capability. The user authorizes GitHub
on the phone, confirms the immutable numeric account, and signs the binding.
No GitHub token enters the phone or QR.

### Cancellation, retry, and evidence

Dismissal before begin clears locally. After begin, the phone cancels through
the exact polling capability. An exact retry may re-present the same valid
bytes only while the authority reports the same pending operation. The
producer must not silently issue a second invitation. Terminal or unknown
state requires a new attended ceremony.

Evidence retains source revisions, fixture digests, public descriptors,
coarse outcomes, cleanup results, and audit correlation only. It never retains
the QR, transfer text, invitation, presentation COSE, polling capability, user
or device code, provider response, or token.

## Required acceptance before implementation

- owner and specialist protocol, cryptography, CLI/terminal, mobile, privacy,
  Prosopikon, and Monas review;
- acceptance of ADR 0027 and Prosopikon ADRs 0002 and 0003;
- exact Rust/Swift/Kotlin positive and hostile fixtures;
- tests for pipe-only input, trailing/short data, signals, terminal restore,
  expiry, secret-free diagnostics, kind confusion, downgrade, and size bounds;
- tests proving TLS is mandatory and redirects cannot receive the invitation;
- restart, duplicate scan, denial, cancellation, expiry, uncertain commit, and
  exact replay tests;
- physical iPhone and Android scan, Device Flow, confirmation, and enrolment;
  and
- exact-revision Jenkins evidence with no sensitive QR artifact.

This proposal activates no producer, CLI command, QR kind, scanner route,
provider request, invitation, or authority state.

## Consequences

- CLI commissioning can hand off to a foreground phone without manual secret
  copying or a dedicated broker.
- Origin and intended identity are signed rather than browser-supplied.
- First-device QR remains distinct from ordinary authentication.
- Customer-hosted installations need no push service.
- Pixel capture remains a residual bearer risk bounded by attendance, expiry,
  identity confirmation, device proof, and atomic one-use authority state.

## Alternatives rejected

- URL or deep link: leaks through history, logs, referrers, and handlers.
- Copy/paste or typing: error-prone and commonly retained.
- Temporary file: deletion is not reliable secret erasure.
- Authentication QR v2: no first-device trust exists.
- Short server reference: creates a second bearer/rendezvous service.
- Local unauthenticated HTTP: exposes the invitation and creates a race.
- Apple/Google push: out of scope and unsuitable for standalone customer
  installations without additional infrastructure.
