# Local discovery and direct exchange development

EPIC-11 adds an optional transport convenience. It does not change the Pistis
trust model, verifier, signed payload, approval semantics, or challenge
consumption rules. Discovery names, addresses, ports, TXT records, network
interfaces, and endpoint responses are untrusted until the exact Pistis
bindings and signed protocol message verify.

There is currently no `pistis-discovery` crate, server advertiser, iOS local
network adapter, or Android network-service-discovery adapter. The iOS bundle
declares no Bonjour service/local-network purpose, and the Android application
reports local discovery as `Not configured`. These are delivery blockers, not
implicit platform support.

## Normative boundary

[ADR 0011](../adr/0011-local-discovery-and-direct-exchange.md) is normative
once merged. Discovery must preserve these boundaries:

- the installation advertises a short-lived, non-user-specific service;
- mobile browsing starts only for a selected or QR-identified installation;
- discovery metadata contains no username, provider identity, profile,
  project/report title, or persistent device identifier;
- an opaque endpoint identifier is correlation data, not a bearer capability;
- the browser observes host-owned ceremony state and never attempts browser
  mDNS discovery;
- discovery and QR feed one bounded challenge/response ingestion path; and
- a network success never means approved, signed, delivered, verified,
  consumed, or authenticated.

The selected service name, TXT schema, endpoint identifier, TTL, protocol
version negotiation, certificate/key binding, and request limits require
accepted protocol definitions and deterministic fixtures. Do not infer these
values from the illustrative milestone text.

## Module and adapter structure

The inward `pistis-discovery` contract should model:

- bounded advertisement metadata;
- scoped browse and resolution events;
- interface and endpoint candidates;
- deterministic deadlines and cancellation;
- direct-exchange request/result states; and
- typed reasons for falling back.

It must not import Axum, Yew, Network.framework, Android `NsdManager`, a
platform HTTP stack, or host-session types. Platform and host adapters own:

- Rust advertisement lifecycle and interface events;
- iOS permission, browse, resolution, and foreground lifecycle;
- Android permission, discovery, resolution, and network callbacks;
- authenticated connection establishment; and
- host completion notification.

Views do not select authority from the first discovered service. They display
bounded state and safe fallback choices while an adapter checks the exact
installation and endpoint binding.

## Secure channel and downgrade rules

mDNS authenticates nothing. A matching service type, friendly name, address,
or opaque endpoint identifier cannot authorize a connection. The direct
channel must be authenticated by material already bound through the reviewed
QR/pairing ceremony, such as an exact installation certificate or key.
Platform or enterprise CA trust alone must not replace that binding.

Apply one policy to IPv4, IPv6, link-local scope identifiers, redirects, DNS
rebinding, multiple interfaces, and address changes. Reject:

- endpoints outside the challenge/pairing scope;
- a changed installation identity or channel key;
- HTTP downgrade or unreviewed TLS exceptions;
- redirects to an unbound host;
- oversized, wrong-content-type, or non-canonical responses; and
- stale discovery after sleep, backgrounding, network change, or expiry.

Fallback is allowed before authoritative completion for permission denial,
multicast timeout, client isolation, resolution failure, an unreachable
endpoint, ambiguity, or a candidate that does not satisfy the required TLS
pin. Exclude that candidate, retain a typed warning, and use QR without
weakening channel policy. Rejection of the signed challenge or response for
identity, signature, binding, schema, replay, or policy reasons is terminal:
stop and investigate rather than relabelling it as transport fallback.

## Bounded fallback state machine

The transport state machine is explicit and deadline driven:

```text
selected installation
  -> scoped local browse
  -> bound direct endpoint reachable
  -> submit through authenticated direct exchange

availability failure
  -> QR direct endpoint when separately bound and reachable
  -> response QR
```

There is no indefinite `Searching` state. Each transition retains the same
challenge, purpose, installation, user, device, key, expiry, and policy
bindings. A terminal or expired ceremony requires a new challenge; transport
fallback never revives it.

Displaying a response QR is not delivery. Posting bytes is not server
acceptance. Human decision, local authentication, signature production,
transfer, server verification, challenge consumption, and host-session
issuance remain separate evidence facts.

## Mobile requirements

iOS requires a reviewed Network.framework/Bonjour adapter, local-network usage
description, declared service type, foreground/background cancellation, and
real-device permission tests. Simulator discovery is not real-LAN acceptance.

Android requires a reviewed `NsdManager` or equivalent adapter, API-level
permission policy, lifecycle cancellation, network-change handling, and
physical-device tests across supported vendors. Emulator networking is not
evidence for multicast, Wi-Fi isolation, or OEM behavior.

Both clients need words-first states for permission rationale, searching,
multiple installations, unavailable multicast, endpoint rejection, fallback,
and completion. Permission denial remains recoverable through QR without
pressure to open system settings.

## Test contract

Pure tests use fixed clocks and synthetic interfaces. Cover:

- malformed, oversized, unknown-version, and privacy-violating metadata;
- duplicate names, conflicting advertisements, and endpoint substitution;
- TTL expiry, browse timeout, cancellation, sleep/wake, and network change;
- IPv4, IPv6, scoped link-local, multiple-interface, and address churn;
- multicast blocked and guest-network client isolation;
- certificate/key mismatch, redirect, rebinding, and wrong installation;
- no fallback after a security-verification failure;
- direct, QR-direct, and response-QR routes reaching one verifier boundary;
- no second consumption under concurrent direct/QR submissions; and
- log/event redaction.

Physical acceptance includes supported iOS and Android devices plus multiple
installations on one LAN. Browser tests prove only that the host advertises,
receives, and updates browser state; they do not ask browser JavaScript to
discover mDNS.

## Jenkins contract

Ordinary hermetic CI can validate metadata parsing, state transitions,
privacy-field rejection, fixtures, and fake-adapter behavior. Real multicast
acceptance needs a separately reviewed network test environment with controlled
interfaces, IPv4/IPv6, packet capture/redaction policy, and explicit capability
allowance. The current generic Pistis Jenkins task is not that environment.

A future dossier retains exact source revision, container/worker identity,
dependency locks, interface topology, service/TXT fixture, test results, and
redacted diagnostics. Native iOS/Android device evidence remains separate.
Do not add a CI stage that passes only because multicast is unavailable and
the implementation immediately selects QR fallback.
