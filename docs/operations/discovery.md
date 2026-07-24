# Local discovery and direct exchange operations

EPIC-11 is not production-ready while the discovery protocol, authenticated
channel, server advertiser, mobile adapters, and supported-network test matrix
remain absent. QR is the universal fallback and must remain available whenever
local multicast or direct connectivity is unavailable.

## Enablement gates

Before enabling local discovery, retain evidence for:

1. accepted ADR 0011, service/TXT schema, privacy review, and exact supported
   protocol versions;
2. a short-lived installation advertisement containing no user or persistent
   device identity;
3. an authenticated channel bound to installation material reviewed during QR
   or pairing;
4. one verifier/consumption path shared by direct and QR transfer;
5. bounded browse, resolve, connect, and completion deadlines;
6. clean unregister, sleep/wake, background, interface-change, and shutdown
   behavior;
7. IPv4, IPv6, multiple-interface, conflicting-service, and client-isolation
   tests;
8. explicit iOS and Android permission/lifecycle behavior on physical devices;
9. browser integration through the host backend rather than browser mDNS;
10. redacted logs, metrics, diagnostics, and evidence; and
11. Jenkins and native-device dossiers for exact release revisions.

Discovery defaults to disabled. Missing permission, unsupported platform,
blocked multicast, no matching service, guest-network isolation, ambiguity, or
a candidate that fails the required TLS pin reports a bounded reason, excludes
that candidate, and offers QR without weakening channel policy. Rejection of
the signed challenge or response is terminal and must not silently fall back.

## Network and privacy policy

Advertise only the reviewed service type, supported protocol version, opaque
short-lived endpoint identifier, and data required for bounded resolution.
Never advertise:

- username, provider account, email, or local role;
- report, project, sample, workflow, or product title;
- persistent phone, device, or user identifier;
- challenge, nonce, response, signature, or session capability; or
- an administration or diagnostic endpoint.

Scope advertisements to intended interfaces. Do not intentionally bridge mDNS
between VLANs, publish it through unicast DNS, or expose the direct endpoint on
a public interface without a separate network and threat review. Treat all
friendly names as display hints and disambiguate installations with reviewed
identity evidence.

## Expected fallback

Use this availability hierarchy:

```text
authenticated paired local endpoint
  -> authenticated QR-carried direct endpoint
  -> response QR
```

Permission denial, multicast filtering, Wi-Fi client isolation, missing IPv6
multicast, endpoint timeout, or a network transition are normal availability
conditions. Stop searching at the configured deadline, explain the condition,
and offer QR without weakening transport or verifier policy.

An endpoint candidate that fails identity or certificate/key pinning is never
used; retain a typed warning and proceed to response QR. Do not fall back after
the signed challenge or response fails signature, schema, binding, replay, or
policy verification. Cancel that ceremony and investigate possible
substitution. Never disable certificate validation, accept cleartext, extend
expiry, reuse a response, or ask the user to choose an unverified same-name
service.

## Platform checks

On iOS, confirm the reviewed local-network explanation and Bonjour service
declaration are present before distribution. Test first prompt, denial,
subsequent denial, Settings changes, Wi-Fi changes, backgrounding, and device
restart on physical hardware.

On Android, confirm the reviewed API-level permissions and network-service
discovery behavior for every supported OS/vendor tier. Test permission denial,
Wi-Fi changes, process/background lifecycle, device restart, power policy, and
StrongBox/non-StrongBox devices independently; key assurance does not prove
network behavior.

Browser operators configure the Synoptikon or Monas backend to advertise and
receive. A web page polls, uses SSE, or uses WebSocket for coarse host state;
JavaScript does not perform arbitrary mDNS discovery.

## Diagnostics

Safe diagnostics may include:

- discovery enabled/disabled and coarse permission state;
- interface class without complete address;
- advertisement generation and expiry;
- browse/resolve/connect phase and bounded reason;
- protocol version and redacted endpoint identifier;
- selected transfer class; and
- independent non-secret correlation identifier.

Do not log packet bodies, complete TXT records when they contain correlation
material, complete addresses at normal level, challenge/response frames,
nonces, signatures, cookies, capabilities, private keys, provider credentials,
or production personal data.

Repeated conflicting advertisements, identity/key mismatch, redirect,
rebinding, unexpected public-interface exposure, or verification failure is a
security incident. Stop advertisement, cancel affected ceremonies, preserve
redacted evidence, and follow key/recovery procedures where compromise is
suspected.

## CI and acceptance evidence

Jenkins is authoritative for deterministic discovery and fallback tests. Real
network acceptance additionally records the controlled topology, interfaces,
IPv4/IPv6 behavior, multicast policy, exact worker/source revisions, and
redacted packet-level observations.

Container unit tests do not prove multicast operation. Emulator tests do not
prove physical mobile networking. A successful fallback test does not prove
direct exchange. A displayed response QR does not prove delivery, and a direct
POST does not prove verification or host-session issuance.
