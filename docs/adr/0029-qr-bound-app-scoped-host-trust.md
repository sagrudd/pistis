# ADR 0029: QR-bound app-scoped host trust

- Status: Accepted
- Date: 2026-07-30
- Accepted: 2026-07-30
- Acceptance note: The project owner accepted the version-4 signed TLS
  public-key commitment, three-word attended comparison, exact-origin
  app-scoped iOS and Android trust, fail-closed rotation, and removal of the
  manual root-certificate/Settings ceremony. Cross-project implementation and
  specialist review evidence remain mandatory.
- Decision owners: Pistis protocol, cryptography, iOS, Android, Prosopikon,
  Monas, security, privacy, accessibility, and operations
- Tracking issue: [#331](https://github.com/sagrudd/pistis/issues/331)
- Supersedes if accepted: ADR 0028's requirement for preinstalled platform TLS
  trust during first-device enrolment
- Reconciles: ADR 0011's installation-controlled TLS public-key binding

## Context

ADR 0028 requires platform TLS trust for the signed first-device HTTPS origin.
Its evaluation runbook therefore asks the user to install a private
certificate-authority profile and enable full trust in iOS Settings before
scanning the protected QR.

That is not a sustainable product contract for small laboratories, artisanal
bioinformatics support units, or customer-hosted installations. It makes an
operating-system trust-store change larger than the Pistis relationship being
approved, requires unfamiliar Settings navigation, and is difficult to
explain, revoke, support, and audit.

Apple does not permit an ordinary consumer application to silently install a
globally trusted root. A manually installed certificate profile still requires
the user to enable SSL/TLS trust in Settings. Managed deployments may use MDM
or Apple Configurator, but Pistis cannot require device management.

Apple does support app-scoped manual server authentication through a
`URLSessionDelegate` server-trust challenge. The application can compare the
server certificate or public key with authenticated material it already holds
and accept that connection without changing trust for Safari or another
application. Android supports an equivalent connection-scoped trust manager.

The first-device QR is already an attended, authority-signed bootstrap
presentation from a terminal the administrator explicitly trusts. It binds
the installation, authority, intended identity, application configuration,
and exact HTTPS origin. It is therefore the correct place to bind the local
TLS key and a human comparison ceremony.

## Decision

### Product contract

Scanning one protected first-device QR shall provide all trust material needed
by Pistis to authenticate the exact local HTTPS endpoint inside the mobile
application. Normal standalone onboarding shall not require:

- installing a certificate or configuration profile;
- changing Certificate Trust Settings;
- MDM or Apple Configurator;
- a public certificate authority;
- accepting a browser certificate warning; or
- weakening the device-wide or application-wide trust store.

After cryptographic verification of the QR and before any network request, the
phone presents:

- **Do you really trust this host?**
- the installation name;
- the exact signed hostname and port;
- the authority and intended tenant context;
- a three-word verification phrase; and
- an explicit statement that trust applies only inside Pistis.

The terminal may display the same three words outside the QR as operator
diagnostics. Following project-owner review on 10 August 2026, the phone does
not require them to be retyped: the user instead starts enrolment only after
Pistis has verified the purpose-separated authority signature, application
digest, canonical HTTPS origin and complete TLS SPKI pin. Scanning alone never
contacts the host.

The phrase is a usability check over the authenticated binding. It is not a
replacement for the authority signature, 256-bit TLS pin, one-use invitation,
GitHub verification, device proof, or signed authority receipt.

### New first-device presentation version

ADR 0028 version 3 remains parseable only for retained evidence. It shall not
be accepted by the new first-device network flow.

Define transport version `4`, kind `3`, and presentation purpose
`pistis.first-device-presentation.v2`. The v2 signed payload retains ADR
0028's keys `0` through `14` and adds:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 15 | `tls_spki_sha256` | SHA-256 of the leaf certificate's exact DER SubjectPublicKeyInfo, 32-byte byte string |
| 16 | `trust_words_version` | unsigned, exactly `1` |

The canonical HTTPS origin and TLS public-key digest are covered by the
purpose-separated Prosopikon signature. They are repeated in the eventual
mobile-enrolment receipt and durable installation binding. A mismatch at any
layer fails the transaction without installing trust.

Version 3 does not gain optional fields or an insecure compatibility flag.
Version 4 is rejected by authentication QR decoders and accepted only by the
explicit first-device enrolment surface.

### Human verification phrase

Version 1 uses a reviewed, committed list of exactly 2,048 distinct lowercase
ASCII words. The list, ordering, licence, and SHA-256 digest are normative
cross-language fixture inputs.

Construct the phrase input as canonical CBOR:

```text
{
  0: 1,
  1: "pistis.host-trust-words.v1",
  2: bstr authority_id,
  3: bstr installation_id,
  4: tstr canonical_https_origin,
  5: bstr tls_spki_sha256,
  6: bstr app_configuration_digest
}
```

Hash the exact bytes with SHA-256. Interpret the first 33 digest bits as three
ordered 11-bit unsigned integers and select the corresponding words.

The terminal and mobile implementations derive the phrase independently from
the same verified fields. The phrase is never supplied as display text by the
producer, transported in DNS-SD, or accepted from the server.

The UI uses three separate text fields in fixed order, disables autocorrection
and predictive replacement, folds ASCII uppercase to lowercase, trims only
leading and trailing ASCII spaces per field, and accepts no other
normalisation. Paste-all and automatic confirmation are prohibited. VoiceOver
announces word position and spelling. Failure does not reveal which word was
wrong and does not contact the host.

Thirty-three displayed bits are an attended comparison checksum, not the
security strength of endpoint authentication. The complete signed 256-bit
digest remains mandatory and is compared in constant time.

### iOS app-scoped TLS authentication

The enrolment transport creates a dedicated ephemeral `URLSession` whose
delegate owns one immutable expected origin and TLS digest. It:

1. handles only `NSURLAuthenticationMethodServerTrust`;
2. requires the challenge hostname to equal the signed canonical hostname;
3. requires exactly the signed port through request construction;
4. extracts the leaf certificate and its DER SubjectPublicKeyInfo;
5. computes SHA-256 and compares all 32 bytes with the signed digest;
6. requires the certificate to be currently valid and suitable for TLS server
   authentication;
7. requires TLS and retains normal minimum protocol and cipher requirements;
8. accepts the credential only for that session after the explicit human
   decision; and
9. cancels every other challenge.

Redirects, proxies, cookies, caches, ambient credentials, alternate
certificates, wildcard widening, HTTP downgrade, and authentication challenges
other than exact server trust remain prohibited.

`NSAllowsLocalNetworking` may be declared to permit `.local`, unqualified, and
local-address connections. `NSAllowsArbitraryLoads` and
`NSAllowsArbitraryLoadsInWebContent` remain prohibited. The local-network
exception permits addressing; it does not supply trust or allow cleartext.

The accepted digest is stored in Keychain only as part of the fully verified
mobile-enrolment receipt. Before completion it remains bounded, foreground,
and ephemeral.

### Versioned endpoint identity variants

`SiteTrustEndpointIdentityV1` is the common producer and consumer validator
for the signed HTTPS origin. Its host is exactly one typed variant: a canonical
lower-case DNS name, a canonical IPv4 address, or a canonical bracketed IPv6
address. The authority-side allowed-host value must exactly equal that
variant's canonical host serialization. Expanded IPv4, expanded or uppercase
IPv6, zone identifiers, DNS trailing dots, default-port aliases, credentials,
paths, queries and fragments are rejected rather than normalised.

Every variant requires the same non-zero 32-byte `tls_spki_sha256` commitment,
certificate validity and TLS server suitability checks described above. An IP
literal is therefore an addressing option for a local-only installation, not
a CA fallback, hostname-verification exception, or weaker trust mode. The
presentation signature, five-minute expiry and one-use authority transaction
remain unchanged.

### Android app-scoped TLS authentication

Android uses a dedicated client and trust manager scoped to the exact signed
origin and SPKI digest. It applies the same full-digest comparison, certificate
validity, TLS requirements, redirect prohibition, request bounds, and
post-receipt persistence rule. It does not install a user CA, modify the
platform trust store, use a permissive hostname verifier, or share the pinned
client with unrelated traffic.

### Public and managed certificates

A publicly trusted or organisation-managed certificate is welcome but not
sufficient by itself. Pistis still requires it to match the signed
installation-controlled digest. Default platform validation may be retained as
an additional check when it succeeds; failure solely due to an unknown local
anchor may be overridden only after the exact app-scoped checks above.

The pin authenticates the Pistis application connection only. It does not make
the certificate trusted by Safari, another browser, command-line tools, or
other Mnemosyne products. Browser-facing customer deployments should use
publicly trusted DNS and ACME certificates or an explicitly managed
organisation PKI. A later native product browser or same-origin proxy requires
its own reviewed session and cookie boundary; this ADR does not silently grant
system-browser trust.

### Rotation, recovery, and revocation

Certificate renewal with the same SubjectPublicKeyInfo retains the binding.
TLS key rotation is a trust change and fails closed. It requires a new
authenticated attended presentation or the separately accepted
already-enrolled-device recovery protocol. DNS, mDNS, the server, or a generic
certificate-validity result cannot rotate the pin.

Removing an installation from Pistis deletes its app-scoped trust record.
Removing the application removes its Keychain record subject to the documented
iOS Keychain lifecycle; reinstall and restore behaviour must be tested and must
not silently resurrect an active installation without the accepted recovery
policy.

### Evidence and privacy

Retained evidence may contain:

- protocol and word-list versions;
- public source revisions and fixture digests;
- the signed presentation digest;
- a redacted TLS digest identifier;
- whether the words matched;
- whether the app-scoped TLS check passed; and
- coarse cancellation or rejection reasons.

Evidence must not contain the QR, invitation, full presentation, complete TLS
pin, typed words, polling capability, provider code, token, device response,
or private key.

### Required implementation and tests

No protocol implementation begins until this ADR receives project-owner
acceptance and its implementation plan receives specialist protocol,
cryptography, mobile, Prosopikon, Monas, accessibility, privacy, and
operations review.

Acceptance then requires:

- deterministic Rust, Swift, and Kotlin positive and hostile fixtures;
- exact SPKI extraction fixtures for supported certificate algorithms;
- wrong host, port, key, certificate, phrase, configuration, authority,
  version, expiry, redirect, proxy, and replay negatives;
- certificate renewal with the same key and rotation with a different key;
- proof that no request occurs before word confirmation;
- proof that trust is session-scoped before receipt and Keychain-scoped after
  receipt;
- tests rejecting version 3 for network enrolment without a manual-trust
  compatibility path;
- physical iPhone and Android tests using a locally anchored certificate with
  no installed profile;
- operator documentation for public-CA, private-CA, and offline/customer-site
  installations; and
- exact-revision Jenkins evidence.

## Consequences

- Standalone onboarding becomes viable without device-management expertise.
- The QR ceremony binds installation identity and local TLS confidentiality in
  one attended decision.
- Pistis trust remains narrow and revocable instead of changing global device
  trust.
- Safari and unrelated applications do not inherit Pistis trust.
- The first-device wire format changes before MVP release and requires
  coordinated Prosopikon, Pistis, Monas, iOS, and Android delivery.
- The current development-CA Settings runbook is rejected as MVP acceptance
  evidence.

## Alternatives rejected

- Manual certificate profile plus Settings: rejected as unsustainable for the
  target operators and broader than the Pistis relationship.
- MDM or Configurator: rejected as a mandatory dependency; retained only as an
  optional managed-enterprise deployment tool.
- Public CA only: rejected because offline and customer-local installations
  may not control public DNS or Internet ACME, and public PKI alone does not
  bind the intended Pistis installation.
- Trust on first network use: rejected because the local network is hostile.
- Pin supplied by mDNS or the server: rejected because neither source is
  authenticated before pairing.
- Disable certificate validation: rejected because it permits endpoint
  substitution and invitation theft.
- Put a CA certificate in the QR and install it globally: rejected because it
  recreates the original operational and trust-scope defect.
- Three words as the only authenticator: rejected because the phrase is only a
  human comparison checksum over the full signed binding.
