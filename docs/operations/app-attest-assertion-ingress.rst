Production App Attest assertion ingress
========================================

``pistis-monas`` 0.4.0 defines the only Rust-side production assertion path
from a previously registered Pistis iPhone to a Monas-consumable Site Trust
human-authority fact.  It is a library contract, not an HTTP route, browser
flow, session issuer, local-login mechanism, or Site Trust completion service.

Authority boundary
------------------

The iPhone sends only this bounded JSON envelope to the eventual transport
adapter::

   {
     "profile": "mnemosyne.pistis.site-trust-app-attest-assertion-ingress.v1",
     "ceremony_id_b64url": "<canonical unpadded base64url of 16 bytes>",
     "assertion_b64url": "<canonical unpadded base64url; 1..16384 bytes>"
   }

Unknown fields, padding, non-canonical base64url, an all-zero ceremony ID, and
oversized input are rejected.  The client cannot send a fact, counter, public
key, App ID, bundle version, browser cookie, session, key receipt, or accepted
registration claim.

Before accepting that envelope, Monas calls Pistis'
``ProductionAppleAppAttestAcceptanceFactoryV1`` with its existing server-held
ceremony state and a bounded iPhone registration envelope.  The factory loads
only the release-pinned reviewed Monas manifest and Apple App Attestation Root
CA; it verifies the registration CBOR/x5c chain, Apple nonce extension,
credential key, production RP-ID/AAGUID, and exact client-data hash.  Only
then does it return an opaque ``ServerHeldMonasAppAttestAcceptanceV1``.  The
type has no public constructor.  Monas supplies only all of these server-held
facts:

* the exact installation, iPhone device, registered key, non-zero ceremony,
  canonical Proxenos payload, Pistis intent, and host issuance time;
* the registered P-256 public key, whose SHA-256 is exactly the registered
  Pistis key ID;
* the previous durable App Attest counter;
* the reviewed Apple trust-anchor manifest digest; and
* the expected distributed application bundle version.

No HTTP client, browser, local Unix user, PAM helper, CLI, cookie, raw Apple
object, or operating-system identity can substitute for that factory.  If the
registration, trust material, or atomic Monas store is unavailable, the
operation is unavailable and no fact is issued.

Apple assertion validation
--------------------------

The production App ID is exactly
``C7A6NQTSY4.org.mnemosynebiosciences.pistis``.  The verifier decodes a
bounded definite CBOR assertion object containing exactly ``signature`` and
``authenticatorData``.  It validates:

* the registered P-256 key's DER signature over
  ``SHA-256(authenticatorData || SHA-256(clientData))``;
* the authenticator RP-ID hash for the exact production App ID;
* user-present plus extension flags;
* a non-zero counter strictly greater than the server-held previous counter;
* the exact production distribution category (TestFlight, App Store, or
  enterprise/ad-hoc) and expected bundle version in Apple's extension map; and
* the exact server-held challenge binding.

``clientData`` is never accepted from the client.  It is defined as the bytes
``"mnemosyne.pistis.site-trust-app-attest-client-data.v1\\0" || challenge``.
``challenge`` is the existing Pistis domain-separated digest over installation,
device, registered key, ceremony, canonical payload, exact intent, and host
issuance time.  The iPhone therefore supplies
``SHA-256(clientData)`` to ``DCAppAttestService.generateAssertion``.  The
assertion envelope contains neither value.

``fixtures/app-attest/site-trust-assertion-client-data-v1.json`` is the shared
non-production known-answer vector for those exact bytes and hash. It is
checked by the Rust ingress suite and is intended for the iPhone client's unit
tests. It contains no Apple evidence, assertion, key, ceremony, receipt, or
session material and cannot activate the route.

Apple does not put a certificate chain into an assertion.  Apple-root and
production-AAGUID validation therefore happen in Pistis' registration factory
before it creates the opaque server-held acceptance; the assertion verifier
never trusts an iPhone-supplied trust bundle or registration receipt.  Monas
still owns the one-use registration ceremony, replay record, later session,
counter state, and final Site Trust transaction.

Atomic fact issuance
--------------------

After signature and binding validation, Pistis constructs the existing opaque
``mnemosyne.pistis.site-trust-human-authority-fact.v1`` and calls only
``MonasSiteTrustAppAttestAtomicStoreV1``.  Monas must persist the verified
counter advance and fact in one rollback-capable durable transaction.  It must
recheck the current counter while holding its transaction, reject replay or a
stale acceptance snapshot, and leave no partial counter or fact after failure.
Pistis contains no counter database or compatibility store.

The successful result contains only the opaque fact and a deterministic
redacted vector of digests and counter.  Raw assertions, client data, Apple
objects, receipts, public keys, tokens, cookies, and private keys are not
retained, surfaced in errors, or emitted in debug output.

Typed Monas session handoff
---------------------------

``pistis-monas`` 0.5.0 can bind only that opaque verified fact to one exact
``authenticate-session`` completion request through
``MonasAppAttestSessionHandoffV1``. Its fixed, bounded canonical record binds
the fact and ceremony identifiers, Proxenos-payload digest, Pistis intent,
installation, immutable Prosopikon principal, external binding, iPhone and
key, policy/revocation generations, authentication time, and non-zero audit
correlation. It carries no raw assertion or browser credential.

The handoff does not issue a session. Monas must consume the fact using its
exact one-use request, re-resolve all current bindings, invalidate
pre-authentication state, request the normal protected Prosopikon session, and
append audit evidence in one rollback-capable transaction. Missing readiness,
wrong purpose, stale authority, fact substitution, local/OS identity, cookies,
PAM, CLI input, and any fallback are denied before session issuance.

Validation
----------

Run the focused Rust contract suite before integrating a transport adapter::

   cargo fmt --check
   cargo test -p pistis-monas
   cargo clippy -p pistis-monas -- -D warnings

Production activation additionally requires Monas wiring to the reviewed
factory and atomic store implementation, Apple production registration evidence for the current
bundle version, a physical-iPhone assertion vector, and an end-to-end retained
Monas/Proxenos dossier.  Unit-generated P-256 vectors prove only parser and
binding behaviour; they are not Apple evidence and cannot activate a route.
