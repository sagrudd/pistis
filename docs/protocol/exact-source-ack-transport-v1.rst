Exact-source ACK attended transport v1
=====================================

This source adapter implements the enrolled-device proof in accepted central
ADR0022 (contract original SHA256
465828463bb214e78f7ddd7652bbfdcfd592674f43d36679364defdcd99d1c15).
It is distinct from the PXRA convergence acknowledgement and from the SiteRoot
IADM/IRCS signing operation. It allocates no key or new signing purpose.

The two fixed HTTPS POST paths are
``/pistis/v1/exact-source-purpose/prepare`` and
``/pistis/v1/exact-source-purpose/submit``. They use the existing pinned
installation origin, native AuthenticateSession profile and Authorization
credential. Browser cookies, redirects, cache delivery and alternate origins
are forbidden. The server authenticates the actual native session/device and
its current role; a TLS response or closed body is not an owner capability.

All bodies are closed canonical CBOR with no trailing bytes, at most 262144
bytes. Prepare is array6 ``[1, "exact-source-ack-prepare-v1" as bstr,
phoneNonce32, kind, enrolledTarget32, enrolledACKGeneration]``, where kind is 1
for enrollment or 2 for technical review. Target and generation are comparison
DATA; the server must freshly select them from the genuine Prox convergence
owner. It never accepts the requested tuple as key authority.

Task is array8 ``[1, "exact-source-ack-task-v1" as bstr, serverTaskUUID16,
echoPhoneNonce32, kind, fullJCSBody, kindOriginals, exclusiveExpiryUnix]``.
The body is the exact accepted ADR0022 closed enrollment or technical-review
body. Its nonce is the independently prepared server task nonce, distinct from
the echoed transport nonce. The task expiry is at most thirty seconds and no
later than any signed-body/role/source ancestor. For enrollment, all thirteen originals are
nonempty, in this order: role decision, exact action, complete source admission,
complete technical-review body, complete installed measurement, old Ed25519
public key32, selected ciphertext SHA25632, successful-load audit, canonical
projection request, exact expectation, independent original review verdict,
governance witness, owner approval/merge witness. Bounds are respectively
8192,8192,16384,8192,32768,32,32,32768,8192,8192,65536,8192,8192 bytes.
For technical review, the exact six originals are current reviewer role, exact
reviewer action, full admission INTENT, independent original verdict, governance
witness, owner approval/merge witness. Their bounds are 8192,8192,16384,65536,
8192,8192 bytes. No enrollment-only original or filler is required before first
review. The phone recomputes the exact review/enrollment INTENT action graph,
including removal only of the allocated final role/action digest fields.

Review proof and review role originals are separately retained on the server
for the subsequent complete business14; they are not replaced by display
witness digests.

The phone compares the task to its current installation enrollment and current
ACK registration, presents every signed field and the bound public originals,
and uses a fresh Face ID context with the existing
``site-root-convergence-ack-v2`` key. Before and after signing it checks that
same registration, public key, target and generation remain current. It never
creates or imports a key. Protected COSE headers contain exactly alg ES256 and
kid equal to the ACK generation as eight big-endian bytes. Unprotected headers
are empty, payload is detached, signature is fixed64 low-S, and proof is at
most 8192 bytes. A sticky background/cancellation observer is installed before the first
preparation await and retained while the task is displayed, through Face ID
and delivery. Explicit view dismissal also permanently invalidates the retained
operation when no async task is running. A context returned after cancellation
cannot bind or invoke a key. Each current check advances a precise observed
wall floor; rollback above the original start is still terminal. Parsed body
and action issue/expiry bounds are checked before and after awaited current
Keychain inspection, with the same original monotonic deadline.
An add-only device-local Keychain invocation fence precedes
the bounded signing invocation. Cancellation, backgrounding, timeout, replay
or uncertain invocation/delivery terminalizes the operation; there is no retry
or secret-delivery status route.

Submit is array6 ``[1, "exact-source-ack-submit-v1" as bstr, sameTaskUUID16,
samePhoneNonce32, SHA256(fullExactTask), fullDetachedCOSE]``. Successful atomic
public-proof retention returns only array4 ``[1, "exact-source-ack-retained-v1"
as bstr, sameTaskUUID16, sameTaskSHA256]``. This is a transport DATA receipt,
not an issuer/native/current-owner capability or an external source proof.

The server retains no live J query or credentials through Face ID. The
separate authenticated J preparation operation can retain the full public
originals for presentation. Before forwarding complete enrollment business to
Prox, a fresh genuine J query must rejoin the exact full originals, request and
expectation, and current role, ACK, native, loaded-custody and lifecycle state.
The independent technical reviewer uses its own current native session and
Reviewer policy. Neither a Root operator session nor matching labels may
replace it. Recorded-owner-exception still requires the allocated full
canonical governance/owner-merge and independent technical-review witnesses.

Implementation status: phone source adapter and tests are authored; matching
M3 HTTP/controller/journal and preparation caller are being integrated. Source
review, actual native qualification and release bindings remain necessary.
No physical phone activation or external issuer authority is claimed here.
