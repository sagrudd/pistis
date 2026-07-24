# QR authentication operations

EPIC-6 supplies a framework-neutral, in-memory reference ceremony. It
demonstrates challenge and response QR transfer, direct-local response
submission, redacted browser polling, verified completion, session rotation,
and audit binding. It is not a production HTTP service or durable session
store, and its completion does not close the broader milestone M5 exit gate.

## Reference ceremony

1. Select the intended local account. Initiation creates a new challenge,
   browser capability, and pre-authentication session capability.
2. Show the challenge QR together with the installation name and fingerprint,
   local username, action, and expiry. No authenticated session exists yet.
3. On the signing device, compare those values before approving. Treat a new
   or changed installation fingerprint as a reason to stop and investigate.
4. Return the signed response either through a policy-approved direct-local
   connection or as a response QR. Both modes use the same bounded ingestion
   and verification path.
5. Polling may report a redacted state. Completion separately verifies the
   response and, on approval, atomically consumes the challenge, invalidates
   the pre-authentication capability, rotates the session, and writes audit
   evidence.

A denial records no authenticated session. Expiry, cancellation, malformed
input, a wrong identity or installation, an inactive device, and a conflicting
response all fail closed. Start a new ceremony rather than retrying a terminal
one.

## Camera and accessible fallback

Do not make color, animation, or camera access the only source of instructions
or state. Display a text heading, installation name and fingerprint, username,
action, absolute expiry, and a concise status message with sufficient contrast.
Keep controls keyboard accessible and expose status changes to assistive
technology without repeatedly stealing focus.

Before requesting camera permission, explain why it is needed. If permission
is denied or no camera is available, preserve the challenge and offer the exact
`PISTIS1:` transfer text through an accessible copy/paste or platform-assisted
scanner workflow. The text is sensitive correlation material: avoid clipboard
history where the platform permits, do not include it in screenshots or
support tickets, and clear it after the ceremony. Never ask an operator to
manually edit, normalize, pad, shorten, or split a frame.

If a response QR cannot be captured, retry camera permission or begin a fresh
ceremony using an approved local-transfer adapter. There is no shortened
manual code in v1.

## Direct-local failure

Endpoint hints in the signed challenge are transport metadata, not automatic
authority. A production adapter must enforce its configured HTTPS, hostname,
certificate, request-size, content-type, cookie, CSRF, and rate-limit policy.
Do not disable certificate checks or accept cleartext because a hint appeared
inside a valid signature.

If the local endpoint is unreachable or rejected, keep the public-internet
offline response-QR route available. Network failure must not mark a response
approved, consume the challenge, disclose a capability, or fall back to an
unsigned or bearer-only response.

## Troubleshooting and incident response

| Symptom | Safe action |
| --- | --- |
| Checksum, format, or size rejection | Rescan the complete original frame; never repair it by hand. |
| Challenge expired or was cancelled | Start a new ceremony with a new QR. |
| Installation fingerprint changed | Stop and verify installation recovery or key rotation out of band. |
| Wrong user, identity, action, or installation | Deny and investigate possible QR substitution. |
| Device suspended or revoked | Use the documented registry procedure; do not bypass lifecycle policy. |
| Direct-local endpoint unavailable | Use response QR without weakening HTTPS policy. |
| Response already submitted or completed | Inspect redacted audit/state information; never reuse the response. |
| Completion storage unavailable | Restore durable service before retrying; do not create a session separately. |

Treat unexpected repeated prompts, fingerprint changes, conflicting responses,
or replay attempts as possible substitution or approval-fatigue incidents.
Cancel the challenge, retain redacted audit evidence, inspect local displays
and endpoint configuration, and rotate affected installation or device keys
through the approved recovery process when compromise is suspected.

## Production boundary

Before production use, provide a reviewed HTTP adapter and durable transaction
covering challenge state, session rotation, and immutable audit evidence.
Configure no-store browser responses, secure capability cookies, CSRF
protection, rate limits, metrics, backups, and recovery. Complete the separate
COSE interoperability work before using an external mobile implementation.
