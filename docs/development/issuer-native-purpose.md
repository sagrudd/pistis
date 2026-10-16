# Explicit native-purpose attendance

This compatible source addition implements the phone side of the separately attended native-installation and new-purpose operation in adopted INT-07 design `9a84279611dc442e77f3ad2b3ad948777cf60039c837563bb79e57ffd00188cd`. It uses the existing enrolled ACK key. Root admission, existing enrolment, current-status signatures and certificate recovery retain their separate purposes.

## Request and review

`NativeInstallApprovalTask` recognises only canonical task kind 8 with the exact BODY10, capture24, policy6 and scope9 graph. Task field 4 is the canonical selection8 comparison original from policy6, bounded to 4096 bytes. It supplies no ACK registration or delegation authority. Opaque registration-shaped values, unknown fields and byte mismatches are rejected.

The parser compares the stable installation, Site and purpose lifecycle, fixed issuer purpose, ACK target and SiteRoot hash, all three distinct P-256 requested public keys, their explicit ES256 and generation-1 purposes, source expiry, supported canonical measurement and placement joins. Initialisation is prospective; the request does not claim an existing generation, issuance floor or namespace. The supported policy permits no recovery, replacement or restore. Restart, loss, rollback and uncertain consumption remain locked; a new UUID cannot reset that rule.

Settings → Source approvals → Review native issuer installation opens a setup notice and the bounded public-plan file review screen. Navigation invokes no import, network request, authentication or signing. The review shows the installation, Site, source, requested W/P/T keys and purposes, stable lifecycle and no-recovery rule before the separate Face ID action. It accepts no URL, deep link, QR-derived trust or caller-supplied trusted key.

## Existing-key approval and transport

The operation independently resolves the retained installation, enrolled Site and device, SiteRoot and selected existing ACK key and generation. Request fields compare with these sources; parsing and a body hash supply no authority. The key invocation boundary validates the actual selected key again and signs the complete body once, within the original task end and a two-second post-authentication fence. Cancellation, changed keys and expiry deny invocation or completion.

A device-only Keychain marker keyed by the stable lifecycle is consumed before signing. It does not replace the server's independently required durable consume owner. Ambiguous delivery, cancellation and dismissal are terminal. No reset or replacement-key fallback is provided.

Closed plan7, prepare8, submission6 and accepted6 codecs retain a phone-generated nonce distinct from the body's server nonce. One actual native authenticated phone session remains bound across review and submission. Fixed pinned-origin routes preserve the original deadline and reject cookies, response compression, adjacent paths and mismatched receipts. Preparation alone cannot display acceptance. Current server permission, revocation and protected P-owner checks must remain live and be repeated with genuine owners on submission.

## Executed qualification and remaining gates

The qualification executes 25 distinct tests in 25 executions across two reviewed source snapshots: ten portable `NativeInstallApprovalTests`, fourteen selected platform tests and one Settings-to-empty-review UI test. The fourteen cover native-session ownership and exact request binding, finalisation joins, signature invocation cancellation/key/deadline boundaries, and fixed SiteRoot/native-session transport. The UI test imports no plan and performs no authentication or signing.

The first app compilation failed on two unique errors in the signer. PH8 adds the missing PistisCore import and explicit SecKey closure types. All 678 other mapped source files remain unchanged, including every portable product and test input; the ten portable cases were retained, and the fourteen platform cases plus UI case passed on PH8. The resulting unsigned simulator app is version 0.27.0, build 74. The owned simulator was removed, the default runtime mapping restored and the build lease returned. Earlier controller and compiler failures remain in the qualification evidence; they are not replaced by the passing result.

These 25 cases are separate from the earlier joint Root component's 29-case history. They do not constitute Rust-to-Monas golden-vector qualification, physical Face ID, device installation or a live approval. The paired server submission currently returns HTTP 503; the screen explicitly reports completion unavailable. The genuine public-plan producer, server fresh acceptance, durable origin, combined native authority tests, final Kanon binding, genuine Jenkins CI and protected merge remain required. No installed effect is claimed.
