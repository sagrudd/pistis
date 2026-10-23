# INT-07 Pistis iOS continuation

Current source group: Pistis iOS 0.28.0+75, existing product and bundle identity.
The Mac approval delta from b3aa801 is applied onto maintained main 9be08625;
unrelated current source and frozen Rust dependencies are retained.

The existing enrolled TLS/native session carries deliberate Mac Pending approval,
with full enrolment, ACK, stream, digest and original-deadline comparisons. No
new wire schema, signing key purpose or custody authority is introduced.

Historical b3aa801 source now has an actual unsigned arm64 simulator build and
five selected Mac-session platform tests passing. This coherent versioned
current source still requires its own affected platform and release-identity
checks. No physical device, Face ID, deployment or full-flow success is claimed.
Main's paired one-use same-Root/Mac bind endpoint is delivered in merged 51568634;
actual installed matching services and genuine current authority remain required.

Governing issues: [MNE-1504](https://linear.app/mnemosyne-biosciences/issue/MNE-1504)
and [MNE-1520](https://linear.app/mnemosyne-biosciences/issue/MNE-1520). The iOS
version allocation is [Kanon PR801](https://github.com/sagrudd/kanon/pull/801),
not the unrelated historical PR772. Adopted paired source contract:
native-origin amendment842f4e40; archive contracts f9338f7b and06362a7a.
Preserve original source, protocol, custody, review and normal merge gates.
