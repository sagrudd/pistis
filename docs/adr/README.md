# Architecture Decision Records

ADRs capture durable architectural decisions and their consequences. Copy
`0000-template.md`, assign the next four-digit number, and open it for review
before implementing protocol, cryptographic, schema, or canonical-encoding
changes.

Statuses are Proposed, Accepted, Superseded, or Rejected. Never rewrite an
accepted decision; supersede it with a new ADR.

Current accepted production-interoperability decisions include:

- [ADR 0018](0018-production-cose-sign1-profile.md), the strict untagged
  COSE Sign1 wire profile; and
- [ADR 0019](0019-mvp-signed-message-schemas.md), the closed integer-key MVP
  enrolment, authentication, and evidence-receipt payloads.

[ADR 0020](0020-prosopikon-pistis-authority-transaction.md) is the accepted
cross-host completion decision. Individual implementation pull requests remain
subject to the review and evidence requirements recorded in that ADR.

[ADR 0021](0021-production-qr-envelope-and-installation-trust.md) accepts the
production QR wrapper, enrolled installation verification-key binding, and
signed approval and denial responses.

[ADR 0022](0022-host-owned-cli-agent-authority-port.md) accepts the
credential-free local-agent to host-authority port. Activation remains gated
on its implementation and cross-repository conformance evidence.

[ADR 0023](0023-authenticated-mobile-enrolment-exchange.md) accepts the
one-use mobile enrolment exchange, invitation-bound authority-key bootstrap,
server-held GitHub callback correlation, and complete signed
installation-trust receipt. Product activation remains blocked until
cross-project implementation review and evidence pass.

[ADR 0024](0024-linux-hardware-signing-providers.md) proposes the
provider-neutral Linux installation-signing boundary, with TPM2 first and
PKCS#11 second. Project-owner direction is approved; implementation remains
blocked pending specialist security and cryptography review.
