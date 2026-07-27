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
