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

[ADR 0023](0023-github-app-device-flow-v0-1.md) is **Accepted**. Numbers 0021
and 0022 remain reserved by earlier unmerged proposals. It supersedes only the
GitHub enrolment transport sections of ADRs 0003, 0007, and 0008 for v0.1;
stable numeric-subject and Prosopikon authority invariants remain unchanged.
