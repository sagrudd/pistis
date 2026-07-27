# Planning issue model

The canonical sources remain `PROJECT_CHARTER.md`, `MILESTONE.md`, and
`TODO.md`. GitHub mirrors them as a navigable execution graph:

- Epics represent the seventeen TODO domains.
- Features group related outcomes within an epic.
- Tasks correspond one-to-one with atomic TODO items.
- Subtasks are checklists inside task issues and are scoped below four hours.

Identifiers use `PIS-E##`, `PIS-E##-F##`, and `PIS-E##-F##-T##`. Dependencies
are explicit in every issue. Tasks are ordered within their feature unless the
issue states that work may proceed in parallel.

The mapping to delivery milestones is:

| TODO epic | Delivery milestone |
| --- | --- |
| 0 Repository | M0 |
| 1 Protocol | M1 |
| 2 Crypto | M2 |
| 3 GitHub trust, 4 Google trust | M3 |
| 5 Device registry | M4 |
| 6 QR authentication | M5 |
| 7 iOS | M6 |
| 9 Synoptikon | M7 |
| 10 Monas | M8 |
| 11 Local discovery | M9 |
| 12 Evidence | M10 |
| 8 Android | M11 |
| 13 Recovery | M12 |
| 14 Security | M13 |
| 15 Release | M15 |
| 16 CLI-native authentication | M8 |

The planning corpus can be reconciled idempotently with
`scripts/bootstrap_github.py`. It creates missing labels, milestones, and
issues, but never deletes or closes existing work.

## Cross-project review records

An ADR that changes an authority, session, protocol, schema, or product trust
boundary names every affected owner. The project owner may accept that ADR once
the review record confirms authority ownership, transaction atomicity, secret
boundaries, negative-path behaviour, and exact-revision Jenkins evidence. This
architectural acceptance does not approve implementation: each subsequent code
pull request identifies its applicable specialist review roles and retains its
own tests and evidence. If a repository prohibits author self-approval, the
documented project-owner decision is the ADR acceptance record.
