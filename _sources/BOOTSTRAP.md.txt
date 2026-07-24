# BOOTSTRAP.md

# Purpose

This document instructs a CODEX implementation agent how to initialise and manage the Pistis repository before feature development begins.

The agent SHALL treat this document as the bootstrap contract.

The authoritative design inputs are:

- `PROJECT_CHARTER.md`
- `MILESTONE.md`
- `TODO.md`

The following planning documents are intentionally ignored during bootstrap:

- `EPIC.md`
- `FEATURE.md`
- `TASK.md`
- `SUBTASK.md`
- `ACCEPTANCE_CRITERIA.md`

They may be regenerated later from the canonical sources above.

---

# Bootstrap Objectives

The bootstrap phase has five goals:

1. Create a production-quality repository.
2. Generate a comprehensive GitHub planning corpus from the charter, milestones and TODO list.
3. Establish engineering governance.
4. Configure automation and quality gates.
5. Leave the repository in a state ready for iterative implementation.

Bootstrap MUST NOT begin implementation of Pistis features.

---

# Deliverables

Bootstrap SHALL produce at minimum:

- AGENTS.md
- README.md
- CONTRIBUTING.md
- SECURITY.md
- CODE_OF_CONDUCT.md
- LICENSE
- CHANGELOG.md
- VERSION
- ADR directory
- docs/ hierarchy
- issue templates
- pull request template
- GitHub labels
- GitHub milestones
- GitHub project (if available)
- comprehensive issue corpus

---

# AGENTS.md

Generate an `AGENTS.md` describing:

- repository goals
- coding standards
- Rust edition and MSRV
- testing expectations
- documentation expectations
- review requirements
- branching strategy
- commit policy
- semantic versioning policy
- issue workflow
- pull request workflow
- release workflow
- security reporting
- architectural decision records
- expectations for future autonomous agents

Treat AGENTS.md as normative.

---

# GitHub Corpus

Generate GitHub Issues directly from:

- PROJECT_CHARTER.md
- MILESTONE.md
- TODO.md

Expand them into:

- Epics
- Features
- Tasks
- Subtasks

Each issue SHALL include:

- identifier
- title
- detailed description
- dependencies
- estimated effort
- acceptance notes
- documentation requirements
- labels
- milestone
- priority

Tasks should generally represent one to two days of engineering effort.

Subtasks should generally represent less than four hours.

The generated issue graph should be sufficiently detailed that implementation can proceed without re-analysis.

---

# Branch Strategy

Main branch SHALL remain releasable.

Feature work SHALL normally occur in short-lived branches.

Recommended naming:

- feature/<name>
- fix/<name>
- docs/<name>
- refactor/<name>
- security/<name>
- release/<version>

Branches SHALL be pushed to origin.

Completed branches SHALL be merged promptly.

Dangling branches SHALL NOT be tolerated.

Merged branches SHALL be deleted locally and remotely.

---

# Commit Policy

Commit frequently.

Commits SHOULD normally represent one logical change.

Every prompt resulting in repository modification SHALL conclude with:

1. tests
2. documentation updates where required
3. commit
4. push

Work MUST NOT accumulate as large uncommitted changesets.

---

# Semantic Versioning

Adhere strictly to Semantic Versioning.

Rules:

PATCH
- bug fixes
- documentation
- refactoring
- internal improvements

MINOR
- backwards-compatible functionality
- new APIs
- new capabilities

MAJOR
- incompatible protocol changes
- incompatible API changes
- schema incompatibility
- canonical encoding changes

A MAJOR version increment SHALL occur ONLY after explicit agreement between:

- Project Owner
- Development Agent(s)

Autonomous agents MUST NOT independently perform a major version increment.

Version updates SHALL only occur when tasks or groups of tasks are complete.

Never bump versions simply because commits have been made.

---

# Pull Requests

Each feature branch SHALL conclude with a Pull Request.

PRs SHALL include:

- purpose
- linked issues
- testing evidence
- documentation updates
- migration notes if required

---

# Documentation

Documentation SHALL evolve continuously.

Every implementation change should update relevant documentation before merge.

Broken or stale documentation is considered a defect.

---

# Testing

Every implemented task SHALL include:

- unit tests
- integration tests where appropriate
- regression tests for discovered defects

No bug fix is complete without a regression test.

---

# ADRs

Architectural decisions SHALL be captured in numbered ADRs.

Protocol changes require ADRs before implementation.

---

# Quality Gates

Before merge:

- formatting
- linting
- tests
- documentation
- dependency audit
- licence audit

must succeed.

---

# Security

Bootstrap SHALL establish:

- SECURITY.md
- private vulnerability reporting guidance
- dependency auditing
- supply-chain checks
- reproducible build aspirations

---

# Bootstrap Completion Criteria

Bootstrap is complete only when:

- repository governance exists
- AGENTS.md exists
- issue corpus has been generated
- milestones exist
- labels exist
- templates exist
- CI passes
- documentation builds
- repository is ready for feature implementation

Only after bootstrap completion should work begin on Milestone M1.
