#!/usr/bin/env python3
"""Create the Pistis GitHub planning corpus from the canonical TODO."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "sagrudd/pistis"

LABELS = {
    "type:epic": ("5319e7", "Planning epic"),
    "type:feature": ("8250df", "User-visible or architectural capability"),
    "type:task": ("1d76db", "Implementation-sized task"),
    "type:bug": ("d73a4a", "Confirmed defect"),
    "status:triage": ("ededed", "Needs triage"),
    "status:ready": ("0e8a16", "Ready for implementation"),
    "status:blocked": ("b60205", "Blocked by a dependency"),
    "priority:P0": ("b60205", "Critical priority"),
    "priority:P1": ("d93f0b", "High priority"),
    "priority:P2": ("fbca04", "Normal priority"),
    "priority:P3": ("c5def5", "Low priority"),
    "area:repository": ("006b75", "Repository and developer experience"),
    "area:protocol": ("0052cc", "Protocol and canonical messages"),
    "area:crypto": ("6f42c1", "Cryptography and verification"),
    "area:trust": ("0366d6", "External trust anchors"),
    "area:device": ("0e8a16", "Device registry and lifecycle"),
    "area:transport": ("1d76db", "QR and local transport"),
    "area:ios": ("d4c5f9", "iOS application"),
    "area:android": ("a4c639", "Android application"),
    "area:integration": ("bfd4f2", "Synoptikon and Monas integration"),
    "area:evidence": ("c2e0c6", "Portable evidence and signing"),
    "area:security": ("ee0701", "Security and privacy"),
    "area:release": ("f9d0c4", "Packaging and release"),
}

MILESTONES = [
    f"M{number} — {title}"
    for number, title in enumerate(
        [
            "Charter reconciliation and delivery baseline",
            "Threat model and protocol specification",
            "Rust workspace and cryptographic foundation",
            "GitHub and Google trust-anchor enrolment",
            "Local installation identity and device registry",
            "QR authentication end-to-end",
            "iOS MVP application",
            "Synoptikon integration",
            "Monas standalone integration and CLI",
            "Local-network discovery and direct exchange",
            "Artefact/report signing and portable evidence",
            "Android application",
            "Recovery, revocation and multi-device lifecycle",
            "Security hardening and independent review",
            "Packaging, operations and documentation",
            "Release candidate and v1.0 acceptance",
        ]
    )
]

EPIC_MILESTONE = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 3, 5: 4, 6: 5, 7: 6, 8: 11,
    9: 7, 10: 8, 11: 9, 12: 10, 13: 12, 14: 13, 15: 15,
}

EPIC_AREA = {
    0: "repository", 1: "protocol", 2: "crypto", 3: "trust", 4: "trust",
    5: "device", 6: "transport", 7: "ios", 8: "android",
    9: "integration", 10: "integration", 11: "transport", 12: "evidence",
    13: "device", 14: "security", 15: "release",
}


@dataclass
class Feature:
    title: str
    tasks: list[str] = field(default_factory=list)


@dataclass
class Epic:
    number: int
    title: str
    features: list[Feature] = field(default_factory=list)


def gh(*arguments: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["gh", *arguments],
        cwd=ROOT,
        input=input_text,
        text=True,
        check=True,
        capture_output=True,
    )
    return result.stdout.strip()


def parse_todo() -> list[Epic]:
    epics: list[Epic] = []
    current_epic: Epic | None = None
    current_feature: Feature | None = None
    for line in (ROOT / "docs/TODO.md").read_text().splitlines():
        epic_match = re.match(r"# EPIC (\d+) — (.+)", line)
        if epic_match:
            current_epic = Epic(int(epic_match.group(1)), epic_match.group(2))
            epics.append(current_epic)
            current_feature = None
            continue
        if line.startswith("## ") and current_epic:
            current_feature = Feature(line[3:])
            current_epic.features.append(current_feature)
            continue
        task_match = re.match(r"- \[[ x~]\] (.+)", line)
        if task_match and current_epic:
            if current_feature is None:
                current_feature = Feature("Delivery")
                current_epic.features.append(current_feature)
            current_feature.tasks.append(task_match.group(1))
    return epics


def existing_issue_ids() -> dict[str, int]:
    output = gh(
        "issue", "list", "--repo", REPOSITORY, "--state", "all",
        "--limit", "1000", "--json", "number,title",
    )
    issues = json.loads(output)
    found: dict[str, int] = {}
    for issue in issues:
        match = re.match(r"\[([^\]]+)\]", issue["title"])
        if match:
            found[match.group(1)] = issue["number"]
    return found


def ensure_labels() -> None:
    current = {
        item["name"]
        for item in json.loads(
            gh("api", f"repos/{REPOSITORY}/labels?per_page=100")
        )
    }
    for name, (color, description) in LABELS.items():
        if name not in current:
            gh(
                "label", "create", name, "--repo", REPOSITORY,
                "--color", color, "--description", description,
            )
            print(f"created label {name}", flush=True)


def ensure_milestones() -> None:
    current = {
        item["title"]
        for item in json.loads(
            gh("api", f"repos/{REPOSITORY}/milestones?state=all&per_page=100")
        )
    }
    for number, title in enumerate(MILESTONES):
        if title not in current:
            gh(
                "api", "--method", "POST", f"repos/{REPOSITORY}/milestones",
                "-f", f"title={title}",
                "-f", "state=open",
                "-f", f"description=Delivery milestone M{number} from docs/MILESTONE.md.",
            )
            print(f"created milestone {title}", flush=True)


def create_issue(
    identifier: str,
    title: str,
    body: str,
    labels: list[str],
    milestone: str,
    known: dict[str, int],
) -> int:
    if identifier in known:
        return known[identifier]
    url = gh(
        "issue", "create", "--repo", REPOSITORY,
        "--title", f"[{identifier}] {title}",
        "--body", body,
        "--milestone", milestone,
        *sum((["--label", label] for label in labels), []),
    )
    number = int(url.rsplit("/", 1)[1])
    known[identifier] = number
    print(f"created {identifier} as #{number}", flush=True)
    return number


def priority_for(epic: int) -> str:
    if epic in {0, 1, 2, 14}:
        return "P1"
    return "P2"


def main() -> None:
    ensure_labels()
    ensure_milestones()
    known = existing_issue_ids()
    previous_epic_id = "None"

    for epic in parse_todo():
        epic_id = f"PIS-E{epic.number:02d}"
        milestone = MILESTONES[EPIC_MILESTONE[epic.number]]
        area = EPIC_AREA[epic.number]
        priority = priority_for(epic.number)
        epic_body = f"""## Description

Deliver the **{epic.title}** domain defined by `docs/TODO.md` and its applicable
acceptance criteria in `docs/MILESTONE.md`.

## Dependencies

{previous_epic_id}

## Estimated effort

Multi-feature epic; estimate and sequence through child issues.

## Acceptance notes

- All child features and tasks are complete.
- Applicable milestone acceptance criteria and repository quality gates pass.
- Security, compatibility, and operational impacts are reviewed.

## Documentation requirements

Keep design, operator, API, and security documentation current. Record
architectural decisions as ADRs.

## Planning metadata

- Identifier: `{epic_id}`
- Type: Epic
- Priority: {priority}
- Milestone: {milestone}
"""
        epic_number = create_issue(
            epic_id, epic.title, epic_body,
            ["type:epic", "status:ready", f"priority:{priority}", f"area:{area}"],
            milestone, known,
        )

        for feature_index, feature in enumerate(epic.features, 1):
            feature_id = f"{epic_id}-F{feature_index:02d}"
            feature_body = f"""## Description

Deliver the **{feature.title}** capability within [{epic_id}](#{epic_number}).

## Dependencies

Parent epic #{epic_number}. Tasks below are ordered unless explicitly noted.

## Estimated effort

Sum of child tasks; each task is scoped to 0.5–2 developer-days.

## Acceptance notes

- Every child task and its subtasks are complete.
- Tests, documentation, auditability, and error handling meet `AGENTS.md`.
- The parent milestone remains releasable.

## Documentation requirements

Update the relevant development, protocol, operations, or security documents.

## Planning metadata

- Identifier: `{feature_id}`
- Type: Feature
- Priority: {priority}
- Milestone: {milestone}
- Parent: #{epic_number}
"""
            feature_number = create_issue(
                feature_id, feature.title, feature_body,
                ["type:feature", "status:ready", f"priority:{priority}", f"area:{area}"],
                milestone, known,
            )
            previous_task = "None"
            for task_index, task in enumerate(feature.tasks, 1):
                task_id = f"{feature_id}-T{task_index:02d}"
                dependency = (
                    f"{previous_task} within feature #{feature_number}"
                    if previous_task != "None"
                    else f"Parent feature #{feature_number}"
                )
                task_body = f"""## Description

Implement **{task}** as the atomic outcome defined by `docs/TODO.md`, while
preserving the charter and architectural invariants.

## Dependencies

{dependency}

## Estimated effort

0.5–2 developer-days.

## Subtasks

- [ ] Design and implementation slice (less than four hours)
- [ ] Tests, negative cases, and fixtures (less than four hours)
- [ ] Documentation and review evidence (less than four hours)

## Acceptance notes

- The named outcome is demonstrably complete.
- Unit tests pass; integration or regression coverage is added where applicable.
- Failure modes are explicit and security-sensitive behavior fails closed.
- Formatting, linting, tests, docs, dependency audit, and license audit pass.

## Documentation requirements

Update relevant public API, protocol, operator, security, or contributor docs;
state explicitly in the PR when no documentation change is necessary.

## Planning metadata

- Identifier: `{task_id}`
- Type: Task with subtasks
- Priority: {priority}
- Milestone: {milestone}
- Parent: #{feature_number}
"""
                create_issue(
                    task_id, task, task_body,
                    ["type:task", "status:ready", f"priority:{priority}", f"area:{area}"],
                    milestone, known,
                )
                previous_task = task_id
        previous_epic_id = epic_id


if __name__ == "__main__":
    main()
