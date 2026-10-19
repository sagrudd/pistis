#!/usr/bin/env python3
"""Read-only source/tool preflight, never a service or release admission check."""

import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
POLICY_PARENT = "ef00ff34efbb9cfeac9298c9c77f1dc9694162cd"


def approved_dependency_policy(baseline):
    return baseline.replace(
        b'[bans]\nmultiple-versions = "warn"\n',
        b'[bans]\nmultiple-versions = "warn"\nmultiple-versions-include-dev = true\n',
    ).replace(b"[licenses]\n", b"[licenses]\ninclude-dev = true\n")


def dependency_policy(pistis):
    try:
        baseline = subprocess.run(
            ["git", "-C", str(pistis), "show", f"{POLICY_PARENT}:deny.toml"],
            capture_output=True, check=True, timeout=5,
        ).stdout
        actual = (pistis / "deny.toml").read_bytes()
        return {
            "matches_approved_coverage_only_policy": actual == approved_dependency_policy(baseline),
            "sha256": hashlib.sha256(actual).hexdigest(),
        }
    except (OSError, subprocess.SubprocessError):
        return {"matches_approved_coverage_only_policy": False, "sha256": None}


def integrated_source_inputs(pistis):
    """Pin integration deltas without treating this developer recipe as authority."""
    denied = {"matches_pinned_integrated_source": False}

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(pistis), *args],
            capture_output=True, check=True, timeout=5,
        ).stdout

    try:
        recipe = json.loads((HERE / "recipe.json").read_text(encoding="utf-8"))
        baseline = recipe["integrated_source_baseline"]
        revision = baseline["revision"]
        expected = baseline["source_blobs"]
        if git("rev-parse", f"{revision}^{{tree}}").decode().strip() != baseline["tree"]:
            return denied
        git("merge-base", "--is-ancestor", revision, "HEAD")
        changed = git(
            "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", revision,
            "--", "ios/PistisApp", "ios/PistisCore", ".mnemosyne/expedition.json",
        ).decode().rstrip("\0").split("\0")
        if set(changed) != set(expected):
            return denied
        for path, blob in expected.items():
            entry = git("ls-tree", "HEAD", "--", path).decode()
            local = pistis / path
            if (
                entry != f"100644 blob {blob}\t{path}\n"
                or local.is_symlink()
                or local.stat().st_mode & 0o111
                or git("hash-object", "--no-filters", "--", path).decode().strip() != blob
            ):
                return denied
        return {"matches_pinned_integrated_source": True}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return denied


def swift_toolchain():
    if shutil.which("swift"):
        return {"available": True, "on_path": True}
    candidates = [
        Path.home() / ".local/share/swiftly/bin/swift",
        Path(os.environ.get("SWIFTLY_HOME", "/nonexistent")) / "bin/swift",
    ]
    return {
        "available": any(path.is_file() and os.access(path, os.X_OK) for path in candidates),
        "on_path": False,
    }


def git_observation(repository):
    if not (repository / ".git").exists():
        return {"head": None, "clean": None}
    try:
        head = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            capture_output=True, check=True, timeout=5,
        ).stdout.decode("ascii").strip()
        status = subprocess.run(
            ["git", "-C", str(repository), "status", "--porcelain=v1"],
            capture_output=True, check=True, timeout=5,
        ).stdout
        return {
            "head": head if len(head) == 40 and all(c in "0123456789abcdef" for c in head) else None,
            "clean": not status,
        }
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"head": None, "clean": None}


def release_witness(pistis):
    manifest_path = pistis / "ios/PistisApp/pistis-ios-release.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        project = pistis / manifest["xcode_project_path"]
        plist = pistis / manifest["info_plist_path"]
        return {
            "identity": manifest["product_id"] if manifest["product_id"] == "pistis-ios" else None,
            "version": manifest["version"],
            "local_witness_matches": (
                hashlib.sha256(project.read_bytes()).hexdigest() == manifest["xcode_project_sha256"]
                and hashlib.sha256(plist.read_bytes()).hexdigest() == manifest["info_plist_sha256"]
            ),
        }
    except (OSError, ValueError, KeyError, TypeError):
        return {"identity": None, "version": None, "local_witness_matches": False}


def observation():
    return {
        "schema": "pistis.internal-ios-regression.preflight.v1",
        "source_checkouts": {
            "pistis": git_observation(REPOSITORY),
            "kanon": git_observation(REPOSITORY.parent / "kanon"),
        },
        "ios_manifest": release_witness(REPOSITORY),
        "dependency_policy": dependency_policy(REPOSITORY),
        "source_inputs": integrated_source_inputs(REPOSITORY),
        "local_toolchain": {
            "os": platform.system().lower(),
            "swift": swift_toolchain(),
            "cargo_available": shutil.which("cargo") is not None,
            "native_xcode_available": shutil.which("xcodebuild") is not None,
        },
        "service_evidence": {
            "monas": "not_observed",
            "product": "not_observed",
            "site_root": "not_observed",
            "site_x509": "not_observed",
            "app_attest": "not_observed",
        },
        "kanon_lockset": "not_evaluated",
        "package_installation_runtime_acceptance": "unknown",
        "physical_iphone_evidence": "not_observed",
        "qualifies_release": False,
    }


if __name__ == "__main__":
    print(json.dumps(observation(), sort_keys=True, separators=(",", ":")))
