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
