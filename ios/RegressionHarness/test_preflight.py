"""Fail-closed regression checks for the owner-approved policy coverage delta."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import preflight


class DependencyPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = subprocess.run(
            ["git", "-C", str(preflight.REPOSITORY), "show",
             f"{preflight.POLICY_PARENT}:deny.toml"],
            capture_output=True, check=True,
        ).stdout
        cls.approved = preflight.approved_dependency_policy(cls.baseline)

    def observe(self, policy):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deny.toml").write_bytes(policy)
            with patch("preflight.subprocess.run", return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=self.baseline)):
                return preflight.dependency_policy(root)

    def test_approved_policy_matches(self):
        self.assertTrue(preflight.dependency_policy(preflight.REPOSITORY)[
            "matches_approved_coverage_only_policy"])

    def test_missing_or_false_coverage_fails(self):
        for field in (b"include-dev = true\n", b"multiple-versions-include-dev = true\n"):
            for policy in (self.approved.replace(field, b""),
                           self.approved.replace(field, field.replace(b"true", b"false"))):
                with self.subTest(field=field, policy=policy):
                    self.assertFalse(self.observe(policy)["matches_approved_coverage_only_policy"])

    def test_other_policy_mutations_fail(self):
        for old, new in (
            (b'"MPL-2.0",', b'"GPL-3.0",'),
            (b"confidence-threshold = 0.93", b"confidence-threshold = 0.80"),
            (b"ignore = false", b"ignore = true"),
            (b"ignore = []", b'ignore = ["RUSTSEC-2026-0000"]'),
            (b'unmaintained = "all"', b'unmaintained = "workspace"'),
            (b'yanked = "deny"', b'yanked = "warn"'),
            (b'wildcards = "deny"', b'wildcards = "allow"'),
            (b'unknown-git = "deny"', b'unknown-git = "allow"'),
            (b'unknown-registry = "deny"', b'unknown-registry = "allow"'),
            (b'required-git-spec = "rev"', b'required-git-spec = "branch"'),
            (b"thesaurophylax.git", b"unreviewed.git"),
        ):
            with self.subTest(field=old):
                self.assertFalse(self.observe(self.approved.replace(old, new))[
                    "matches_approved_coverage_only_policy"])

    def test_missing_repository_or_policy_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(preflight.dependency_policy(Path(directory))[
                "matches_approved_coverage_only_policy"])
            with patch("preflight.subprocess.run", return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=self.baseline)):
                self.assertFalse(preflight.dependency_policy(Path(directory))[
                    "matches_approved_coverage_only_policy"])

    def test_unreadable_parent_fails(self):
        with patch("preflight.subprocess.run", side_effect=OSError):
            self.assertFalse(preflight.dependency_policy(preflight.REPOSITORY)[
                "matches_approved_coverage_only_policy"])


if __name__ == "__main__":
    unittest.main()
