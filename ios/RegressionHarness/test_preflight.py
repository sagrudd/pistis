"""Fail-closed regression checks for source inputs and approved policy coverage."""

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import preflight


class IntegratedSourceInputTests(unittest.TestCase):
    def setUp(self):
        self.recipe = json.loads((preflight.HERE / "recipe.json").read_text())
        self.run = subprocess.run

    def observe(self, recipe=None, tamper=None):
        def run(command, **kwargs):
            result = self.run(command, **kwargs)
            if tamper:
                result.stdout = tamper(command, result.stdout)
            return result

        with patch("preflight.json.loads", return_value=recipe or self.recipe), \
                patch("preflight.subprocess.run", side_effect=run):
            return preflight.integrated_source_inputs(preflight.REPOSITORY)[
                "matches_pinned_integrated_source"]

    def test_exact_integrated_inputs_match(self):
        self.assertTrue(self.observe())

    def test_substituted_baseline_or_blob_fails(self):
        baseline = self.recipe["integrated_source_baseline"]
        for field in ("revision", "tree"):
            recipe = copy.deepcopy(self.recipe)
            recipe["integrated_source_baseline"][field] = "0" * 40
            with self.subTest(field=field):
                self.assertFalse(self.observe(recipe))
        for path in baseline["source_blobs"]:
            recipe = copy.deepcopy(self.recipe)
            recipe["integrated_source_baseline"]["source_blobs"][path] = "0" * 40
            with self.subTest(path=path):
                self.assertFalse(self.observe(recipe))

    def test_missing_extra_or_unknown_source_paths_fail(self):
        for changed in (b"", b"ios/PistisCore/Unexpected.swift\0"):
            with self.subTest(changed=changed):
                self.assertFalse(self.observe(tamper=lambda command, raw:
                    changed if "--name-only" in command else raw))
        recipe = copy.deepcopy(self.recipe)
        recipe["integrated_source_baseline"]["source_blobs"].pop(".mnemosyne/expedition.json")
        self.assertFalse(self.observe(recipe))

    def test_changed_working_bytes_or_non_regular_committed_source_fails(self):
        for marker, replacement in (("hash-object", b"0" * 40), ("ls-tree", b"120000 blob forged")):
            with self.subTest(marker=marker):
                self.assertFalse(self.observe(tamper=lambda command, raw:
                    replacement if marker in command else raw))

    def test_unreadable_recipe_or_git_source_fails(self):
        with patch("preflight.json.loads", return_value={}):
            self.assertFalse(preflight.integrated_source_inputs(preflight.REPOSITORY)[
                "matches_pinned_integrated_source"])
        with patch("preflight.subprocess.run", side_effect=OSError):
            self.assertFalse(preflight.integrated_source_inputs(preflight.REPOSITORY)[
                "matches_pinned_integrated_source"])


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
