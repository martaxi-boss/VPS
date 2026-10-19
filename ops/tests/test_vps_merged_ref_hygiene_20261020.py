"""Pure offline tests for one-time, provably merged VPS ref cleanup."""
from datetime import datetime, timezone
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vps_merged_ref_hygiene_20261020 as h

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)
SHA = "a" * 40
OTHER_SHA = "b" * 40


def branch(name="fix/old-codex", sha=SHA, protected=False):
    return {"name": name, "commit": {"sha": sha}, "protected": protected}


def merged(name="fix/old-codex", sha=SHA, when="2026-10-10T12:00:00Z",
           base="main", repo=h.REPO, number=1):
    return {
        "number": number,
        "merged_at": when,
        "head": {"ref": name, "sha": sha,
                 "repo": {"full_name": repo}},
        "base": {"ref": base, "repo": {"full_name": h.REPO}},
    }


class MergedRefHygieneTests(unittest.TestCase):
    def test_old_exact_merged_pr_is_eligible(self):
        x = h.candidates([branch()], [merged()], [], NOW)
        self.assertEqual(x, [{"name": "fix/old-codex", "sha": SHA, "pr": 1}])

    def test_unmerged_and_unknown_refs_are_untouchable(self):
        unmerged = merged()
        unmerged["merged_at"] = None
        self.assertEqual(h.candidates([branch()], [unmerged], [], NOW), [])
        self.assertEqual(h.candidates([branch()], [], [], NOW), [])

    def test_mismatch_in_head_sha_prevents_deletion(self):
        self.assertEqual(
            h.candidates([branch(sha=OTHER_SHA)], [merged()], [], NOW),
            [],
        )

    def test_recent_merges_wait_seven_days(self):
        self.assertEqual(
            h.candidates([branch()], [merged(when="2026-10-18T00:00:00Z")],
                         [], NOW), [],
        )

    def test_protected_or_open_pr_prevents_cleanup(self):
        self.assertEqual(
            h.candidates([branch(protected=True)], [merged()], [], NOW), [],
        )
        active = {"head": {"ref": "fix/old-codex"}, "base": {"ref": "main"}}
        self.assertEqual(
            h.candidates([branch()], [merged()], [active], NOW), [],
        )

    def test_other_repo_or_non_main_base_never_pruned(self):
        for p in (merged(repo="someone/fork"),
                  merged(base="release"),
                  merged()):
            if p["base"]["ref"] == "main" and p["head"]["repo"]["full_name"] == h.REPO:
                p["base"]["repo"]["full_name"] = "someone/fork"
            self.assertEqual(h.candidates([branch()], [p], [], NOW), [])

    def test_preserve_recovery_and_other_project_refs(self):
        for name in ("main", "master", "release/pink-1",
                     "vault/signing", "security/rollback",
                     "recovery/codex-1", "project-leader/archive",
                     "ops/lowcost-thing", "builder/pink-rollout",
                     "fix/iptv", "ops/fadego-live", "fix/codex-oauth",
                     "fix/owner-secret-test"):
            with self.subTest(name=name):
                self.assertEqual(
                    h.candidates([branch(name)], [merged(name)], [], NOW), [],
                )

    def test_different_prs_reusing_branch_names_are_skipped(self):
        first = merged(number=1, sha=SHA)
        second = merged(number=2, sha=OTHER_SHA)
        self.assertEqual(
            h.candidates([branch()], [first, second], [], NOW), [],
        )

    def test_preserve_branch_referenced_by_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "active.yml").write_text(
                "on:\n  push:\n    branches:\n      - fix/old-codex\n"
            )
            protected = h.workflow_references(root, ["fix/old-codex",
                                                      "fix/other"])
            self.assertEqual(protected, {"fix/old-codex"})
            self.assertEqual(
                h.candidates([branch()], [merged()], [], NOW, protected), [],
            )

    def test_self_cleanup_only_when_merged_and_no_open_pr(self):
        name = h.SELF_BRANCH
        x = h.candidates([branch(name)], [merged(
            name, when="2026-10-20T00:01:00Z")], [], NOW)
        self.assertEqual([y["name"] for y in x], [name])
        pending = [{"head": {"ref": name}, "base": {"ref": "main"}}]
        self.assertEqual(
            h.candidates([branch(name)], [merged(name)], pending, NOW), [],
        )

    def test_guarded_mode_rejects_wrong_repo_without_any_token_request(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "someone/other",
                                      "GITHUB_TOKEN": "not-real"}, clear=False):
            with patch("sys.argv", ["cleanup", "--mode", "clean"]):
                with self.assertRaises(h.HygieneBlocked):
                    h.main()

    def test_invalid_branch_path_is_never_eligible(self):
        for name in ("../main", ".hidden", "fix//twice", "fix/a..b",
                     "fix/../main", "fix/deploy/", "fix/with space"):
            with self.subTest(name=name):
                self.assertFalse(h._is_safe_ref(name))


if __name__ == "__main__":
    unittest.main()
