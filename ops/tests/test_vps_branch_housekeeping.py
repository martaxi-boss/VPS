"""Prove branch hygiene cannot delete active, unique, recent or protected refs."""
import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch
from datetime import datetime, timezone
import vps_branch_housekeeping as bh


class BranchHygieneTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.main = "b" * 40
        self.old = bh.MIN_AGE_SECONDS + 100

    def test_only_fully_merged_old_branch_can_be_candidate(self):
        self.assertTrue(bh.eligible("builder/merged-demo", self.sha, self.main,
                                    self.old, set(), False, True))

    def test_open_pr_and_unmerged_unique_work_preserved(self):
        self.assertFalse(bh.eligible("builder/important", self.sha, self.main,
                                     self.old, {"builder/important"}, False, True))
        self.assertFalse(bh.eligible("builder/important", self.sha, self.main,
                                     self.old, set(), False, False))

    def test_control_security_ops_and_current_work_preserved(self):
        for name in ("main", "control/merge-authorization-1", "security/host-key",
                     "ops/recovery", "release/current", "governance/planner"):
            self.assertFalse(bh.eligible(name, self.sha, self.main,
                                         self.old, set(), False, True))

    def test_workflow_reference_recent_branch_and_protection_preserved(self):
        self.assertFalse(bh.eligible("fix/actively-used", self.sha, self.main,
                                     self.old, set(), True, True))
        self.assertFalse(bh.eligible("fix/recent", self.sha, self.main,
                                     5, set(), False, True))
        self.assertFalse(bh.eligible("fix/protected", self.sha, self.main,
                                     self.old, set(), False, True, True))

    def test_corrupt_ref_sha_cannot_be_candidate(self):
        self.assertFalse(bh.eligible("builder/possible", "not-a-sha", self.main,
                                     self.old, set(), False, True))
        self.assertFalse(bh.eligible("builder/possible", self.sha, "unknown",
                                     self.old, set(), False, True))


    def test_recent_ref_to_old_commit_without_old_exact_pr_is_preserved(self):
        self.assertFalse(bh.eligible("builder/new-ref-at-old-commit", self.sha,
                                     self.main, -1, set(), False, True))

    def test_historical_merged_pr_age_requires_same_head_sha_and_repo(self):
        now = int(datetime(2026, 10, 12, 19, tzinfo=timezone.utc).timestamp())
        previous = "2026-10-09T17:00:00Z"
        raw = "\n".join([
            f"builder/old-pr\t{self.sha}\t{previous}\tmartaxi-boss/VPS",
            f"builder/foreign\t{self.sha}\t{previous}\tsomeone/fork",
            f"builder/different-sha\t{'c'*40}\t2026-10-12T18:00:00Z\tmartaxi-boss/VPS",
        ])
        with patch.object(bh, "command", return_value=(0, raw)) as runner:
            evidence = bh.merged_pr_age_evidence("martaxi-boss/VPS", now)
            self.assertEqual(runner.call_count, 1)
        self.assertIn(("builder/old-pr", self.sha), evidence)
        self.assertNotIn(("builder/foreign", self.sha), evidence)
        self.assertNotIn(("builder/different-sha", "c"*40), evidence)

    def test_dot_yaml_and_dot_yml_both_protect_mentioned_refs(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "a.yaml").write_text("deploy: builder/staging\n")
            (base / "b.yml").write_text("deploy: fix/legacy\n")
            (base / "note.txt").write_text("not a workflow: feat/not-a-workflow\n")
            text = bh.workflow_text(base)
            self.assertIn("builder/staging", text)
            self.assertIn("fix/legacy", text)
            self.assertNotIn("feat/not-a-workflow", text)



if __name__ == "__main__":
    unittest.main()
