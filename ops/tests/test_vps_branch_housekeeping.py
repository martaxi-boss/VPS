"""Prove branch hygiene cannot delete active, unique, recent or protected refs."""
import unittest
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


if __name__ == "__main__":
    unittest.main()
