"""Offline checks: adaptive effort, private usage tracking and safe replay denial."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

from ops import codex_resource_policy as policy


class AdaptiveCodexResourceTests(unittest.TestCase):
    def task(self, text, **extras):
        return {"task": text, **extras}

    def test_reasoning_lower_middle_higher_and_explicit_override(self):
        self.assertEqual(
            policy.choose_effort(self.task("Corrige um typo no README da interface PINK IPTV")),
            "low",
        )
        self.assertEqual(
            policy.choose_effort(self.task("Implement the channel list and validate playback")),
            "medium",
        )
        self.assertEqual(
            policy.choose_effort(self.task("Diagnose a race condition causing WireGuard lease collisions")),
            "high",
        )
        self.assertEqual(
            policy.choose_effort(self.task("Corrige um typo no README", reasoning_effort="high")),
            "high",
        )
        for invalid in ("xhigh", "ultra", None, 1):
            with self.subTest(invalid=invalid), self.assertRaises(policy.BudgetError):
                policy.choose_effort(self.task("Normal bounded work", reasoning_effort=invalid))

    def test_two_real_reservations_share_private_usage_ledger(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            first = policy.reserve(root, "100-1-1", "medium")
            second = policy.reserve(root, "100-1-2", "high")
            self.assertEqual(first["reserved_tokens"], 35000)
            self.assertEqual(second["reserved_tokens"], 75000)
            self.assertEqual(second["tracked_24h_tokens_estimate"], 110000)
            self.assertEqual(second["quota_source"], "provider_not_available_in_cli")
            self.assertNotIn("budget_remaining_estimate", second)
            result = policy.settle(root, "100-1-1", {
                "observed": True,
                "input_tokens": 40000,
                "cached_input_tokens": 30000,
                "output_tokens": 12000,
            })
            self.assertEqual(result["accounted_tokens"], 52000)
            self.assertTrue(result["observed"])
            ledger = json.loads((root / "usage-budget.json").read_text())
            self.assertEqual(len(ledger["records"]), 2)
            self.assertEqual(ledger["records"][0]["actual"], 52000)
            self.assertNotIn("WireGuard", json.dumps(ledger))
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "usage-budget.json").stat().st_mode), 0o600)
            self.assertTrue(policy.settle(root, "100-1-1", {
                "observed": False
            })["already_settled"])

    def test_unobserved_early_failure_counts_conservative_reservation(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            policy.reserve(root, "101-1", "high")
            result = policy.settle(root, "101-1", {"observed": False})
            self.assertFalse(result["observed"])
            self.assertEqual(result["accounted_tokens"], 75000)
            # The 24-hour amount is accounting data, not a fabricated cap:
            next_turn = policy.reserve(root, "101-2", "medium")
            self.assertEqual(next_turn["tracked_24h_tokens_estimate"], 110000)
            with self.assertRaisesRegex(policy.BudgetError, "Already reserved"):
                policy.reserve(root, "101-1", "low")

    def test_observed_usage_above_old_300k_cap_does_not_block_real_quota(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            policy.reserve(root, "110-1", "low")
            policy.settle(root, "110-1", {
                "observed": True, "input_tokens": 380000,
                "cached_input_tokens": 350000, "output_tokens": 25000,
            })
            # A stale environment override cannot reintroduce the old budget.
            from unittest import mock
            with mock.patch.dict(os.environ, {"CODEX_SOFT_24H_TOKEN_LIMIT": "100000"}):
                more = policy.reserve(root, "110-2", "high")
            self.assertEqual(more["tracked_24h_tokens_estimate"], 480000)
            self.assertEqual(more["quota_source"], "provider_not_available_in_cli")

    def test_concurrent_distinct_reservations_both_recorded_atomically(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            barrier = threading.Barrier(2)
            succeeded, blocked = [], []

            def worker(job):
                barrier.wait(timeout=5)
                try:
                    policy.reserve(root, job, "high")
                    succeeded.append(job)
                except policy.BudgetError:
                    blocked.append(job)

            left = threading.Thread(target=worker, args=("102-1-1",))
            right = threading.Thread(target=worker, args=("102-1-2",))
            left.start()
            right.start()
            left.join(timeout=10)
            right.join(timeout=10)
            self.assertFalse(left.is_alive() or right.is_alive())
            self.assertEqual(len(succeeded), 2)
            self.assertEqual(len(blocked), 0)
            rows = json.loads((root / "usage-budget.json").read_text())["records"]
            self.assertEqual(len(rows), 2)
            self.assertEqual({r["job"] for r in rows}, {"102-1-1", "102-1-2"})

    def test_concurrent_duplicate_identity_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            barrier = threading.Barrier(2)
            outcomes = []
            def duplicate():
                barrier.wait(timeout=5)
                try:
                    policy.reserve(root, "111-1-1", "low")
                    outcomes.append("reserved")
                except policy.BudgetError:
                    outcomes.append("duplicate")
            jobs = [threading.Thread(target=duplicate) for _ in range(2)]
            for job in jobs:
                job.start()
            for job in jobs:
                job.join(timeout=10)
            self.assertEqual(sorted(outcomes), ["duplicate", "reserved"])
            rows = json.loads((root / "usage-budget.json").read_text())["records"]
            self.assertEqual(len(rows), 1)

    def test_legacy_shared_parent_can_remain_unmodified_and_ledger_stays_private(self):
        # Deployed bridge parent predates the 0700 rule. Do not change its
        # existing 0755 permissions, as the legacy Codex entrypoints share it.
        with tempfile.TemporaryDirectory() as location:
            parent = Path(location) / "codex-bridge"
            parent.mkdir(mode=0o755)
            os.chmod(parent, 0o755)
            root = parent / ".account-budget"
            policy.reserve(root, "106-1-1", "low")
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "usage-budget.json").stat().st_mode), 0o600)
            self.assertEqual(policy.settle(root, "106-1-1", {"observed": False})["accounted_tokens"], 12000)
            remote = (Path(__file__).resolve().parents[1] / "codex-autonomous-remote.sh").read_text()
            self.assertIn('budget_root="$HOME/codex-bridge/.account-budget"', remote)
            self.assertNotIn('chmod 700 "$HOME/codex-bridge"', remote)

    def test_bad_usage_and_bad_identifiers_fail_closed(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            policy.reserve(root, "103-1", "low")
            for bad in (
                {"observed": True, "input_tokens": 5, "output_tokens": 2, "cached_input_tokens": 8},
                {"observed": True, "input_tokens": "5", "output_tokens": 2, "cached_input_tokens": 0},
            ):
                with self.assertRaises(policy.BudgetError):
                    policy.settle(root, "103-1", bad)
            with self.assertRaises(policy.BudgetError):
                policy.reserve(root, "../../evil", "low")
            with self.assertRaises(policy.BudgetError):
                policy.reserve(root, "103-2", "xhigh")

    def test_cli_permitted_path_and_true_accounting_only(self):
        source = Path(policy.__file__).resolve()
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            proc = subprocess.run(
                [sys.executable, str(source), "reserve", str(root), "105-1-1", "medium"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["reserved"])
            usage = Path(location) / "usage.json"
            usage.write_text(json.dumps({
                "observed": True, "input_tokens": 3000,
                "cached_input_tokens": 2500, "output_tokens": 1000
            }))
            settled = subprocess.run(
                [sys.executable, str(source), "settle", str(root), "105-1-1", str(usage)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(settled.returncode, 0, settled.stderr)
            self.assertEqual(json.loads(settled.stdout)["accounted_tokens"], 4000)


if __name__ == "__main__":
    unittest.main()
