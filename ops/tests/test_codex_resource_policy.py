"""Deterministic offline checks: adaptive effort, same-account two-slot soft ledger."""
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

    def test_two_real_reservations_share_private_budget(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            first = policy.reserve(root, "100-1-1", "medium", limit=150000)
            second = policy.reserve(root, "100-1-2", "high", limit=150000)
            self.assertEqual(first["reserved_tokens"], 35000)
            self.assertEqual(second["reserved_tokens"], 75000)
            self.assertEqual(second["budget_remaining_estimate"], 40000)
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
            policy.reserve(root, "101-1", "high", limit=100000)
            result = policy.settle(root, "101-1", {"observed": False})
            self.assertFalse(result["observed"])
            self.assertEqual(result["accounted_tokens"], 75000)
            with self.assertRaisesRegex(policy.BudgetError, "soft budget exhausted"):
                policy.reserve(root, "101-2", "medium", limit=100000)
            with self.assertRaisesRegex(policy.BudgetError, "Already reserved"):
                policy.reserve(root, "101-1", "low", limit=100000)

    def test_concurrent_reserve_is_atomic_and_blocks_second_high_job_at_cap(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location) / "account"
            barrier = threading.Barrier(2)
            succeeded, blocked = [], []

            def worker(job):
                barrier.wait(timeout=5)
                try:
                    policy.reserve(root, job, "high", limit=100000)
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
            self.assertEqual(len(succeeded), 1)
            self.assertEqual(len(blocked), 1)
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
            policy.reserve(root, "106-1-1", "low", limit=100000)
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
            policy.reserve(root, "103-1", "low", limit=100000)
            for bad in (
                {"observed": True, "input_tokens": 5, "output_tokens": 2, "cached_input_tokens": 8},
                {"observed": True, "input_tokens": "5", "output_tokens": 2, "cached_input_tokens": 0},
            ):
                with self.assertRaises(policy.BudgetError):
                    policy.settle(root, "103-1", bad)
            with self.assertRaises(policy.BudgetError):
                policy.reserve(root, "../../evil", "low", limit=100000)
            with self.assertRaises(policy.BudgetError):
                policy.reserve(root, "103-2", "xhigh", limit=100000)

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
