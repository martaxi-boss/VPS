"""Offline regression checks: generic Owner-scoped targets, never tokens/network."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest

from ops import agent_switch, coordinator_phase_continuation, project_target

ROOT = Path(__file__).resolve().parents[2]
REVISION = "a" * 40


def audit(target: str, phased: bool = False) -> dict:
    findings = [
        {"id": "one", "severity": "low", "paths": ["docs/one.md"],
         "observation": "The first inspected guide has an outdated safe example"},
    ]
    items = [
        {"id": "correct-one", "paths": ["docs/one.md"], "finding_ids": ["one"],
         "task": "Correct the first verified guide using existing conventions"},
    ]
    if phased:
        findings.append(
            {"id": "two", "severity": "low", "paths": ["docs/two.md"],
             "observation": "Second guide depends on the verified first correction"})
        items.append(
            {"id": "correct-two", "paths": ["docs/two.md"], "finding_ids": ["two"],
             "depends_on": ["correct-one"],
             "task": "Correct the second guide only after the first integration"})
    return {
        "target_repository": target,
        "audit": {"revision": REVISION, "findings": findings, "work_items": items},
    }


def encoded(value: dict) -> str:
    return base64.b64encode(json.dumps(value, sort_keys=True).encode()).decode()


class TargetIdentityTests(unittest.TestCase):
    def test_existing_and_future_owner_repositories(self):
        for target in ("martaxi-boss/VPS", "martaxi-boss/Project-leader-codex",
                       "martaxi-boss/pink-iptv", "martaxi-boss/future-project-42"):
            with self.subTest(target=target):
                self.assertTrue(project_target.is_managed_target(target))
                self.assertEqual(
                    project_target.from_owner_order(
                        "TARGET_REPOSITORY=" + target + "\n\nResolve the documented defect"),
                    target)

    def test_cross_owner_and_path_injection_fail_closed(self):
        invalid = (None, 123, "", "other-owner/new-app", "../VPS", "/VPS",
                   "martaxi-boss/../VPS", "martaxi-boss/new/app",
                   "martaxi-boss/app.git", "martaxi-boss/.hidden",
                   "martaxi-boss/app..name", "martaxi-boss/app.",
                   "martaxi-boss/app\nTOKEN=bad", "martaxi-boss/evil?ref=main")
        for target in invalid:
            with self.subTest(target=target):
                self.assertFalse(project_target.is_managed_target(target))
        for bad_order in ("", "Fix the app", "TARGET_REPOSITORY=other/new\nFix",
                          "TARGET_REPOSITORY=martaxi-boss/VPS X\nFix",
                          "TARGET_REPOSITORY=martaxi-boss/VPS\r\nFix"):
            with self.subTest(order=bad_order):
                with self.assertRaises(project_target.TargetRefused):
                    project_target.from_owner_order(bad_order)

    def test_remote_validator_cli_rejects_wrong_owner(self):
        script = ROOT / "ops/project_target.py"
        for target, accepted in (("martaxi-boss/future-app", True),
                                 ("other-owner/future-app", False)):
            result = subprocess.run([sys.executable, str(script), "validate", target],
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode == 0, accepted)
            self.assertEqual(result.stdout, b"")


class GenericCoordinatorTests(unittest.TestCase):
    def test_new_project_plan_routes_one_worker_with_real_target(self):
        target = "martaxi-boss/future-project-42"
        plan, phases = agent_switch.parse_coordinator_envelope(encoded(audit(target)))
        self.assertEqual(plan["target_repository"], target)
        self.assertEqual(phases["phase_count"], 1)
        self.assertEqual(agent_switch.workflow_values(plan)["task_count"], "1")

    def test_next_phase_cannot_change_target(self):
        target = "martaxi-boss/future-project-42"
        base = encoded(audit(target, phased=True))
        next_phase = coordinator_phase_continuation.prepared_phase(base, 2, "b" * 40)
        self.assertEqual(next_phase["target_repository"], target)
        plan = json.loads(base64.b64decode(next_phase["coordinator_plan_b64"]))
        self.assertEqual(plan["target_repository"], target)
        self.assertEqual(plan["audit"]["revision"], "b" * 40)

    def test_gateway_binds_model_to_owner_issue_and_scope(self):
        owner = (ROOT / ".github/workflows/coordinator-owner-order.yml").read_text()
        switch = (ROOT / ".github/workflows/agent-switch.yml").read_text()
        phase = (ROOT / ".github/workflows/coordinator-phase-cycle.yml").read_text()
        worker = (ROOT / ".github/workflows/codex-autonomous.yml").read_text()
        remote = (ROOT / "ops/coordinator-smoke-remote.sh").read_text()
        self.assertIn("from_owner_order(body)", owner)
        self.assertIn("order['target_repository'] != expected_target", owner)
        self.assertIn("order['target_repository'] != issue_target", switch)
        self.assertIn("plan['target_repository'] != target", phase)
        self.assertIn("info.get('permissions', {}).get('push') is not True", owner)
        self.assertIn("info.get('default_branch') != 'main'", owner)
        self.assertIn("info.get('private') is not False", owner)
        self.assertIn("from_owner_order(task)", worker)
        self.assertIn('python3 "$control/ops/project_target.py" validate "$slug"', remote)
        self.assertNotIn("StrictHostKeyChecking=no", owner)


if __name__ == "__main__":
    unittest.main()
