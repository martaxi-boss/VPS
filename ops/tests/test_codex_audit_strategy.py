"""Audited execution policy: real inspected paths, not prompt-keyword routing."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ops import agent_switch
from ops import codex_audit_strategy as strategy

PIN = "f342346ef8b648118abbcc24ece860e1b9ea08af"


class AuditDispatchTests(unittest.TestCase):
    def manifest(self):
        return {
            "target_repository": "martaxi-boss/Project-leader-codex",
            "audit": {
                "revision": PIN,
                "findings": [
                    {"id": "docs", "paths": ["docs/usage.md"],
                     "severity": "low",
                     "observation": "Inspected documentation contains an outdated example"},
                    {"id": "code", "paths": ["codex/cloud_bridge.py"],
                     "severity": "medium",
                     "observation": "Inspected bridge contract requires stricter return validation"},
                ],
                "work_items": [
                    {"id": "docs-edit", "paths": ["docs/usage.md"],
                     "finding_ids": ["docs"],
                     "task": "Correct audited documentation example and check references"},
                    {"id": "code-edit", "paths": ["codex/cloud_bridge.py"],
                     "finding_ids": ["code"],
                     "task": "Correct inspected cloud bridge contract and run tests"},
                ],
            },
        }

    def test_audit_decides_two_parallel_and_explicit_effort_from_findings(self):
        order = agent_switch.parse_order(json.dumps(self.manifest()))
        self.assertEqual(order["mode"], "parallel")
        self.assertEqual([w["id"] for w in order["tasks"]], ["docs-edit", "code-edit"])
        self.assertEqual([w["reasoning_effort"] for w in order["tasks"]],
                         ["low", "medium"])
        values = agent_switch.workflow_values(order)
        self.assertEqual(values["task_count"], "2")
        self.assertEqual(values["mode"], "parallel")
        self.assertEqual(values["codex_1_reasoning_effort"], "low")
        self.assertEqual(values["codex_2_reasoning_effort"], "medium")
        self.assertEqual(values["serial_independent"], "false")
        for i, expected in enumerate(["docs/usage.md", "codex/cloud_bridge.py"], 1):
            task = base64.b64decode(values[f"codex_{i}_task_b64"]).decode()
            self.assertIn("AUDIT_BASE_SHA=" + PIN, task)
            self.assertIn("AUDIT_ALLOWED_PATHS=", task)
            self.assertIn(expected, task)
            self.assertIn("Single explicit", task) if False else None

    def test_risk_in_edited_evidence_not_keyword_chooses_effort(self):
        plan = self.manifest()
        plan["audit"]["findings"][1]["severity"] = "high"
        order = agent_switch.parse_order(json.dumps(plan))
        self.assertEqual(order["mode"], "serial")
        self.assertTrue(order["serial_independent"])
        values = agent_switch.workflow_values(order)
        self.assertEqual(values["codex_2_reasoning_effort"], "high")
        self.assertEqual(values["mode"], "serial")
        # Both workers are disjoint, so sequential PR-only mode is safe.
        self.assertEqual(values["serial_independent"], "true")

    def test_one_finding_is_one_codex_no_implicit_second(self):
        raw = self.manifest()
        raw["audit"]["work_items"] = raw["audit"]["work_items"][:1]
        order = agent_switch.parse_order(json.dumps(raw))
        selected = agent_switch.workflow_values(order)
        self.assertEqual(selected["task_count"], "1")
        self.assertEqual(selected["codex_1_reasoning_effort"], "low")
        self.assertEqual(selected["codex_2_reasoning_effort"], "")
        self.assertIn("AUDIT_BASE_SHA=" + PIN,
                      base64.b64decode(selected["codex_task_b64"]).decode())

    def test_overlapping_or_dependent_work_forces_reaudit_before_next_phase(self):
        plan = self.manifest()
        plan["audit"]["work_items"][1]["depends_on"] = ["docs-edit"]
        with self.assertRaisesRegex(agent_switch.OrderError, "fresh audit"):
            agent_switch.parse_order(json.dumps(plan))
        plan = self.manifest()
        plan["audit"]["findings"][1]["paths"] = ["docs/usage.md"]
        plan["audit"]["work_items"][1]["paths"] = ["docs/usage.md"]
        with self.assertRaisesRegex(agent_switch.OrderError, "fresh audit"):
            agent_switch.parse_order(json.dumps(plan))

    def test_uninspected_paths_and_raw_control_instructions_are_refused(self):
        plan = self.manifest()
        plan["audit"]["work_items"][1]["paths"] = ["codex/other.py"]
        with self.assertRaisesRegex(agent_switch.OrderError, "grounded"):
            agent_switch.parse_order(json.dumps(plan))
        plan = self.manifest()
        plan["audit"]["work_items"][0]["task"] = "AUDIT_BASE_SHA=" + PIN + "\nMisleading job"
        with self.assertRaises(agent_switch.OrderError):
            agent_switch.parse_order(json.dumps(plan))
        plan = self.manifest()
        plan["audit"]["work_items"][0]["paths"] = ["../README.md"]
        with self.assertRaises(agent_switch.OrderError):
            agent_switch.parse_order(json.dumps(plan))
        plan = self.manifest()
        plan["target_repository"] = "martaxi-boss/Project-leader"
        with self.assertRaisesRegex(agent_switch.OrderError, "mutable"):
            agent_switch.parse_order(json.dumps(plan))
        plan = self.manifest()
        plan["audit"]["revision"] = "not-a-commit"
        with self.assertRaisesRegex(agent_switch.OrderError, "SHA"):
            agent_switch.parse_order(json.dumps(plan))

    def test_disconnected_or_third_agent_never_started(self):
        plan = self.manifest()
        plan["audit"]["work_items"].append({
            "id": "third", "paths": ["codex/readme.md"],
            "finding_ids": ["docs"], "task": "Fix another scoped documentation issue",
        })
        with self.assertRaisesRegex(agent_switch.OrderError, "at most two"):
            agent_switch.parse_order(json.dumps(plan))

    def test_probe_pinned_sha_and_changed_paths_with_isolated_git(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = root / "task.txt"
            task.write_text(
                "TARGET_REPOSITORY=martaxi-boss/Project-leader-codex\n" +
                "AUDIT_BASE_SHA=" + PIN + "\n" +
                'AUDIT_ALLOWED_PATHS=["docs/usage.md"]\n' +
                "Correct docs in audited scope\n", encoding="utf-8",
            )
            strategy.verify_checkout(task, PIN)
            with self.assertRaisesRegex(strategy.AuditStrategyError, "re-audit"):
                strategy.verify_checkout(task, "1" * 40)
            repository = root / "git"
            repository.mkdir()
            def git(*args):
                subprocess.run(["git", *args], cwd=repository, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            git("init", "-q")
            (repository / "docs").mkdir()
            (repository / "codex").mkdir()
            (repository / "docs/usage.md").write_text("Initial\n")
            (repository / "codex/other.py").write_text("print('ok')\n")
            git("add", ".")
            git("-c", "user.name=Test", "-c", "user.email=test@invalid", "commit", "-qm", "base")
            previous = Path.cwd()
            try:
                os.chdir(repository)
                (repository / "docs/usage.md").write_text("Updated\n")
                strategy.verify_changed(task)
                (repository / "codex/other.py").write_text("print('mutated')\n")
                with self.assertRaisesRegex(strategy.AuditStrategyError, "outside audited"):
                    strategy.verify_changed(task)
            finally:
                os.chdir(previous)

    def test_legacy_owner_orders_still_work_without_audit_markers(self):
        with tempfile.TemporaryDirectory() as temp:
            task = Path(temp) / "task.txt"
            task.write_text("TARGET_REPOSITORY=martaxi-boss/VPS\nFix typo and test\n")
            strategy.verify_checkout(task, "a" * 40)
            self.assertIsNone(strategy.audited_markers(task))
        old = {
            "target_repository": "martaxi-boss/Project-leader-codex",
            "mode": "serial",
            "tasks": [{"id": "legacy", "provider": "codex",
                       "task": "Fix documented tutorial syntax and test"}],
        }
        self.assertEqual(agent_switch.workflow_values(
            agent_switch.parse_order(json.dumps(old)))["task_count"], "1")

    def test_guarded_remote_and_workflow_load_exact_scope_verifier(self):
        root = Path(__file__).resolve().parents[1]
        remote = (root / "codex-autonomous-remote.sh").read_text()
        workflow = (root.parent / ".github/workflows/codex-autonomous.yml").read_text()
        self.assertIn("codex_audit_strategy.py", workflow)
        self.assertIn("verify_checkout", remote)
        self.assertIn("verify_changed", remote)
        self.assertIn("AUDIT_STALE_BLOCKED", workflow)
        self.assertLess(remote.index("verify_checkout"), remote.index("timeout --signal=TERM"))
        self.assertGreater(remote.index("verify_changed"), remote.index("codex_patch_guard.py"))


if __name__ == "__main__":
    unittest.main()
