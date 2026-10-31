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
        self.assertEqual(values["audit_managed"], "true")
        self.assertEqual(values["codex_1_reasoning_effort"], "low")
        self.assertEqual(values["codex_2_reasoning_effort"], "medium")
        self.assertEqual(values["serial_independent"], "false")
        for i, expected in enumerate(["docs/usage.md", "codex/cloud_bridge.py"], 1):
            task = base64.b64decode(values[f"codex_{i}_task_b64"]).decode()
            self.assertIn("AUDIT_BASE_SHA=" + PIN, task)
            self.assertIn("AUDIT_ALLOWED_PATHS=", task)
            self.assertIn(expected, task)

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
        self.assertEqual(selected["audit_managed"], "true")
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
        with self.assertRaisesRegex(agent_switch.OrderError, "explicitly present"):
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
        plan["target_repository"] = "untrusted-owner/Project-leader"
        with self.assertRaisesRegex(agent_switch.OrderError, "mutable"):
            agent_switch.parse_order(json.dumps(plan))
        plan = self.manifest()
        plan["audit"]["revision"] = "not-a-commit"
        with self.assertRaisesRegex(agent_switch.OrderError, "SHA"):
            agent_switch.parse_order(json.dumps(plan))

    def test_finding_does_not_expand_file_scope_to_parent_directory(self):
        plan = self.manifest()
        plan["audit"]["findings"][1]["paths"] = ["codex/auth/check.py"]
        plan["audit"]["work_items"][1]["paths"] = ["codex"]
        with self.assertRaisesRegex(agent_switch.OrderError, "explicitly present"):
            agent_switch.parse_order(json.dumps(plan))
        plan = self.manifest()
        plan["audit"]["findings"][1]["paths"] = ["codex"]
        plan["audit"]["work_items"][1]["paths"] = ["codex/other.py"]
        with self.assertRaisesRegex(agent_switch.OrderError, "explicitly present"):
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
                with self.assertRaisesRegex(strategy.AuditStrategyError, "outside exact audited"):
                    strategy.verify_changed(task)
                # Even if a broad owner-supplied scope marker is present,
                # runtime ownership is exact-file, not directory-wide.
                task.write_text(
                    "TARGET_REPOSITORY=martaxi-boss/Project-leader-codex\n" +
                    "AUDIT_BASE_SHA=" + PIN + "\n" +
                    'AUDIT_ALLOWED_PATHS=["codex"]\n' +
                    "Correct explicitly reviewed file only\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(strategy.AuditStrategyError, "outside exact audited"):
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
        self.assertEqual(agent_switch.workflow_values(
            agent_switch.parse_order(json.dumps(old)))["audit_managed"], "false")

    def test_guarded_remote_and_workflow_load_exact_scope_verifier(self):
        root = Path(__file__).resolve().parents[1]
        remote = (root / "codex-autonomous-remote.sh").read_text()
        workflow = (root.parent / ".github/workflows/codex-autonomous.yml").read_text()
        self.assertIn("codex_audit_strategy.py", workflow)
        self.assertIn("verify_checkout", remote)
        self.assertIn("verify_changed", remote)
        self.assertIn("AUDIT_STALE_BLOCKED", workflow)
        router = (root.parent / ".github/workflows/agent-switch.yml").read_text()
        self.assertIn("fromJSON(needs.preflight.outputs.audit_managed)", router)
        self.assertIn("no_auto_merge:", router)
        self.assertLess(remote.index("verify_checkout"), remote.index("timeout --signal=TERM"))
        self.assertGreater(remote.index("verify_changed"), remote.index("codex_patch_guard.py"))



class AuditedPhasePlanTests(unittest.TestCase):
    def base(self):
        return AuditDispatchTests().manifest()

    def test_dependency_graph_selects_two_then_holds_dependent_stage(self):
        audit = self.base()
        audit["audit"]["findings"].append({
            "id": "more-docs", "paths": ["docs/second.md"], "severity": "low",
            "observation": "Second independent documentation correction verified",
        })
        audit["audit"]["work_items"].insert(1, {
            "id": "second-docs", "paths": ["docs/second.md"],
            "finding_ids": ["more-docs"],
            "task": "Fix the second audited documentation example",
        })
        audit["audit"]["work_items"][2]["depends_on"] = ["docs-edit", "second-docs"]
        planned = strategy.plan_phases(audit)
        self.assertEqual(planned["status"], "DRY_PLAN_NO_MODELS_STARTED")
        self.assertEqual(planned["phase_count"], 2)
        first, second = planned["phases"]
        self.assertEqual(first["task_ids"], ["docs-edit", "second-docs"])
        self.assertEqual(first["worker_count"], 2)
        self.assertEqual(first["mode"], "parallel")
        self.assertFalse(first["requires_fresh_audit"])
        self.assertTrue(first["pr_only"])
        self.assertEqual(first["reasoning_by_task"],
                         {"docs-edit": "low", "second-docs": "low"})
        self.assertEqual(
            first["dispatch_json"],
            json.dumps(first["dispatch_audit"], sort_keys=True,
                       separators=(",", ":"), ensure_ascii=True),
        )
        self.assertEqual(
            agent_switch.workflow_values(agent_switch.parse_order(
                first["dispatch_json"]))["mode"], "parallel"
        )
        self.assertLessEqual(len(first["dispatch_json"].encode("utf-8")),
                             strategy.MAX_AUDIT)
        self.assertEqual(second["task_ids"], ["code-edit"])
        self.assertEqual(second["reasoning_by_task"], {"code-edit": "medium"})
        self.assertFalse(second["requires_fresh_audit"])
        self.assertIsNone(second["dispatch_audit"])
        self.assertIsNone(second["dispatch_json"])
        self.assertEqual(second["state"], "HOLD_FOR_CI_AND_NEXT_PHASE")

    def test_high_risk_finding_selects_independent_serial_prs(self):
        audited = self.base()
        audited["audit"]["findings"][1]["severity"] = "high"
        planned = strategy.plan_phases(audited)
        self.assertEqual(planned["phase_count"], 1)
        self.assertEqual(planned["phases"][0]["mode"], "serial")
        self.assertEqual(planned["phases"][0]["reasoning_by_task"]["code-edit"], "high")
        order = agent_switch.parse_order(json.dumps(
            planned["phases"][0]["dispatch_audit"]))
        self.assertTrue(order["serial_independent"])

    def test_overlapping_paths_are_never_parallel_and_require_reaudit(self):
        audited = self.base()
        audited["audit"]["findings"][1]["paths"] = ["docs/usage.md"]
        audited["audit"]["work_items"][1]["paths"] = ["docs/usage.md"]
        result = strategy.plan_phases(audited)
        self.assertEqual(result["phase_count"], 2)
        self.assertEqual([p["worker_count"] for p in result["phases"]], [1, 1])
        self.assertFalse(result["phases"][1]["requires_fresh_audit"])
        self.assertIsNone(result["phases"][1]["dispatch_audit"])

    def test_cyclic_or_unknown_dependency_fails_before_first_dispatch(self):
        audited = self.base()
        audited["audit"]["work_items"][0]["depends_on"] = ["code-edit"]
        audited["audit"]["work_items"][1]["depends_on"] = ["docs-edit"]
        with self.assertRaisesRegex(strategy.AuditStrategyError, "Cyclic"):
            strategy.plan_phases(audited)
        audited["audit"]["work_items"][1]["depends_on"] = ["missing-stage"]
        with self.assertRaisesRegex(strategy.AuditStrategyError, "Unknown"):
            strategy.plan_phases(audited)

    def test_uninspected_deferred_stage_is_rejected_in_full_preflight(self):
        audited = self.base()
        audited["audit"]["work_items"][1]["depends_on"] = ["docs-edit"]
        audited["audit"]["work_items"][1]["paths"] = ["codex/not-a-finding.py"]
        with self.assertRaisesRegex(strategy.AuditStrategyError,
                                    "explicitly present"):
            strategy.plan_phases(audited)

    def test_first_wave_does_not_include_irrelevant_findings(self):
        audited = self.base()
        for number in range(8):
            audited["audit"]["findings"].append({
                "id": "unused-" + str(number),
                "paths": ["docs/unrelated" + str(number) + ".md"],
                "severity": "low",
                "observation": "An unrelated audited observation " + "x" * 450,
            })
        phases = strategy.plan_phases(audited)["phases"]
        self.assertEqual(len(phases), 1)
        payload = phases[0]["dispatch_audit"]
        self.assertEqual({f["id"] for f in payload["audit"]["findings"]},
                         {"docs", "code"})
        self.assertLessEqual(len(json.dumps(payload).encode("utf-8")),
                             strategy.MAX_AUDIT)

    def test_compiled_worker_exceeding_actual_2200_character_ceiling_fails_closed(self):
        audited = self.base()
        long_paths = ["docs/" + "folder" * 25 + "-" + str(i) + ".md"
                      for i in range(12)]
        audited["audit"]["findings"][0]["paths"] = long_paths
        audited["audit"]["work_items"][0]["paths"] = long_paths
        audited["audit"]["work_items"][0]["task"] = (
            "Correct safely scoped file " + "x" * 1500
        )
        with self.assertRaisesRegex(strategy.AuditStrategyError,
                                    "actual executor contract"):
            strategy.plan_phases(audited)

    def test_ascii_escaped_owner_order_cannot_exceed_real_byte_limit(self):
        audited = self.base()
        audited["audit"]["work_items"][0]["task"] = (
            "Review documented semantics " + "\u00e1" * 1200
        )
        with self.assertRaisesRegex(strategy.AuditStrategyError,
                                    "safe dispatch size"):
            strategy.plan_phases(audited)

    def test_more_than_eight_tasks_fail_closed(self):
        audited = self.base()
        audited["audit"]["work_items"] = (
            audited["audit"]["work_items"] * 5
        )
        with self.assertRaisesRegex(strategy.AuditStrategyError, "1-8"):
            strategy.plan_phases(audited)




if __name__ == "__main__":
    unittest.main()
