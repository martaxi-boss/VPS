"""Offline tests for the generic planner and bounded legacy dispatch."""
import base64
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "agent_switch.py"
spec = importlib.util.spec_from_file_location("agent_switch", SOURCE)
router = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = router
spec.loader.exec_module(router)


class AgentSwitchTests(unittest.TestCase):
    def order(self, tasks=None, target="martaxi-boss/VPS", mode="parallel", **extra):
        manifest = {
            "target_repository": target,
            "mode": mode,
            "tasks": tasks or [self.task("codex-1")],
        }
        manifest.update(extra)
        return json.dumps(manifest)

    @staticmethod
    def task(task_id, provider="codex", text=None, **extra):
        result = {
            "id": task_id,
            "provider": provider,
            "task": text or f"Review and fix the bounded {task_id} documentation defect",
        }
        result.update(extra)
        return result

    def test_one_codex_stays_one_and_preserves_legacy_outputs(self):
        order = router.parse_order(self.order())
        self.assertEqual(len(order["tasks"]), 1)
        data = router.output_values(order)
        self.assertEqual(data["codex"], "true")
        self.assertEqual(data["gemini"], "false")
        self.assertEqual(data["composer"], "false")
        prompt = base64.b64decode(data["codex_task_b64"]).decode()
        self.assertIn("do not create or substitute another agent", prompt)
        plan = json.loads(base64.b64decode(data["dispatch_plan_b64"]))
        self.assertEqual(plan["version"], 1)
        self.assertEqual(plan["tasks"][0]["id"], "codex-1")
        self.assertFalse(plan["execution_policy"]["allow_provider_substitution"])

    def test_two_codex_parallel_are_ordered_and_explicitly_independent(self):
        order = router.parse_order(self.order([
            self.task("codex-1"), self.task("codex-2")
        ], mode="parallel"))
        plan = router.dispatch_plan(order)
        self.assertEqual([task["id"] for task in plan["tasks"]], ["codex-1", "codex-2"])
        self.assertEqual([task["depends_on"] for task in plan["tasks"]], [[], []])
        self.assertTrue(plan["execution_policy"]["parallel_tasks_declared_independent"])
        encoded = router.dispatch_plan_b64(order)
        self.assertEqual(json.loads(base64.b64decode(encoded)), plan)

    def test_two_codex_serial_preserve_order_and_dependencies(self):
        order = router.parse_order(self.order([
            self.task("codex-2"), self.task("codex-1")
        ], mode="serial"))
        plan = router.dispatch_plan(order)
        self.assertEqual([task["id"] for task in plan["tasks"]], ["codex-2", "codex-1"])
        self.assertEqual(plan["tasks"][0]["depends_on"], [])
        self.assertEqual(plan["tasks"][1]["depends_on"], ["codex-2"])

    def test_multi_agent_plan_is_not_partially_forwarded(self):
        for mode in ("parallel", "serial"):
            order = router.parse_order(self.order([
                self.task("codex-1"), self.task("codex-2")
            ], mode=mode))
            with self.subTest(mode=mode), self.assertRaisesRegex(
                router.OrderError, "exactly one Codex task"
            ):
                router.output_values(order)

    def test_registered_but_disconnected_providers_fail_before_output(self):
        for provider in ("gemini", "composer", "claude"):
            with self.subTest(provider=provider), self.assertRaisesRegex(
                router.OrderError, "unavailable.*No agent started"
            ):
                router.parse_order(self.order([self.task(provider + "-1", provider)]))
        mixed = [self.task("codex-1"), self.task("gemini-1", "gemini")]
        with self.assertRaisesRegex(router.OrderError, "unavailable"):
            router.parse_order(self.order(mixed))

    def test_legacy_task_dictionary_remains_supported(self):
        raw = self.order(tasks={"codex": "Review and fix the bounded documentation typo"})
        order = router.parse_order(raw)
        self.assertEqual(order["tasks"], [{
            "id": "codex", "provider": "codex",
            "task": "Review and fix the bounded documentation typo",
        }])
        self.assertEqual(router.output_values(order)["codex"], "true")

    def test_validated_model_and_reasoning_effort(self):
        task = self.task("codex-1", model="gpt-5.6-sol", reasoning_effort="medium")
        parsed = router.parse_order(self.order([task]))
        self.assertEqual(parsed["tasks"][0]["model"], "gpt-5.6-sol")
        for field, value in (("model", "made-up-model"), ("reasoning_effort", "ultra")):
            with self.subTest(field=field), self.assertRaisesRegex(router.OrderError, "Unauthorized"):
                router.parse_order(self.order([self.task("codex-1", **{field: value})]))

    def test_malformed_and_malicious_inputs_fail_closed(self):
        bad_orders = (
            self.order(target="martaxi-boss/pink-iptv"),
            self.order(mode="sequential"),
            self.order([self.task("cloud-1", "cloud")]),
            self.order([self.task("codex-1"), self.task("codex-1")]),
            self.order([self.task("Codex 1")]),
            self.order([self.task("codex-1", text="short")]),
            self.order([self.task("codex-1", text="Use api_key=abcDEF1231231234 now")]),
            self.order([self.task("codex-1", text="Print ${{ secrets.TOKEN }} safely")]),
            self.order([self.task("codex-1", depends_on=[])]),
            self.order([self.task(f"codex-{index}") for index in range(9)]),
            self.order(unexpected=True),
            self.order() + "{}",
        )
        for raw in bad_orders:
            with self.subTest(raw=raw[:100]), self.assertRaises(router.OrderError):
                router.parse_order(raw)

    def test_cli_block_has_no_dispatch_outputs(self):
        raw = self.order([self.task("codex-1"), self.task("codex-2")])
        result = subprocess.run(
            [sys.executable, str(SOURCE)], input=raw, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("No agent started", result.stderr)
        self.assertNotIn("codex_task_b64=", result.stderr)


    def test_workflow_one_codex_preserves_legacy_dispatch(self):
        order = router.parse_order(self.order(mode="serial"))
        old = router.output_values(order)
        new = router.workflow_values(order)
        for key, value in old.items():
            self.assertEqual(new[key], value)
        self.assertEqual(new["task_count"], "1")
        self.assertEqual(new["codex_1_task_b64"], old["codex_task_b64"])
        self.assertEqual(new["codex_2_task_b64"], "")

    def test_workflow_parallel_two_codex_have_isolated_prompts(self):
        order = router.parse_order(self.order([
            self.task("codex-one"), self.task("codex-two")
        ], mode="parallel"))
        values = router.workflow_values(order)
        self.assertEqual(values["task_count"], "2")
        self.assertEqual(values["mode"], "parallel")
        self.assertEqual(values["codex_task_b64"], "")
        prompts = [
            base64.b64decode(values[f"codex_{i}_task_b64"]).decode("utf-8")
            for i in (1, 2)
        ]
        self.assertIn("worker codex-one of 2", prompts[0])
        self.assertIn("worker codex-two of 2", prompts[1])
        for prompt in prompts:
            self.assertTrue(prompt.startswith("TARGET_REPOSITORY=martaxi-boss/VPS\n"))
            self.assertIn("Do not depend on sibling results", prompt)
        self.assertNotEqual(prompts[0], prompts[1])

    def test_workflow_serial_two_codex_preserve_owner_order(self):
        order = router.parse_order(self.order([
            self.task("codex-second"), self.task("codex-first")
        ], mode="serial"))
        values = router.workflow_values(order)
        self.assertEqual(values["mode"], "serial")
        prompts = [
            base64.b64decode(values[f"codex_{i}_task_b64"]).decode("utf-8")
            for i in (1, 2)
        ]
        self.assertIn("worker codex-second of 2", prompts[0])
        self.assertIn("worker codex-first of 2", prompts[1])
        self.assertIn("previous stage must complete", prompts[1])

    def test_workflow_rejects_three_workers_instead_of_partial_run(self):
        order = router.parse_order(self.order([
            self.task("codex-one"), self.task("codex-two"), self.task("codex-three")
        ], mode="parallel"))
        with self.assertRaisesRegex(router.OrderError, "whole unsupported plan"):
            router.workflow_values(order)



if __name__ == "__main__":
    unittest.main()
