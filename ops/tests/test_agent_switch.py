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

    def test_specialization_is_separate_target_for_parallel_low_workers(self):
        raw = self.order(
            [self.task("smoke-alpha", reasoning_effort="low"),
             self.task("smoke-beta", reasoning_effort="low")],
            target="martaxi-boss/Project-leader-codex", mode="parallel")
        manifest = router.parse_order(raw)
        values = router.workflow_values(manifest)
        self.assertEqual(values["task_count"], "2")
        self.assertEqual(values["mode"], "parallel")
        self.assertEqual(values["codex_1_reasoning_effort"], "low")
        self.assertEqual(values["codex_2_reasoning_effort"], "low")
        for idx in (1, 2):
            prompt = base64.b64decode(
                values[f"codex_{idx}_task_b64"]).decode("utf-8")
            self.assertEqual(prompt.splitlines()[0],
                             "TARGET_REPOSITORY=martaxi-boss/Project-leader-codex")
        self.assertNotEqual(values["codex_1_task_b64"],
                            values["codex_2_task_b64"])

    def test_owner_can_route_two_independent_codex_to_pink_without_auto_merge(self):
        manifest = self.order(
            [self.task("codex-pink-1"), self.task("codex-pink-2")],
            target="martaxi-boss/pink-iptv", mode="parallel")
        order = router.parse_order(manifest)
        outputs = router.workflow_values(order)
        self.assertEqual(outputs["task_count"], "2")
        self.assertEqual(outputs["mode"], "parallel")
        self.assertNotEqual(outputs["codex_1_task_b64"], outputs["codex_2_task_b64"])
        for index in (1, 2):
            task = base64.b64decode(outputs[f"codex_{index}_task_b64"]).decode()
            self.assertEqual(task.splitlines()[0], "TARGET_REPOSITORY=martaxi-boss/pink-iptv")
        self.assertTrue(router.dispatch_plan(order)["execution_policy"]["parallel_tasks_declared_independent"])

    def test_validated_model_and_reasoning_effort(self):
        task = self.task("codex-1", model="gpt-5.6-sol", reasoning_effort="medium")
        parsed = router.parse_order(self.order([task]))
        self.assertEqual(parsed["tasks"][0]["model"], "gpt-5.6-sol")
        for field, value in (("model", "made-up-model"), ("reasoning_effort", "ultra")):
            with self.subTest(field=field), self.assertRaisesRegex(router.OrderError, "Unauthorized"):
                router.parse_order(self.order([self.task("codex-1", **{field: value})]))

    def test_adaptive_effort_is_independent_for_two_parallel_codex_workers(self):
        tasks = [
            self.task("codex-doc", text="Corrige um typo na documentação da VPN",
                      reasoning_effort="auto"),
            self.task("codex-race", text="Investigate a race condition in concurrent VPN leases",
                      reasoning_effort="auto"),
        ]
        order = router.parse_order(self.order(tasks, mode="parallel"))
        values = router.workflow_values(order)
        self.assertEqual(values["codex_1_reasoning_effort"], "low")
        self.assertEqual(values["codex_2_reasoning_effort"], "high")
        plan = json.loads(base64.b64decode(values["dispatch_plan_b64"]))
        self.assertEqual(
            [t["selected_reasoning_effort"] for t in plan["tasks"]],
            ["low", "high"],
        )
        self.assertTrue(all(t["effort_selection"] == "adaptive_task_boundary"
                            for t in plan["tasks"]))
        # One account, two worker slots; two distinct task prompts, never
        # a second implicit instance for a one-task Owner order.
        self.assertEqual(values["task_count"], "2")
        self.assertNotEqual(values["codex_1_task_b64"], values["codex_2_task_b64"])

    def test_explicit_reasoning_level_overrides_auto_and_single_stays_single(self):
        one = router.parse_order(self.order(
            [self.task("codex-only", text="Fix typo in the docs", reasoning_effort="high")],
            mode="serial"))
        selected = router.workflow_values(one)
        self.assertEqual(selected["task_count"], "1")
        self.assertEqual(selected["codex_1_reasoning_effort"], "high")
        self.assertEqual(selected["codex_2_reasoning_effort"], "")
        with self.assertRaisesRegex(router.OrderError, "Unauthorized reasoning_effort"):
            router.parse_order(self.order([
                self.task("codex-only", reasoning_effort="xhigh")
            ]))

    def test_malformed_and_malicious_inputs_fail_closed(self):
        bad_orders = (
            self.order(target="untrusted-owner/untrusted"),
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

    def test_cli_unsupported_plan_has_no_dispatch_outputs(self):
        raw = self.order([
            self.task("codex-1"), self.task("codex-2"), self.task("codex-3")
        ])
        result = subprocess.run(
            [sys.executable, str(SOURCE)], input=raw, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("No agent started", result.stderr)
        self.assertNotIn("codex_task_b64=", result.stderr)

    def test_cli_two_workers_emits_only_validated_encoded_outputs(self):
        raw = self.order([self.task("codex-1"), self.task("codex-2")])
        result = subprocess.run(
            [sys.executable, str(SOURCE)], input=raw, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("task_count=2", result.stdout)
        self.assertIn("mode=parallel", result.stdout)
        self.assertIn("codex_1_task_b64=", result.stdout)
        self.assertIn("codex_2_task_b64=", result.stdout)
        self.assertNotIn("TARGET_REPOSITORY=", result.stdout)


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



    def test_serial_phase_two_is_blocked_for_unmerged_first_phase(self):
        workflow = (SOURCE.parents[1] / ".github/workflows/agent-switch.yml").read_text(
            encoding="utf-8")
        serial = workflow.split("  codex_serial_2:", 1)[1].split(
            "  codex_serial_blocked:", 1)[0]
        self.assertIn("publication_status == 'MERGED'", serial)
        self.assertIn("publication_status == 'NO_CHANGE'", serial)
        self.assertIn("publication_status == 'PR_STAGED'", serial)
        self.assertIn("serial_independent == 'true'", serial)
        self.assertIn("serial_independent != 'true'", workflow)
        # Serial and audit-managed tasks retain their original PR-only
        # safety gate; the old quota replay event can no longer bypass it.
        self.assertEqual(workflow.count(
            "no_auto_merge: ${{ fromJSON(needs.preflight.outputs.serial_independent) || "
            "fromJSON(needs.preflight.outputs.audit_managed) }}"), 2)
        self.assertIn("outputs.run_stage_2 == 'true'", serial)
        self.assertIn("needs.codex_serial_1.result == 'success'", serial)
        self.assertNotIn("outputs.resume_stage", serial)
        self.assertNotIn("repository_dispatch", workflow)
        self.assertIn("always()", serial)
        self.assertIn("FIRST_PUBLICATION:", workflow)
        self.assertIn("CODEX_2_NOT_STARTED", workflow)

    def test_no_change_permission_requires_exact_boolean(self):
        read_only = self.task("codex-read", allow_no_change=True)
        order = router.parse_order(self.order([read_only], mode="serial"))
        self.assertIs(order["tasks"][0]["allow_no_change"], True)
        values = router.workflow_values(order)
        self.assertEqual(values["allow_no_change_1"], "true")
        self.assertEqual(values["allow_no_change_2"], "false")
        plan = router.dispatch_plan(order)
        self.assertTrue(plan["tasks"][0]["allow_no_change"])
        for invalid in ("true", 1, None, [], {}):
            with self.subTest(invalid=invalid), self.assertRaises(router.OrderError):
                router.parse_order(self.order([self.task("codex-read", allow_no_change=invalid)]))

    def test_no_change_permission_per_worker_not_inherited(self):
        tasks = [self.task("codex-first", allow_no_change=True), self.task("codex-second")]
        order = router.parse_order(self.order(tasks, mode="serial"))
        values = router.workflow_values(order)
        self.assertEqual(values["allow_no_change_1"], "true")
        self.assertEqual(values["allow_no_change_2"], "false")
        self.assertNotIn("allow_no_change", order["tasks"][1])


    def test_explicit_independent_serial_stages_have_distinct_pr_only_tasks(self):
        tasks = [self.task("codex-config", reasoning_effort="low"),
                 self.task("codex-upstream", reasoning_effort="low")]
        order = router.parse_order(self.order(tasks, mode="serial", serial_independent=True))
        plan = router.dispatch_plan(order)
        self.assertEqual([t["depends_on"] for t in plan["tasks"]], [[], []])
        self.assertTrue(plan["execution_policy"]["serial_independent_pr_only"])
        values = router.workflow_values(order)
        self.assertEqual(values["serial_independent"], "true")
        self.assertEqual(values["task_count"], "2")
        self.assertEqual(values["mode"], "serial")
        prompts = []
        for i in (1, 2):
            prompt = base64.b64decode(values[f"codex_{i}_task_b64"]).decode("utf-8")
            self.assertIn("do not depend on or merge", prompt)
            self.assertIn("fresh main", prompt)
            prompts.append(prompt)
        self.assertIn("start immediately", prompts[0])
        self.assertNotIn("wait until the previous worker", prompts[0])
        self.assertIn("wait until the previous worker", prompts[1])

    def test_independent_serial_opt_in_is_strict_and_defaults_to_dependent(self):
        tasks = [self.task("codex-config"), self.task("codex-upstream")]
        default = router.parse_order(self.order(tasks, mode="serial"))
        self.assertEqual(router.workflow_values(default)["serial_independent"], "false")
        self.assertEqual(router.dispatch_plan(default)["tasks"][1]["depends_on"],
                         ["codex-config"])
        for bad in ("true", 1, None, {}, []):
            with self.subTest(value=bad), self.assertRaises(router.OrderError):
                router.parse_order(self.order(
                    tasks, mode="serial", serial_independent=bad))
        with self.assertRaises(router.OrderError):
            router.parse_order(self.order(tasks, mode="parallel", serial_independent=True))
        with self.assertRaises(router.OrderError):
            router.parse_order(self.order([tasks[0]], mode="serial", serial_independent=True))

if __name__ == "__main__":
    unittest.main()
