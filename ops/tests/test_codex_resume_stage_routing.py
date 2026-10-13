"""Quota continuation must execute only the attested stage, never its sibling."""
import json
from pathlib import Path
import re
import unittest

from ops import agent_switch

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/agent-switch.yml"


def owner_order(mode="parallel", count=2):
    items = [
        {"id": "first", "provider": "codex",
         "task": "Correct independently inspected documentation example"},
        {"id": "second", "provider": "codex",
         "task": "Correct separate and inspected code contract tests"},
    ][:count]
    return agent_switch.parse_order(json.dumps({
        "target_repository": "martaxi-boss/Project-leader-codex",
        "mode": mode, "tasks": items,
    }))


def job_text(source, name):
    match = re.search(
        r"(?ms)^  " + re.escape(name) +
        r":\n(.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)", source,
    )
    if not match:
        raise AssertionError("Missing GitHub job: " + name)
    return match.group(1)


class QuotaStageRoutingTests(unittest.TestCase):
    def test_initial_two_worker_runs_both(self):
        for mode in ("serial", "parallel"):
            with self.subTest(mode=mode):
                values = agent_switch.workflow_values(owner_order(mode))
                self.assertEqual((values["run_stage_1"], values["run_stage_2"]),
                                 ("true", "true"))

    def test_resumed_first_worker_never_restarts_second(self):
        for mode in ("serial", "parallel"):
            with self.subTest(mode=mode):
                values = agent_switch.workflow_values(owner_order(mode), "1")
                self.assertEqual((values["run_stage_1"], values["run_stage_2"]),
                                 ("true", "false"))

    def test_resumed_second_worker_never_restarts_first(self):
        for mode in ("serial", "parallel"):
            with self.subTest(mode=mode):
                values = agent_switch.workflow_values(owner_order(mode), "2")
                self.assertEqual((values["run_stage_1"], values["run_stage_2"]),
                                 ("false", "true"))

    def test_solo_resume_is_first_stage_only(self):
        order = owner_order("serial", count=1)
        normal = agent_switch.workflow_values(order)
        resumed = agent_switch.workflow_values(order, "1")
        self.assertEqual((normal["run_stage_1"], normal["run_stage_2"]),
                         ("true", "false"))
        self.assertEqual((resumed["run_stage_1"], resumed["run_stage_2"]),
                         ("true", "false"))
        with self.assertRaisesRegex(agent_switch.OrderError, "Second stage"):
            agent_switch.workflow_values(order, "2")

    def test_unattested_stage_values_are_rejected_without_partial_route(self):
        order = owner_order()
        for bad in ("0", "3", "02", None, 2, True, {}, " 2"):
            with self.subTest(stage=bad), self.assertRaises(agent_switch.OrderError):
                agent_switch.workflow_values(order, bad)

    def test_github_job_conditions_enforce_stage_identity(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("switch.workflow_values(order)", source)
        self.assertNotIn("repository_dispatch", source)
        self.assertNotIn("verify_resume(payload)", source)
        for name, expected, excluded in (
            ("codex_parallel_1", "run_stage_1", "run_stage_2"),
            ("codex_parallel_2", "run_stage_2", "run_stage_1"),
            ("codex_serial_1", "run_stage_1", "run_stage_2"),
        ):
            with self.subTest(job=name):
                job = job_text(source, name)
                cond = job.split("    permissions:", 1)[0]
                self.assertIn("outputs." + expected + " == 'true'", cond)
                self.assertNotIn("outputs." + excluded + " == 'true'", cond)

        solo = job_text(source, "codex")
        self.assertIn("outputs.run_stage_1 == 'true'", solo)

    def test_serial_second_stage_requires_prior_accepted_publication(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        stage2 = job_text(source, "codex_serial_2")
        condition = stage2.split("    permissions:", 1)[0]
        self.assertIn("always()", condition)
        self.assertIn("outputs.run_stage_2 == 'true'", condition)
        self.assertNotIn("needs.codex_serial_1.result == 'skipped'", condition)
        self.assertIn("needs.codex_serial_1.result == 'success'", condition)
        self.assertIn("publication_status == 'PR_STAGED'", condition)

        blocked = job_text(source, "codex_serial_blocked")
        self.assertNotIn("outputs.resume_stage", blocked)
        self.assertIn("outputs.run_stage_2 == 'true'", blocked)

    def test_all_owner_workers_bind_original_issue_without_legacy_resume(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for name in ("codex", "codex_parallel_1", "codex_parallel_2",
                     "codex_serial_1", "codex_serial_2"):
            with self.subTest(job=name):
                job = job_text(source, name)
                self.assertIn(
                    "issue_number: ${{ fromJSON(needs.preflight.outputs.issue_number) }}",
                    job,
                )
                self.assertNotIn("issue_number: ${{ github.event.issue.number }}", job)
                self.assertIn("no_auto_merge:", job)
                self.assertNotIn("repository_dispatch", job)
                self.assertNotIn("outputs.resume_stage", job)

        self.assertIn("run_stage_1: ${{ steps.validate.outputs.run_stage_1 }}", source)
        self.assertIn("run_stage_2: ${{ steps.validate.outputs.run_stage_2 }}", source)


if __name__ == "__main__":
    unittest.main()
