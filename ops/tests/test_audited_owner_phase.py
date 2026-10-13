"""One Owner-audited DAG must never silently dispatch its held phases."""
import base64
import hashlib
import json
from pathlib import Path
import unittest

from ops import agent_switch
from ops import codex_quota_resume as quota

PIN = "f342346ef8b648118abbcc24ece860e1b9ea08af"
ROOT = Path(__file__).resolve().parents[2]


def phase_manifest():
    return {
        "target_repository": "martaxi-boss/Project-leader-codex",
        "audit": {
            "revision": PIN,
            "findings": [
                {"id": "doc-one", "severity": "low",
                 "paths": ["docs/first.md"],
                 "observation": "Inspected first tutorial has one obsolete example"},
                {"id": "doc-two", "severity": "low",
                 "paths": ["docs/second.md"],
                 "observation": "Inspected second tutorial refers to an old route"},
                {"id": "bridge-test", "severity": "medium",
                 "paths": ["codex/tests/test_cloud_bridge.py"],
                 "observation": "Inspected bridge fixture needs a post-documentation check"},
            ],
            "work_items": [
                {"id": "fix-doc-one", "paths": ["docs/first.md"],
                 "finding_ids": ["doc-one"],
                 "task": "Fix first inspected example without changing any code"},
                {"id": "fix-doc-two", "paths": ["docs/second.md"],
                 "finding_ids": ["doc-two"],
                 "task": "Fix second inspected documentation and validate links"},
                {"id": "check-bridge", "paths": ["codex/tests/test_cloud_bridge.py"],
                 "finding_ids": ["bridge-test"], "depends_on": ["fix-doc-one", "fix-doc-two"],
                 "task": "Verify bridge test only after both earlier documentation phases"},
            ],
        },
    }


class OwnerAuditedFirstWaveTests(unittest.TestCase):
    def test_first_wave_routes_two_low_workers_and_holds_dependent_third(self):
        data = json.dumps(phase_manifest(), ensure_ascii=False, indent=2)
        order, phase = agent_switch.parse_owner_envelope(data)
        self.assertEqual(phase["phase_count"], 2)
        self.assertEqual(phase["active_task_ids"], ["fix-doc-one", "fix-doc-two"])
        self.assertEqual(phase["pending_task_ids"], ["check-bridge"])
        self.assertEqual(phase["audited_revision"], PIN)
        self.assertEqual(phase["owner_digest"],
                         hashlib.sha256(data.encode("utf-8")).hexdigest())
        self.assertEqual(order["phase_owner_digest"], phase["owner_digest"])
        self.assertEqual(order["mode"], "parallel")
        self.assertEqual([t["reasoning_effort"] for t in order["tasks"]],
                         ["low", "low"])
        routed = agent_switch.workflow_values(order)
        self.assertEqual((routed["task_count"], routed["audit_managed"]),
                         ("2", "true"))
        self.assertEqual((routed["run_stage_1"], routed["run_stage_2"]),
                         ("true", "true"))
        for worker in (1, 2):
            prompt = base64.b64decode(
                routed["codex_" + str(worker) + "_task_b64"]).decode("utf-8")
            self.assertNotIn("Verify bridge test only after", prompt)
            self.assertIn("AUDIT_BASE_SHA=" + PIN, prompt)

    def test_quota_checkpoints_bind_even_pending_tasks_in_original_owner_order(self):
        original = phase_manifest()
        raw = json.dumps(original, sort_keys=True)
        first, meta = agent_switch.parse_owner_envelope(raw)
        from_quota = quota._order(raw)
        self.assertEqual(quota.order_digest(from_quota), quota.order_digest(first))
        self.assertEqual(from_quota["phase_owner_digest"], meta["owner_digest"])
        amended = phase_manifest()
        amended["audit"]["work_items"][2]["task"] = (
            "Verify changed bridge behavior after earlier work is accepted"
        )
        after_raw = json.dumps(amended, sort_keys=True)
        after, _ = agent_switch.parse_owner_envelope(after_raw)
        self.assertEqual([x["id"] for x in first["tasks"]],
                         [x["id"] for x in after["tasks"]])
        self.assertNotEqual(quota.order_digest(first), quota.order_digest(after))

    def test_resume_attested_worker_in_first_wave_never_replays_sibling(self):
        raw = json.dumps(phase_manifest())
        order = quota._order(raw)
        only_first = agent_switch.workflow_values(order, "1")
        only_second = agent_switch.workflow_values(order, "2")
        self.assertEqual(
            (only_first["run_stage_1"], only_first["run_stage_2"]),
            ("true", "false"),
        )
        self.assertEqual(
            (only_second["run_stage_1"], only_second["run_stage_2"]),
            ("false", "true"),
        )

    def test_dependent_second_phase_never_reaches_initial_dispatch(self):
        plan = phase_manifest()
        plan["audit"]["work_items"][1]["depends_on"] = ["fix-doc-one"]
        plan["audit"]["work_items"][2]["depends_on"] = ["fix-doc-two"]
        order, meta = agent_switch.parse_owner_envelope(json.dumps(plan))
        self.assertEqual(len(order["tasks"]), 1)
        self.assertEqual(order["tasks"][0]["id"], "fix-doc-one")
        self.assertEqual(meta["phase_count"], 3)
        self.assertEqual(meta["pending_task_ids"], ["fix-doc-two", "check-bridge"])
        self.assertEqual(agent_switch.workflow_values(order)["task_count"], "1")

    def test_legacy_owner_order_and_single_audited_order_still_valid(self):
        legacy = json.dumps({
            "target_repository": "martaxi-boss/Project-leader-codex",
            "mode": "serial",
            "tasks": [{"id": "solo", "provider": "codex",
                       "task": "Fix previously audited spelling in one readme"}],
        })
        old, metadata = agent_switch.parse_owner_envelope(legacy)
        self.assertIsNone(metadata)
        self.assertNotIn("phase_owner_digest", old)
        self.assertEqual(agent_switch.workflow_values(old)["task_count"], "1")

        audited = phase_manifest()
        audited["audit"]["work_items"] = audited["audit"]["work_items"][:1]
        one, meta = agent_switch.parse_owner_envelope(json.dumps(audited))
        self.assertEqual(meta["phase_count"], 1)
        self.assertEqual([t["id"] for t in one["tasks"]], ["fix-doc-one"])

    def test_invalid_or_cyclic_owner_plan_fails_closed_before_model(self):
        plan = phase_manifest()
        plan["audit"]["work_items"][0]["depends_on"] = ["check-bridge"]
        with self.assertRaises(agent_switch.OrderError):
            agent_switch.parse_owner_envelope(json.dumps(plan))
        plan = phase_manifest()
        plan["audit"]["work_items"][0]["paths"] = ["docs/never-inspected.md"]
        with self.assertRaises(agent_switch.OrderError):
            agent_switch.parse_owner_envelope(json.dumps(plan))
        plan = phase_manifest()
        raw = json.dumps(plan) + (" " * 24_000)
        with self.assertRaisesRegex(agent_switch.OrderError, "bounded"):
            agent_switch.parse_owner_envelope(raw)

    def test_workflow_and_quota_use_same_authenticated_phase_parser(self):
        workflow = (ROOT / ".github/workflows/agent-switch.yml").read_text()
        resume = (ROOT / "ops/codex_quota_resume.py").read_text()
        self.assertIn("switch.parse_owner_envelope(", workflow)
        self.assertIn("agent_switch.parse_owner_envelope(raw)[0]", resume)
        self.assertIn("github.event.issue.user.login == github.repository_owner",
                      workflow)
        self.assertIn("startsWith(github.event.issue.title, '[agents run]')",
                      workflow)
        self.assertIn("HOLD_FOR_CI_AND_REAUDIT", workflow)
        self.assertIn("owner_digest", workflow)


if __name__ == "__main__":
    unittest.main()
