"""Offline tests of the existing Coordinator -> agent-switch Owner-only bridge."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import unittest

from ops import agent_switch

ROOT = Path(__file__).resolve().parents[2]
PIN = "f342346ef8b648118abbcc24ece860e1b9ea08af"


def audit(two=True, high=False):
    data = {
        "target_repository": "martaxi-boss/Project-leader-codex",
        "audit": {
            "revision": PIN,
            "findings": [
                {"id": "doc-one", "paths": ["docs/one.md"], "severity": "low",
                 "observation": "Inspected document one has an obsolete usage example"},
                {"id": "doc-two", "paths": ["docs/two.md"],
                 "severity": "high" if high else "low",
                 "observation": "Inspected document two has one inaccurate command"},
            ],
            "work_items": [
                {"id": "fix-one", "paths": ["docs/one.md"],
                 "finding_ids": ["doc-one"],
                 "task": "Correct the outdated example in inspected document one"},
                {"id": "fix-two", "paths": ["docs/two.md"],
                 "finding_ids": ["doc-two"],
                 "task": "Correct the inaccurate command in inspected document two"},
            ],
        },
    }
    if not two:
        data["audit"]["work_items"].pop()
    return data


def encode(data):
    return base64.b64encode(json.dumps(data, sort_keys=True).encode()).decode()


class CoordinatorRoutingTests(unittest.TestCase):
    def test_one_worker_decision(self):
        order, phase = agent_switch.parse_coordinator_envelope(encode(audit(two=False)))
        values = agent_switch.workflow_values(order)
        self.assertEqual((values["task_count"], phase["phase_count"]), ("1", 1))
        self.assertEqual(values["mode"], "serial")
        self.assertEqual(values["codex_2_task_b64"], "")

    def test_parallel_decision(self):
        order, phase = agent_switch.parse_coordinator_envelope(encode(audit()))
        values = agent_switch.workflow_values(order)
        self.assertEqual((values["task_count"], values["mode"]), ("2", "parallel"))
        self.assertEqual(phase["phase_count"], 1)
        self.assertEqual(values["codex_1_reasoning_effort"], "low")
        self.assertEqual(values["codex_2_reasoning_effort"], "low")
        self.assertEqual(values["audit_managed"], "true")

    def test_serial_high_effort_decision(self):
        order, _ = agent_switch.parse_coordinator_envelope(encode(audit(high=True)))
        values = agent_switch.workflow_values(order)
        self.assertEqual(values["mode"], "serial")
        self.assertEqual(values["serial_independent"], "true")
        self.assertEqual(values["codex_2_reasoning_effort"], "high")

    def test_untrusted_or_oversized_plan_is_refused(self):
        for value in ("", "not-base64", "ABC\nD", "X"*32001,
                      encode({"mode": "parallel"})):
            with self.subTest(value=value[:12]), self.assertRaises(agent_switch.OrderError):
                agent_switch.parse_coordinator_envelope(value)
        wrong = audit()
        wrong["target_repository"] = "martaxi-boss/VPS"
        with self.assertRaises(agent_switch.OrderError):
            agent_switch.parse_coordinator_envelope(encode(wrong))
        bad = audit()
        bad["audit"]["work_items"][0]["paths"] = ["../secrets"]
        with self.assertRaises(agent_switch.OrderError):
            agent_switch.parse_coordinator_envelope(encode(bad))

    def test_held_dependent_phase_never_dispatched_with_first_wave(self):
        plan = audit()
        plan["audit"]["findings"].append({
            "id": "doc-three", "paths": ["docs/three.md"], "severity": "medium",
            "observation": "Third document requires corrections after both guides"})
        plan["audit"]["work_items"].append({
            "id": "fix-three", "paths": ["docs/three.md"],
            "finding_ids": ["doc-three"], "depends_on": ["fix-one", "fix-two"],
            "task": "Update third document only when both guides have passed CI"})
        order, meta = agent_switch.parse_coordinator_envelope(encode(plan))
        self.assertEqual(meta["phase_count"], 2)
        self.assertEqual(meta["pending_task_ids"], ["fix-three"])
        self.assertEqual(agent_switch.workflow_values(order)["task_count"], "2")
        self.assertEqual(order["held_task_count"], 1)


class OwnerBridgeContractTests(unittest.TestCase):
    def setUp(self):
        self.gateway = (ROOT / ".github/workflows/coordinator-owner-order.yml").read_text()
        self.router = (ROOT / ".github/workflows/agent-switch.yml").read_text()
        self.worker = (ROOT / ".github/workflows/codex-autonomous.yml").read_text()
        self.remote = (ROOT / "ops/coordinator-smoke-remote.sh").read_text()

    def test_only_owner_issue_spends_tokens_not_a_pr(self):
        self.assertIn("github.event.issue.user.login == github.repository_owner", self.gateway)
        self.assertIn("startsWith(github.event.issue.title, '[coordinator run] ')", self.gateway)
        offline = self.gateway.split("  offline-contract:", 1)[1].split("  plan:", 1)[0]
        self.assertNotIn("secrets.", offline)
        self.assertNotIn("sshpass", offline)
        self.assertNotIn("workflow_dispatch:", self.gateway)
        self.assertIn("permissions: {}", self.gateway)

    def test_routes_into_original_agent_switch_and_executor(self):
        self.assertIn("uses: ./.github/workflows/agent-switch.yml", self.gateway)
        self.assertIn("coordinator_plan_b64: ${{ needs.plan.outputs.coordinator_plan_b64 }}", self.gateway)
        self.assertIn("switch.parse_coordinator_envelope(", self.router)
        self.assertIn("switch.workflow_values(order", self.router)
        self.assertIn("inputs.coordinator_plan_b64 != ''", self.router)
        self.assertIn("inputs.issue_number == github.event.issue.number", self.worker)
        self.assertIn("startsWith(github.event.issue.title, '[coordinator run] ')", self.worker)

    def test_remote_stays_read_only_and_output_not_logged(self):
        self.assertIn("mode='dispatch'", self.remote)
        self.assertIn('"$control/ops/coordinator_ai.py"', self.remote)
        self.assertIn("AUDIT_B64=", self.remote)
        self.assertIn("COORDINATOR_DISPATCH_STATUS=VALIDATED", self.remote)
        self.assertIn("COORDINATOR_AUDIT_VERIFIED_AND_ROUTED", self.gateway)
        self.assertIn("COORDINATOR_PUBLICATION_TOKEN_UNAVAILABLE", self.gateway)
        self.assertIn("SHA256:Q7y5zs6sXWHtznlMQS/IQjcqPKdr7YEku1hWlNLvdxc", self.gateway)
        self.assertNotIn("StrictHostKeyChecking=no", self.gateway)
        self.assertNotIn("git push", self.remote)
        self.assertNotIn("gh issue create", self.remote)

    def test_bash_syntax_and_inline_python(self):
        script = str(ROOT / "ops/coordinator-smoke-remote.sh")
        p = subprocess.run(["bash", "-n", script],
                           capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        for path in ("coordinator-owner-order.yml",):
            workflow = (ROOT / ".github/workflows" / path).read_text()
            self.assertNotIn(chr(92) + "${{", workflow)
        rows = self.gateway.splitlines()
        count = 0
        for i, row in enumerate(rows):
            tag = next((x for x in ("PY_ORDER", "PY_PLAN")
                        if "<<'" + x + "'" in row), None)
            if tag is None:
                continue
            source = []
            for candidate in rows[i+1:]:
                if candidate.strip() == tag:
                    break
                source.append(candidate)
            else:
                self.fail("unterminated python heredoc")
            spaces = min(len(line) - len(line.lstrip()) for line in source if line.strip())
            compile("\n".join(line[spaces:] for line in source),
                    "<owner-gateway>", "exec")
            count += 1
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
