"""Permanent regression: VPS is Supervisor-only for Project Leader + Codex."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows"
OBSOLETE = (
    "coordinator-owner-order.yml", "coordinator-ai-smoke.yml",
    "coordinator-phase-cycle.yml", "coordinator-private-media-relay.yml",
    "telegram-coordinator-owner.yml", "telegram-codex-gateway.yml",
    "codex-autonomous-validation.yml", "agent-switch.yml",
)
INERT_WORKERS = (
    "codex-autonomous.yml",
    "codex-chatgpt-bridge.yml", "codex-project-leader-safe-fix.yml",
)

class SupervisorOnlyTests(unittest.TestCase):
    def test_coordinator_workflows_are_absent(self):
        for name in OBSOLETE:
            with self.subTest(name=name):
                self.assertFalse((WF/name).exists())
    def test_coordinator_ai_and_inbound_media_modules_absent(self):
        for prefix in ("coordinator_ai.py", "coordinator_media.py",
                       "coordinator_phase_continuation.py",
                       "coordinator_plan_archive.py", "coordinator_pr_integrator.py",
                       "coordinator_sealed_relay.py", "coordinator_supervisor.py",
                       "telegram_coordinator_authority.py",
                       "telegram_coordinator_issue.py",
                       "chatgpt_attachment_ingress.py", "chatgpt_media_mcp.py"):
            with self.subTest(path=prefix):
                self.assertFalse((ROOT/"ops"/prefix).exists())
    def test_old_worker_workflows_are_not_dispatchable(self):
        for name in INERT_WORKERS:
            with self.subTest(workflow=name):
                text=(WF/name).read_text()
                header=text.split("\non:\n",1)[1].split("\npermissions:",1)[0].split("\nconcurrency:",1)[0]
                self.assertIn("  pull_request:",header)
                for forbidden in ("\n  issues:", "\n  workflow_call:",
                                  "\n  workflow_dispatch:", "\n  schedule:"):
                    self.assertNotIn(forbidden,header)
    def test_passive_supervisor_and_rea_transport_preserved(self):
        src=(WF/"cloud-supervisor-observation.yml").read_text()
        quota=(WF/"codex-quota-watch.yml").read_text()
        self.assertIn("python3 -m ops.supervisor_live cloud",src)
        self.assertIn("schedule:",src)
        self.assertIn("schedule:",quota)
        self.assertIn("ops.codex_quota_supervisor",quota)
        self.assertNotIn("codex exec",src)
    def test_telegram_has_no_inbound_dispatch(self):
        from ops import telegram_gateway as t
        self.assertFalse(hasattr(t,"poll"))
        self.assertFalse(hasattr(t,"dispatch_coordinator"))
        self.assertFalse(hasattr(t,"create_audit"))
        self.assertTrue(callable(t.say))

if __name__ == "__main__":
    unittest.main()
