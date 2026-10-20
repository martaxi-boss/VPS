"""Contract: legacy VPS Coordinator ingress is retired, passive Supervisor remains."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def events(name: str) -> str:
    source = (WORKFLOWS / name).read_text(encoding="utf-8")
    before, sep, after = source.partition("\non:\n")
    if not sep:
        raise AssertionError(f"Missing GitHub event declaration: {name}")
    return after.split("\npermissions:", 1)[0]


class PortableCoordinatorRetirementTests(unittest.TestCase):
    def test_legacy_vps_ai_planner_and_media_ingress_have_no_live_issue_event(self):
        for name in (
            "coordinator-owner-order.yml",
            "coordinator-ai-smoke.yml",
            "coordinator-private-media-relay.yml",
        ):
            with self.subTest(workflow=name):
                header = events(name)
                self.assertIn("\n  pull_request:", header)
                self.assertNotIn("\n  issues:", header)
                self.assertNotIn("\n  workflow_dispatch:", header)

    def test_telegram_remains_outbound_only_for_coordinator_orders(self):
        header = events("telegram-coordinator-owner.yml")
        self.assertIn("\n  pull_request:", header)
        self.assertNotIn("\n  workflow_dispatch:", header)
        self.assertNotIn("\n  issues:", header)

    def test_existing_passive_supervisor_keeps_its_original_paths(self):
        cloud = (WORKFLOWS / "cloud-supervisor-observation.yml").read_text(encoding="utf-8")
        quota = (WORKFLOWS / "codex-quota-watch.yml").read_text(encoding="utf-8")
        self.assertIn("python3 -m ops.supervisor_live cloud", cloud)
        self.assertIn("schedule:", cloud)
        self.assertIn("schedule:", quota)
        self.assertIn("Supervisor - Real ChatGPT quota watch", quota)


if __name__ == "__main__":
    unittest.main()
