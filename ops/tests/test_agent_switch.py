"""Focused offline checks for the minimal GitHub agent selector."""
import base64
import importlib.util
import json
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "agent_switch.py"
spec = importlib.util.spec_from_file_location("agent_switch", SOURCE)
router = importlib.util.module_from_spec(spec)
spec.loader.exec_module(router)


class AgentSwitchTests(unittest.TestCase):
    def order(self, tasks=None, target="martaxi-boss/VPS", mode="parallel"):
        return json.dumps({
            "target_repository": target,
            "mode": mode,
            "tasks": tasks or {"codex": "Review and fix the bounded documentation typo"},
        })

    def test_one_selected_codex(self):
        order = router.parse_order(self.order())
        data = router.output_values(order)
        self.assertEqual(data["codex"], "true")
        self.assertEqual(data["gemini"], "false")
        self.assertEqual(data["composer"], "false")
        self.assertTrue(base64.b64decode(data["codex_task_b64"]).decode()
                        .startswith("TARGET_REPOSITORY=martaxi-boss/VPS\n"))

    def test_three_independent_tasks(self):
        tasks = {name: f"Independently inspect the {name} component for regressions"
                 for name in ("codex", "gemini", "composer")}
        data = router.output_values(router.parse_order(self.order(tasks)))
        self.assertEqual([data[name] for name in tasks], ["true"] * 3)

    def test_unsupported_and_unsafe_requests_fail_closed(self):
        for raw in (
            self.order(target="martaxi-boss/pink-iptv"),
            self.order(mode="sequential"),
            self.order({"cloud": "Inspect this code independently"}),
            self.order({"composer": "Please use api_key=abcDEF1231231234"}),
            self.order({"codex": "short"}),
            '{"target_repository": "martaxi-boss/VPS", "mode": "parallel"}',
            self.order({"codex": "Review this file and report back"}) + "{}",
        ):
            with self.subTest(raw=raw[:75]), self.assertRaises(router.OrderError):
                router.parse_order(raw)

    def test_no_codex_selected_does_not_generate_fake_codex_work(self):
        order = router.parse_order(self.order({"gemini": "Review the API authentication design"}))
        self.assertEqual(router.output_values(order)["codex_task_b64"], "")


if __name__ == "__main__":
    unittest.main()
