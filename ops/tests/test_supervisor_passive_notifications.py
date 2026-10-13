"""Passive Project Leader worker -> Supervisor -> existing Telegram routing.

No bot, VPS, GitHub token, subprocess or AI is called in these offline tests.
"""
import inspect
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops import coordinator_supervisor as supervisor
from ops import telegram_gateway


RUN = "https://github.com/martaxi-boss/VPS/actions/runs/38414318007"


def env(root: Path, category="WORKER_REPORT", status="WORKER_REPORT_RECEIVED"):
    return {
        "RUNNER_TEMP": str(root),
        "SUPERVISOR_OBSERVATION": category,
        "CODEX_REPORT_MODE": "worker" if category == "WORKER_REPORT" else "status",
        "CODEX_JOB_STATUS": status,
        "CODEX_REPORT_PATH": str(root / "report.md"),
        "CODEX_ISSUE_NUMBER": "181",
        "CODEX_RUN_URL": RUN,
        "CODEX_INSTANCE_ID": "p2-1",
    }


class PassiveSupervisorTests(unittest.TestCase):
    def test_worker_report_is_forwarded_unmodified_without_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = "HUMAN_GATE declarado APENAS pelo Project Leader do trabalhador.\n"
            (root / "report.md").write_text(raw, encoding="utf-8")
            with (patch.dict(os.environ, env(root), clear=True),
                  patch.object(supervisor, "_api", side_effect=AssertionError(
                      "passive observation must not issue any GitHub API call")),
                  patch.object(supervisor, "assess", side_effect=AssertionError(
                      "passive observation must not execute CI/merge")),
                  patch.object(telegram_gateway, "notify") as delivery):
                self.assertEqual(supervisor.observe_worker_event(), 0)
                delivery.assert_called_once_with()
                self.assertEqual((root / "report.md").read_text(), raw)

    def test_final_status_is_notification_only_no_worker_or_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for status in ("PR_STAGED", "MERGED", "NO_CHANGE",
                           "NOT_STARTED", "FAILED", "NOT_COMPLETED"):
                with (self.subTest(status=status),
                      patch.dict(os.environ, env(root, "FINAL_STATE", status),
                                 clear=True),
                      patch.object(supervisor, "_api",
                                   side_effect=AssertionError("no GitHub API")),
                      patch.object(telegram_gateway, "notify") as delivery):
                    self.assertEqual(supervisor.observe_worker_event(), 0)
                    delivery.assert_called_once_with()

    def test_rejects_forged_source_and_invalid_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "report.md").write_text("A real worker report.", encoding="utf-8")
            invalid = [
                {"CODEX_ISSUE_NUMBER": "0"},
                {"CODEX_ISSUE_NUMBER": "181\nINJECTION"},
                {"CODEX_RUN_URL": "https://evil.example/actions/runs/1"},
                {"CODEX_RUN_URL": "https://github.com/martaxi-boss/VPS/actions/runs/not-a-run"},
                {"CODEX_JOB_STATUS": "NEW_UNCOVERED_MATERIAL_DECISION"},
                {"CODEX_REPORT_MODE": "status"},
                {"CODEX_REPORT_PATH": str(root / "another.txt")},
                {"SUPERVISOR_OBSERVATION": "RUN_WORKER"},
            ]
            for data in invalid:
                values = dict(env(root), **data)
                with (self.subTest(data=data),
                      patch.dict(os.environ, values, clear=True),
                      patch.object(telegram_gateway, "notify") as delivery):
                    self.assertEqual(supervisor.observe_worker_event(), 2)
                    delivery.assert_not_called()

    def test_rejects_symlink_missing_oversized_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected = root / "report.md"
            with (patch.dict(os.environ, env(root), clear=True),
                  patch.object(telegram_gateway, "notify") as delivery):
                self.assertEqual(supervisor.observe_worker_event(), 2)
                expected.symlink_to(root / "target")
                (root / "target").write_text("Report data.", encoding="utf-8")
                self.assertEqual(supervisor.observe_worker_event(), 2)
                expected.unlink()
                expected.write_bytes(b"X" * 65537)
                self.assertEqual(supervisor.observe_worker_event(), 2)
                delivery.assert_not_called()

    def test_observer_does_not_classify_or_create_human_gate(self):
        observer = inspect.getsource(supervisor.observe_worker_event)
        self.assertNotIn("parse_human_gate", observer)
        self.assertNotIn("create_human_gate", observer)
        self.assertNotIn("workflow_dispatch", observer)
        self.assertNotIn("repository_dispatch", observer)
        self.assertNotIn("codex exec", observer)
        self.assertNotIn("_api(", observer)
        self.assertNotIn("subprocess.", observer)
        self.assertNotIn("assess(", observer)

    def test_original_worker_report_is_delivered_before_publisher_wait(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/codex-autonomous.yml").read_text(
                        encoding="utf-8")
        first = workflow.index("Passive Supervisor forwards Project Leader worker report")
        publish = workflow.index("Publish guarded PR")
        final = workflow.index("Passive Supervisor sends final publication state")
        self.assertLess(first, publish)
        self.assertLess(publish, final)
        self.assertEqual(workflow.count("python3 ops/coordinator_supervisor.py observe"), 2)
        self.assertNotIn("python3 ops/telegram_gateway.py notify", workflow)
        self.assertIn("secrets.TELEGRAM_BOT_TOKEN", workflow)
        self.assertIn("secrets.TELEGRAM_CHAT_ID", workflow)
        self.assertNotIn("codex_autonomous_resume", workflow[first:publish])


    def test_passive_telegram_env_expands_actual_github_expressions(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/codex-autonomous.yml").read_text(
                        encoding="utf-8")
        # A leading backslash is passed literally to the runner environment.
        # It breaks chat IDs, run provenance and paths but tests once missed it.
        self.assertNotIn("\\${{", workflow)
        report = workflow.split("id: supervisor_report", 1)[1].split(
            "- name: Publish guarded PR", 1)[0]
        final = workflow.split("id: private_report", 1)[1].split(
            "- name: Publish truthful execution result", 1)[0]
        for section in (report, final):
            for env_value in (
                    "TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}",
                    "TELEGRAM_CHAT_ID: ${{ secrets.TELEGRAM_CHAT_ID }}",
                    "CODEX_ISSUE_NUMBER: ${{ inputs.issue_number || github.event.issue.number }}",
                    "CODEX_RUN_URL: https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}"):
                with self.subTest(section=section[:32], value=env_value):
                    self.assertIn(env_value, section)
        self.assertIn("CODEX_REPORT_PATH: ${{ runner.temp }}/report.md", report)
        for outcome in ("STAGE_OUTCOME", "CODEX_OUTCOME", "PUBLISH_OUTCOME"):
            self.assertIn(outcome + ": ${{ steps." +
                          outcome.split("_")[0].lower() + ".outcome }}", final)

if __name__ == "__main__":
    unittest.main()
