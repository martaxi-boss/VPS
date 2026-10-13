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

    def test_supervisor_module_cannot_merge_or_dispatch(self):
        source = inspect.getsource(supervisor)
        for name in ("_api", "_merge", "assess", "main", "_review"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(supervisor, name))
        for forbidden in ("CODEX_GITHUB_TOKEN", "GH_TOKEN", "urllib.",
                          "workflow_dispatch", "repository_dispatch",
                          "subprocess.", "codex exec"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_failed_codex_still_delivers_private_report_without_publisher_metadata(self):
        """Run actual collection shell with offline fake scp: only report.md exists."""
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "sshpass"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "from pathlib import Path\n"
                "if Path(sys.argv[-2]).name != 'report.md':\n"
                "    sys.exit(1)\n"
                "Path(sys.argv[-1]).write_text('HUMAN_GATE: worker report only.\\n')\n",
                encoding="utf-8")
            fake.chmod(0o700)
            workflow = (Path(__file__).resolve().parents[2] /
                        ".github/workflows/codex-autonomous.yml").read_text(encoding="utf-8")
            collect = workflow.split(
                "- name: Retrieve patch, provenance and private agent report", 1
            )[1].split("- name: Passive Supervisor forwards Project Leader worker report", 1)[0]
            script = collect.split("run: |\n", 1)[1]
            commands = []
            for line in script.splitlines():
                if not line.startswith("          "):
                    break
                commands.append(line[10:])
            self.assertTrue(commands)
            runtime_env = {**os.environ,
                           "PATH": str(root) + os.pathsep + os.environ["PATH"],
                           "RUNNER_TEMP": str(root), "CODEX_INSTANCE_ID": "",
                           "GITHUB_RUN_ID": "38414318007",
                           "GITHUB_RUN_ATTEMPT": "1",
                           "SSHPASS": "offline-placeholder"}
            actual = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", "\n".join(commands)],
                env=runtime_env, capture_output=True, text=True, timeout=15)
            self.assertEqual(actual.returncode, 0, actual.stderr)
            self.assertTrue((root / "report.md").is_file())
            self.assertFalse((root / "target.txt").exists())
            self.assertFalse((root / "base-sha.txt").exists())
            with (patch.dict(os.environ, env(root), clear=True),
                  patch.object(telegram_gateway, "notify") as sent):
                self.assertEqual(supervisor.observe_worker_event(), 0)
                sent.assert_called_once_with()
                self.assertIn("HUMAN_GATE: worker report only.",
                              (root / "report.md").read_text(encoding="utf-8"))

    def test_existing_publication_guards_run_only_after_private_handoff(self):
        """A report alone cannot authorize publishing an incomplete workspace."""
        import subprocess
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/codex-autonomous.yml").read_text(encoding="utf-8")
        collected = workflow.index("- name: Retrieve patch, provenance and private agent report")
        observer = workflow.index("- name: Passive Supervisor forwards Project Leader worker report")
        gate = workflow.index("- name: Validate publisher artifacts after private worker report")
        publisher = workflow.index("- name: Publish guarded PR, validate exact CI")
        self.assertLess(collected, observer)
        self.assertLess(observer, gate)
        self.assertLess(gate, publisher)
        section = workflow[gate:publisher]
        self.assertIn("id: validate_artifacts", section)
        self.assertIn("steps.codex.outcome == 'success'", section)
        self.assertIn("steps.collect.outcome == 'success'", section)
        self.assertIn("steps.validate_artifacts.outcome == 'success'", workflow[publisher:])
        contents = section.split("run: |\n", 1)[1]
        commands = []
        for line in contents.splitlines():
            if not line.startswith("          "):
                break
            commands.append(line[10:])
        with tempfile.TemporaryDirectory() as directory:
            runtime_env = {**os.environ, "RUNNER_TEMP": directory}
            cmd = ["bash", "-e", "-o", "pipefail", "-c", "\n".join(commands)]
            (Path(directory) / "report.md").write_text("Worker report\n")
            denied = subprocess.run(cmd, env=runtime_env, capture_output=True,
                                    text=True, timeout=5)
            self.assertNotEqual(denied.returncode, 0)
            for name in ("target.txt", "base-sha.txt", "codex-task.txt",
                         "project-leader-runtime.json"):
                (Path(directory) / name).write_text("synthetic\n", encoding="utf-8")
            (Path(directory) / "patch.diff").write_bytes(b"")
            allowed = subprocess.run(cmd, env=runtime_env, capture_output=True,
                                     text=True, timeout=5)
            self.assertEqual(allowed.returncode, 0, allowed.stderr)

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
