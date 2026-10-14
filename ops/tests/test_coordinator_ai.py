"""Offline tests for the explicitly invoked read-only AI coordinator."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from ops import coordinator_ai


class FakeCodex:
    def __init__(self, response: dict | str, login: str = "Logged in using ChatGPT"):
        self.response = response
        self.login = login
        self.commands = []
        self.environments = []
        self.on_exec = None

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        self.environments.append(kwargs.get("env"))
        if command[1:] == ["login", "status"]:
            return subprocess.CompletedProcess(
                command, 0, stdout=b"", stderr=(self.login + "\n").encode())
        if command[1] == "exec":
            if self.on_exec:
                self.on_exec()
            output = Path(command[command.index("--output-last-message") + 1])
            raw = self.response if isinstance(self.response, str) else json.dumps(self.response)
            output.write_text(raw, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)
        raise AssertionError("unexpected process: " + repr(command))


class CoordinatorAITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / "checkout"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Coordinator Tests")
        self.git("config", "user.email", "coordinator@example.invalid")
        self.put("docs/one.md", "one\n")
        self.put("ops/sample.py", "VALUE = 1\n")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.git("remote", "add", "origin", "https://github.com/martaxi-boss/VPS.git")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.output = self.base / "private-results"
        self.codex = self.base / "codex"
        self.codex.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        self.codex.chmod(0o700)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True)

    def put(self, relative, content):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def audit(self, workers=1):
        findings = [{
            "id": "docs", "paths": ["docs/one.md"], "severity": "low",
            "observation": "Inspected documentation has one actionable inconsistency",
        }]
        work = [{
            "id": "docs-fix", "paths": ["docs/one.md"],
            "finding_ids": ["docs"], "task": "Correct the inspected documentation inconsistency",
        }]
        if workers == 2:
            findings.append({
                "id": "code", "paths": ["ops/sample.py"], "severity": "medium",
                "observation": "Inspected source has one bounded validation defect",
            })
            work.append({
                "id": "code-fix", "paths": ["ops/sample.py"],
                "finding_ids": ["code"], "task": "Correct the inspected validation defect safely",
            })
        return {
            "target_repository": "martaxi-boss/VPS",
            "audit": {"revision": self.head, "findings": findings, "work_items": work},
        }

    def coordinate(self, fake, **kwargs):
        return coordinator_ai.coordinate(
            "Planear correcções para os problemas realmente observados",
            self.repo, self.output,
            codex=self.codex, runner=fake, environment={}, **kwargs)

    def test_selected_private_photo_is_sent_to_existing_codex(self):
        from ops import coordinator_media
        photo = self.base / "test.jpg"
        photo.write_bytes(b"\\xff\\xd8\\xff" + b"photo")
        private = coordinator_media.pack([photo], self.base / "originals")
        fake = FakeCodex(self.audit())
        self.coordinate(fake, attachment_bundle=private)
        exec_call = fake.commands[1]
        self.assertIn("--add-dir", exec_call)
        self.assertEqual(str(private), exec_call[exec_call.index("--add-dir") + 1])
        self.assertIn("--image", exec_call)
        self.assertIn(str(private / "file-001.jpg"), exec_call)
        self.assertEqual("read-only", exec_call[exec_call.index("--sandbox") + 1])

    def test_missing_media_blocks_before_any_model_call(self):
        from ops import coordinator_media
        photo = self.base / "test.jpg"
        photo.write_bytes(b"\\xff\\xd8\\xff" + b"photo")
        private = coordinator_media.pack([photo], self.base / "originals")
        (private / "file-001.jpg").unlink()
        fake = FakeCodex(self.audit())
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "attachments"):
            self.coordinate(fake, attachment_bundle=private)
        self.assertEqual([], fake.commands)

    def test_one_or_two_workers_are_selected_without_dispatch(self):
        for count, mode in ((1, "serial"), (2, "parallel")):
            with self.subTest(count=count):
                fake = FakeCodex(self.audit(count))
                result = self.coordinate(fake)
                first = result.phase_plan["phases"][0]
                self.assertEqual(count, first["worker_count"])
                self.assertEqual(mode, first["mode"])
                self.assertEqual(["login", "exec"], [c[1] for c in fake.commands])
                exec_command = fake.commands[1]
                self.assertEqual("read-only", exec_command[exec_command.index("--sandbox") + 1])
                self.assertNotIn("dispatch", " ".join(exec_command).lower())

    def test_prompt_contains_complete_executable_audit_contract(self):
        prompt = coordinator_ai._prompt(
            "Audit inspected files", "martaxi-boss/VPS", self.head)
        self.assertIn("validator lives in another repository", prompt)
        self.assertIn("COORDINATOR INDEPENDENCE:", prompt)
        self.assertNotIn("PROJECT LEADER CANONICAL RULES", prompt)
        self.assertNotIn("EXECUTION_FIRST_WITHIN_BOUNDS", prompt)
        self.assertIn("finding_ids", prompt)
        self.assertIn("observation: 12-500 characters", prompt)
        self.assertIn("allow_no_change: boolean", prompt)
        self.assertIn("NO_VERIFIABLE_FINDINGS", prompt)
        self.assertIn("1-8 objects", prompt)

    def test_no_verifiable_finding_is_honestly_refused(self):
        fake = FakeCodex({"status": "NO_VERIFIABLE_FINDINGS"})
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "No verifiable"):
            self.coordinate(fake)
        self.assertFalse(self.output.exists())

    def test_invalid_json_and_cycle_are_rejected_without_output(self):
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "invalid JSON"):
            self.coordinate(FakeCodex("not json"))
        cyclic = self.audit(2)
        cyclic["audit"]["work_items"][0]["depends_on"] = ["code-fix"]
        cyclic["audit"]["work_items"][1]["depends_on"] = ["docs-fix"]
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "phase planner"):
            self.coordinate(FakeCodex(cyclic))
        self.assertFalse(self.output.exists())

    def test_changed_head_after_model_call_is_stale(self):
        fake = FakeCodex(self.audit())
        def advance_head():
            self.put("docs/two.md", "two\n")
            self.git("add", ".")
            self.git("commit", "-qm", "concurrent change")
        fake.on_exec = advance_head
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "changed during"):
            self.coordinate(fake)

    def test_non_versioned_and_protected_paths_are_rejected(self):
        missing = self.audit()
        missing["audit"]["findings"][0]["paths"] = ["docs/missing.md"]
        missing["audit"]["work_items"][0]["paths"] = ["docs/missing.md"]
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "non-versioned"):
            self.coordinate(FakeCodex(missing))
        protected = self.audit()
        protected["audit"]["findings"][0]["paths"] = [".github/workflows/x.yml"]
        protected["audit"]["work_items"][0]["paths"] = [".github/workflows/x.yml"]
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "phase planner"):
            self.coordinate(FakeCodex(protected))

    def test_fake_login_api_key_and_missing_model_are_refused_before_exec(self):
        fake = FakeCodex(self.audit(), login="Logged in using API key")
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "subscription login"):
            self.coordinate(fake)
        self.assertEqual(1, len(fake.commands))
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "API-key billing"):
            coordinator_ai.coordinate(
                "Valid order", self.repo, self.output,
                codex=self.codex, runner=FakeCodex(self.audit()),
                environment={"OPENAI_API_KEY": "not-printed"})
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "unavailable"):
            coordinator_ai.coordinate(
                "Valid order", self.repo, self.output,
                codex=self.base / "absent", runner=FakeCodex(self.audit()),
                environment={})

    def test_only_validated_result_is_private_and_coordinator_needs_no_skill(self):
        result = self.coordinate(FakeCodex(self.audit(2)))
        self.assertEqual(self.audit(2), json.loads(result.output_path.read_text()))
        self.assertEqual(0o700, self.output.stat().st_mode & 0o777)
        self.assertEqual(0o600, result.output_path.stat().st_mode & 0o777)
        self.assertFalse(result.output_path.is_relative_to(self.repo))
        raw_files = [p for p in self.output.iterdir() if p != result.output_path]
        self.assertEqual([], raw_files)
        self.assertFalse((self.base / "project-leader-rules.md").exists())
        self.assertFalse((self.base / "project-leader-runtime.json").exists())


    def test_codex_never_inherits_ambient_github_or_vps_secrets(self):
        fake = FakeCodex(self.audit())
        coordinator_ai.coordinate(
            "Planear apenas os problemas confirmados", self.repo,
            self.output, codex=self.codex, runner=fake,
            environment={
                "HOME": str(self.base), "PATH": "/usr/bin",
                "GH_TOKEN": "private-example", "CODEX_GITHUB_TOKEN": "private-example",
                "TELEGRAM_BOT_TOKEN": "private-example",
                "VPS_SSH_PASSWORD": "private-example",
                "AWS_SECRET_ACCESS_KEY": "private-example",
                "BASH_ENV": "/tmp/untrusted-env",
            })
        self.assertEqual(2, len(fake.environments))
        self.assertTrue(all(env == {
            "HOME": str(self.base), "PATH": "/usr/bin",
        } for env in fake.environments))

    def test_private_output_refuses_checkout_and_public_directory_without_chmod(self):
        original_mode = self.repo.stat().st_mode & 0o777
        with self.assertRaisesRegex(
                coordinator_ai.CoordinatorAIError, "outside the checkout"):
            coordinator_ai.coordinate(
                "Planear tarefa confirmada", self.repo, self.repo,
                codex=self.codex,
                runner=FakeCodex(self.audit()), environment={})
        self.assertEqual(original_mode, self.repo.stat().st_mode & 0o777)

        public = self.base / "public-results"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "owner-only"):
            coordinator_ai.coordinate(
                "Planear tarefa confirmada", self.repo, public,
                codex=self.codex,
                runner=FakeCodex(self.audit()), environment={})
        self.assertEqual(0o755, public.stat().st_mode & 0o777)

        linked = self.base / "linked-results"
        linked.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(coordinator_ai.CoordinatorAIError, "symlink"):
            coordinator_ai.coordinate(
                "Planear tarefa confirmada", self.repo, linked,
                codex=self.codex,
                runner=FakeCodex(self.audit()), environment={})


if __name__ == "__main__":
    unittest.main()
