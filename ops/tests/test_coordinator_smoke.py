"""Offline regression tests for the disabled, owner-trigger-only coordinator smoke."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "coordinator-smoke-remote.sh"
JOB = "38393756249-1"


class CoordinatorSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.bridge = self.home / "codex-bridge"
        self.bridge.mkdir(mode=0o700)
        self.cli = self.home / "codex-agent/node_modules/.bin/codex"
        self.cli.parent.mkdir(parents=True)
        self.cli.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        self.cli.chmod(0o700)

    def run_smoke(self, *args):
        return subprocess.run(
            ["bash", str(SCRIPT), *args], capture_output=True, text=True,
            env={"HOME": str(self.home), "PATH": os.environ["PATH"]},
            check=False, timeout=10,
        )

    def test_bash_syntax_is_valid_without_network_or_codex(self):
        syntax = subprocess.run(
            ["bash", "-n", str(SCRIPT)], capture_output=True, text=True,
            check=False, timeout=5,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_malformed_identifiers_never_create_workspace_or_run_cli(self):
        for ident in ("", "../evil", JOB + ";echo X", "1-1", "12345-1", "-1"):
            with self.subTest(ident=ident):
                result = self.run_smoke(ident)
                self.assertEqual(result.returncode, 12)
                self.assertIn("REFUSED", result.stderr)
        self.assertFalse((self.bridge / ".coordinator-smoke").exists())

    def test_existing_job_is_never_deleted_or_replayed(self):
        root = self.bridge / ".coordinator-smoke"
        root.mkdir(mode=0o700)
        existing = root / JOB
        existing.mkdir(mode=0o700)
        (existing / "sentinel").write_text("important", encoding="utf-8")
        result = self.run_smoke(JOB)
        self.assertEqual(result.returncode, 12)
        self.assertEqual((existing / "sentinel").read_text(), "important")
        self.assertFalse((root / (".started-" + JOB)).exists())

    def test_replay_marker_blocks_retry_without_any_model_call(self):
        root = self.bridge / ".coordinator-smoke"
        root.mkdir(mode=0o700)
        (root / (".started-" + JOB)).write_text("previous", encoding="utf-8")
        result = self.run_smoke(JOB)
        self.assertEqual(result.returncode, 12)
        self.assertFalse((root / JOB).exists())

    def test_symlinked_or_public_directory_is_refused_without_chmod(self):
        root = self.bridge / ".coordinator-smoke"
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        root.symlink_to(elsewhere, target_is_directory=True)
        result = self.run_smoke(JOB)
        self.assertEqual(result.returncode, 12)
        self.assertEqual(list(elsewhere.iterdir()), [])
        root.unlink()
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        result = self.run_smoke(JOB)
        self.assertEqual(result.returncode, 12)
        self.assertEqual(root.stat().st_mode & 0o777, 0o755)

    def test_absent_signed_in_cli_refused_before_workspace(self):
        self.cli.unlink()
        result = self.run_smoke(JOB)
        self.assertEqual(result.returncode, 12)
        self.assertFalse((self.bridge / ".coordinator-smoke").exists())

    def test_read_only_fixed_target_and_no_dispatch_contract(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("slug='martaxi-boss/Project-leader-codex'", text)
        self.assertIn("control_slug='martaxi-boss/VPS'", text)
        self.assertIn("canonical_slug='martaxi-boss/Project-leader'", text)
        self.assertIn('"$control/ops/coordinator_ai.py"', text)
        self.assertIn("VALIDATED_PLAN_NO_DISPATCH", text)
        self.assertIn('flock -n 8', text)
        self.assertIn('flock -n 9', text)
        self.assertIn('> "$private/coordinator-result.json"', text)
        self.assertIn('2>"$private/coordinator-error.txt"', text)
        self.assertNotIn("gh issue create", text)
        self.assertNotIn("git push", text)
        self.assertNotIn("repository_dispatch", text)
        self.assertNotIn("chmod -R", text)


class CoordinatorSmokeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (Path(__file__).resolve().parents[2] / ".github" /
                         "workflows" / "coordinator-ai-smoke.yml").read_text(encoding="utf-8")

    def test_github_context_expressions_are_not_escaped(self):
        self.assertNotIn(chr(92) + "${{", self.workflow)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", self.workflow)
        self.assertIn("SSHPASS: ${{ secrets.VPS_SSH_PASSWORD }}", self.workflow)
    def test_paid_smoke_requires_exact_owner_issue(self):
        self.assertIn("github.event.issue.user.login == github.repository_owner", self.workflow)
        self.assertIn("github.event.issue.title == '[coordinator smoke] Test real de planeamento read-only'", self.workflow)
        self.assertIn("types: [opened]", self.workflow)
        self.assertIn("permissions: {}", self.workflow)
        self.assertNotIn("workflow_dispatch:", self.workflow)

    def test_pr_validation_cannot_receive_vps_secret(self):
        offline = self.workflow.split("  offline-contract:", 1)[1].split("  coordinator-smoke:", 1)[0]
        self.assertIn("github.event_name == 'pull_request'", offline)
        self.assertNotIn("secrets.", offline)
        self.assertNotIn("sshpass", offline)
        self.assertNotIn("gh issue comment", offline)

    def test_vps_ssh_identity_is_pinned_and_no_live_script_is_installed(self):
        self.assertIn("SHA256:Q7y5zs6sXWHtznlMQS/IQjcqPKdr7YEku1hWlNLvdxc", self.workflow)
        self.assertIn("StrictHostKeyChecking=yes", self.workflow)
        self.assertNotIn("StrictHostKeyChecking=no", self.workflow)
        self.assertIn('ubuntu@146.59.145.3 "bash -s --', self.workflow)
        self.assertNotIn("scp ", self.workflow)

    def test_inline_workflow_python_is_syntactically_valid(self):
        rows = self.workflow.splitlines()
        blocks = 0
        for i, row in enumerate(rows):
            if not any(marker in row for marker in ("<<'PY'", "<<'PY_EOF'", "<<'PY_DIAG'")):
                continue
            indent = len(row) - len(row.lstrip(" "))
            terminator = ("PY_DIAG" if "<<'PY_DIAG'" in row else
                          "PY_EOF" if "<<'PY_EOF'" in row else "PY")
            code = []
            for candidate in rows[i + 1:]:
                if candidate.strip() == terminator:
                    # YAML strips the common block indent, not the deeper
                    # indentation of a command nested in shell if/else.
                    base_indent = len(candidate) - len(candidate.lstrip(" "))
                    break
                code.append(candidate)
            else:
                self.fail("Unterminated inline Python in workflow")
            self.assertLessEqual(base_indent, indent)
            self.assertTrue(all(
                not line.strip() or line.startswith(" " * base_indent)
                for line in code))
            compile("\n".join(line[base_indent:] for line in code),
                    "<coordinator-smoke-workflow>", "exec")
            blocks += 1
        self.assertEqual(blocks, 3)

    def test_failure_class_is_allowlisted_and_private_data_is_disposable(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('refuse "$diagnostic"', text)
        self.assertIn("diagnostic='MODEL_SCHEMA'", text)
        self.assertIn("diagnostic='NO_FINDINGS'", text)
        self.assertIn("COORDINATOR_SMOKE_REASON=%s", text)
        self.assertIn('grep -qxF', text)
        self.assertIn('"$workspace/validated"', text)
        self.assertNotIn('"$root/validated-$job"', text)
        self.assertNotIn('cat "$private/coordinator-error.txt"', text)
        self.assertIn("coordinator_smoke_failure_class.txt", self.workflow)
        self.assertIn("Diagnostic class:", self.workflow)
        self.assertIn("UNCLASSIFIED", self.workflow)

    def test_no_model_logs_or_implementation_dispatch(self):
        self.assertIn('> "$output" 2>/dev/null', self.workflow)
        self.assertIn("COORDINATOR_SMOKE_STATUS=PASS", self.workflow)
        self.assertNotIn("repository_dispatch", self.workflow)
        self.assertNotIn("gh issue create", self.workflow)
        self.assertIn('test "$SMOKE_OUTCOME" = success', self.workflow)


if __name__ == "__main__":
    unittest.main()
