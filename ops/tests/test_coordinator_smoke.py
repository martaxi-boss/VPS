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
        self.assertIn('> "$private/coordinator-result.json" 2>/dev/null', text)
        self.assertNotIn("gh issue create", text)
        self.assertNotIn("git push", text)
        self.assertNotIn("repository_dispatch", text)
        self.assertNotIn("chmod -R", text)


if __name__ == "__main__":
    unittest.main()
