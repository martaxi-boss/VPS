#!/usr/bin/env python3
"""Offline safety regression tests for the Codex patch guard."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = Path(__file__).with_name("codex_patch_guard.py")


def sh(cwd, *args):
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True)


class CodexPatchGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.assertEqual(sh(self.repo, "git", "init", "-q").returncode, 0)
        sh(self.repo, "git", "config", "user.name", "Codex CI")
        sh(self.repo, "git", "config", "user.email", "codex@example.invalid")
        (self.repo / "README.md").write_text("before\n")
        sh(self.repo, "git", "add", "README.md")
        self.assertEqual(sh(self.repo, "git", "commit", "-qm", "baseline").returncode, 0)
        self.patch = self.repo.parent / (self.repo.name + ".patch")

    def guard(self):
        return sh(self.repo, sys.executable, str(GUARD), str(self.patch))

    def test_ordinary_change_allowed(self):
        (self.repo / "README.md").write_text("after\n")
        done = self.guard()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("CODEX_PATCH_STATE=CHANGED", done.stdout)
        self.assertIn(b"README.md", self.patch.read_bytes())

    def test_protects_github_workflows(self):
        (self.repo / ".github" / "workflows").mkdir(parents=True)
        (self.repo / ".github" / "workflows" / "deploy.yml").write_text("name: test\n")
        done = self.guard()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("PATCH_REJECTED", done.stderr)

    def test_protects_credentials(self):
        (self.repo / ".env").write_text("SECRET=example\n")
        done = self.guard()
        self.assertNotEqual(done.returncode, 0)

    def test_no_change_returns_empty_patch(self):
        done = self.guard()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.patch.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
