#!/usr/bin/env python3
"""Safely preserving real work on a quota error, no Codex credits needed."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from ops import codex_quota_workspace as hold


class WorktreeCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / "12345-1-p2-1"
        self.base.mkdir(mode=0o700)
        self.repo = self.base / "repository"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "offline@example.com"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Offline Test"], check=True)
        (self.repo / "tracked.txt").write_text("First")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "baseline"], check=True)
        (self.base / "codex-preflight-signal.txt").write_bytes(b"CODEX_QUOTA_BLOCKED\n")

    def test_preserve_all_work_including_untracked_files_in_private_dir(self):
        (self.repo / "tracked.txt").write_text("Edited by original Codex before quota.")
        (self.repo / "new-file.txt").write_text("New untracked work retained")
        result = hold.attest(self.base, "12345-1-p2-1")
        self.assertTrue(result["private_worktree"])
        self.assertEqual(result["owner_resumption"], "NEW_OWNER_ORDER_REQUIRED")
        self.assertEqual(result["job"], self.base.name)
        self.assertEqual((self.repo / "tracked.txt").read_text(),
                         "Edited by original Codex before quota.")
        self.assertEqual((self.repo / "new-file.txt").read_text(),
                         "New untracked work retained")
        proof = self.base / hold.PROOF
        self.assertEqual(proof.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("Edited by original", proof.read_text())
        self.assertNotIn("new-file.txt", proof.read_text())
        self.assertEqual(json.loads(proof.read_text())["base_sha"], result["base_sha"])

    def test_no_provider_error_means_no_preserved_quota_claim(self):
        (self.base / "codex-preflight-signal.txt").write_bytes(b"NOT_A_QUOTA_ERROR\n")
        with self.assertRaises(hold.CheckpointError):
            hold.attest(self.base, self.base.name)
        self.assertFalse((self.base / hold.PROOF).exists())

    def test_invalid_worker_key_or_private_permissions_refused(self):
        with self.assertRaises(hold.CheckpointError):
            hold.attest(self.base, "../../escape")
        self.base.chmod(0o755)
        with self.assertRaisesRegex(hold.CheckpointError, "NOT_PRIVATE"):
            hold.attest(self.base, self.base.name)

    def test_no_second_overwrite_or_false_checkpoint_resume(self):
        hold.attest(self.base, self.base.name)
        with self.assertRaisesRegex(hold.CheckpointError, "PROOF_NOT_WRITTEN"):
            hold.attest(self.base, self.base.name)

    def test_missing_clone_does_not_claim_progress_preserved(self):
        import shutil
        shutil.rmtree(self.repo)
        with self.assertRaisesRegex(hold.CheckpointError, "WORKTREE_UNAVAILABLE"):
            hold.attest(self.base, self.base.name)


if __name__ == "__main__":
    unittest.main()
