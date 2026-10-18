import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import telegram_leads_stage_20261019 as stage
from telegram_leads_stage_20261019 import stale_key, PINNED, DEST, VAULT, LEGACY_PREFIXES

class LeadsStagingPolicyTests(unittest.TestCase):
    def test_only_legacy_configuration_keys_are_removed(self):
        for key in ("SCRAPE_GROUPS", "MIN_ADDS_ACCOUNT", "MAX_ADDS_PROJECT_PER_DAY", "TELEGRAM_INVITES_ENABLED"):
            self.assertTrue(stale_key(key + "=irrelevant\n"))
        for key in ("TELEGRAM_API_ID", "TELEGRAM_API_HASH", "TARGET_GROUP", "TELEGRAM_TZ",
                    "TELEGRAM_OPERATION_STATE", "TELEGRAM_APPROVED_USERS"):
            self.assertFalse(stale_key(key + "=private_or_current\n"))
        self.assertFalse(stale_key("# SCRAPE_GROUPS=archived comment\n"))

    def test_drop_git_history_only_after_pinned_commit_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder)
            gitdir = dest / ".git"
            gitdir.mkdir()
            with patch.object(stage.subprocess, "check_output",
                              return_value=stage.PINNED + "\\n"):
                self.assertTrue(stage.finalize_source_checkout(dest))
            self.assertFalse(gitdir.exists())
            self.assertEqual((dest / ".verified-source-commit").read_text().strip(),
                             stage.PINNED)
            self.assertFalse(stage.finalize_source_checkout(dest))

    def test_mismatched_source_does_not_delete_git(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder)
            gitdir = dest / ".git"
            gitdir.mkdir()
            with patch.object(stage.subprocess, "check_output",
                              return_value="0" * 40 + "\\n"):
                with self.assertRaises(stage.StageBlocked):
                    stage.finalize_source_checkout(dest)
            self.assertTrue(gitdir.exists())

    def test_staging_is_pinned_to_one_repo_path(self):
        self.assertEqual(len(PINNED), 40)
        self.assertEqual(str(DEST), "/opt/telegram-robot-leads")
        self.assertEqual(str(VAULT), "/root/project-secrets/telegram-robot-leads")
        self.assertNotIn("IPTV", str(DEST))
        self.assertEqual(LEGACY_PREFIXES, ("SCRAPE_", "MIN_ADDS_", "MAX_ADDS_"))

if __name__ == "__main__":
    unittest.main()
