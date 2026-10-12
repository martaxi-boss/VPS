"""Read-only preflight: no GitHub token data, git writes or model calls."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "codex-publish-probe.py"
spec = importlib.util.spec_from_file_location("codex_publish_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class PublicationProbeTests(unittest.TestCase):
    def test_known_git_errors_are_classified_without_raw_text(self):
        self.assertEqual(probe.classify("remote: Permission to repo denied to token", 128),
                         "permission_denied")
        self.assertEqual(probe.classify("fatal: Authentication failed", 128),
                         "authentication")
        self.assertEqual(probe.classify("GH013 repository rule violation", 1),
                         "branch_rules")
        self.assertEqual(probe.classify("unauthorized credential=private-value", 1),
                         "other_git_failure")
        self.assertEqual(probe.classify("", 0), "accepted_dry_run")

    def test_owner_trigger_uses_real_github_expression_without_backslash(self):
        workflow = (SCRIPT.parents[1] / ".github/workflows/codex-publish-probe.yml").read_text(
            encoding="utf-8")
        self.assertNotIn("\\${{", workflow)
        self.assertIn("${{ secrets.CODEX_GITHUB_TOKEN }}", workflow)
        self.assertIn("${{ github.token }}", workflow)
        self.assertIn("${{ github.event.issue.number }}", workflow)
        self.assertIn("github.event.issue.user.login == github.repository_owner", workflow)

    def test_probe_has_fixed_repo_and_is_dry_run_only(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(probe.REPO, "martaxi-boss/Project-leader-codex")
        self.assertEqual(probe.BRANCH, "codex/issue-134-38235356661-1-1")
        self.assertIn('"--dry-run"', source)
        self.assertIn("publisher.git_push_environment(root)", source)
        self.assertIn('"models_called": False, "git_writes": False', source)
        self.assertNotIn("codex exec", source)
        self.assertNotIn("git commit", source)
        self.assertNotIn("git branch -D", source)

if __name__ == "__main__":
    unittest.main()
