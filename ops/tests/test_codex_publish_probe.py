"""Read-only preflight: no GitHub token data, git writes or model calls."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock
import os
import subprocess

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

    def test_rest_failure_still_probes_git_without_authorizing_models(self):
        publisher = mock.Mock()
        publisher.api.side_effect = RuntimeError(
            "GitHub GET repos/martaxi-boss/Project-leader-codex HTTP 403")
        publisher.git_push_environment.return_value = {}
        ok = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.dict(os.environ, {"CODEX_GITHUB_TOKEN": "unit-test-only"}):
            with mock.patch.object(probe, "publisher_module", return_value=publisher):
                with mock.patch.object(probe, "call", side_effect=[ok, ok, ok]) as git:
                    result = probe.diagnose()
        self.assertEqual(result["api_check"], "http_403")
        self.assertEqual(result["status"], "PERMISSION_QUERY_FAILED")
        self.assertEqual(result["normal"], "accepted_dry_run")
        self.assertEqual(git.call_count, 3)
        self.assertFalse(result["git_writes"])
        self.assertFalse(result["models_called"])

    def test_rest_success_and_git_success_are_both_required(self):
        publisher = mock.Mock()
        publisher.api.return_value = {"permissions": {"push": True}}
        publisher.git_push_environment.return_value = {}
        ok = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.dict(os.environ, {"CODEX_GITHUB_TOKEN": "unit-test-only"}):
            with mock.patch.object(probe, "publisher_module", return_value=publisher):
                with mock.patch.object(probe, "call", side_effect=[ok, ok, ok]):
                    result = probe.diagnose()
        self.assertEqual(result["api_check"], "ok")
        self.assertEqual(result["status"], "DRY_RUN_ACCEPTED")

    def test_git_dry_run_refusal_is_not_masked_by_rest_success(self):
        publisher = mock.Mock()
        publisher.api.return_value = {"permissions": {"push": True}}
        publisher.git_push_environment.return_value = {}
        ok = subprocess.CompletedProcess([], 0, "", "")
        denied = subprocess.CompletedProcess([], 128, "", "remote: Permission to repo denied")
        with mock.patch.dict(os.environ, {"CODEX_GITHUB_TOKEN": "unit-test-only"}):
            with mock.patch.object(probe, "publisher_module", return_value=publisher):
                with mock.patch.object(probe, "call",
                                       side_effect=[ok, ok, denied, denied]):
                    result = probe.diagnose()
        self.assertEqual(result["status"], "DRY_RUN_REFUSED")
        self.assertEqual(result["normal"], "permission_denied")
        self.assertEqual(result["no_helper"], "permission_denied")

if __name__ == "__main__":
    unittest.main()
