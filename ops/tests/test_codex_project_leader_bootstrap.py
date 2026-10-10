"""Regression tests for automatic pinned Project Leader Skill loading in Codex."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

OPS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "codex_project_leader_bootstrap", OPS / "codex-project-leader-bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)

SHA = "a" * 40
SKILL = """---
name: project-leader
---
CANONICAL_RUNTIME_BOOTSTRAP
CAPABILITY_AND_RESULT_TRUTH
MINIMAL_COORDINATION_BUDGET
Supervisor
Human Gate
"""


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Codex Tests")
        self.git("config", "user.email", "codex-tests@example.invalid")
        self.put("plugins/project-leader/plugin.json",
                 json.dumps({"name": "project-leader", "version": "0.7.0"}))
        self.put("plugins/project-leader/skills/project-leader/SKILL.md", SKILL)
        self.put("projects/standing-authority.json", json.dumps({
            "source": "STANDING_OWNER_GRANT",
            "runtime_scope": "PROJECT_LEADER_SKILL_RUNTIME",
            "project_isolation": "ONE_MUTABLE_TARGET_REPOSITORY_PER_TASK",
            "required_controls": sorted(bootstrap.REQUIRED_CONTROLS),
        }))
        self.git("add", ".")
        self.git("commit", "-qm", "canonical fixture")
        self.head = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args], text=True)

    def put(self, path, content):
        p = self.repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def test_pinned_runtime_for_external_vps_task(self):
        text, data = bootstrap.load_runtime(self.repo, "martaxi-boss/VPS", SHA)
        self.assertEqual(self.head, data["canonical_revision"])
        self.assertEqual(1, data["loader_version"])
        self.assertEqual("0.7.0", data["plugin_version"])
        self.assertIn("RUNTIME_CANONICAL_REVISION=" + self.head, text)
        self.assertIn("CAPABILITY_AND_RESULT_TRUTH", text)
        self.assertIn("MINIMAL_COORDINATION_BUDGET", text)
        self.assertIn("trusted publisher independently enforces scope", text)

    def test_runtime_reads_exact_git_object_not_dirty_worktree(self):
        self.put("plugins/project-leader/skills/project-leader/SKILL.md",
                 "MALICIOUS_UNCOMMITTED_WORKTREE_CONTENT")
        text, _ = bootstrap.load_runtime(self.repo, "martaxi-boss/VPS", SHA)
        self.assertIn("CAPABILITY_AND_RESULT_TRUTH", text)
        self.assertNotIn("MALICIOUS_UNCOMMITTED", text)

    def test_project_leader_target_requires_same_exact_sha(self):
        _, data = bootstrap.load_runtime(
            self.repo, "martaxi-boss/Project-leader", self.head)
        self.assertEqual(data["canonical_revision"], data["target_revision"])
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_runtime(self.repo, "martaxi-boss/Project-leader", SHA)

    def test_unknown_target_rejected(self):
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_runtime(self.repo, "attacker/repo", SHA)

    def test_invalid_target_sha_rejected(self):
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_runtime(self.repo, "martaxi-boss/VPS", "main")

    def test_missing_required_skill_rule_rejected(self):
        self.put("plugins/project-leader/skills/project-leader/SKILL.md",
                 SKILL.replace("MINIMAL_COORDINATION_BUDGET", ""))
        self.git("add", ".")
        self.git("commit", "-qm", "remove rule")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_runtime(self.repo, "martaxi-boss/VPS", SHA)

    def test_missing_standing_control_rejected(self):
        path = "projects/standing-authority.json"
        controls = sorted(bootstrap.REQUIRED_CONTROLS)
        self.put(path, json.dumps({
            "source": "STANDING_OWNER_GRANT",
            "runtime_scope": "PROJECT_LEADER_SKILL_RUNTIME",
            "project_isolation": "ONE_MUTABLE_TARGET_REPOSITORY_PER_TASK",
            "required_controls": controls[1:],
        }))
        self.git("add", ".")
        self.git("commit", "-qm", "remove control")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_runtime(self.repo, "martaxi-boss/VPS", SHA)

    def test_missing_canonical_skill_rejected(self):
        self.git("rm", "plugins/project-leader/skills/project-leader/SKILL.md")
        self.git("commit", "-qm", "remove skill")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_runtime(self.repo, "martaxi-boss/VPS", SHA)

    def test_no_new_mutable_target_from_bootstrap(self):
        before = self.git("status", "--porcelain")
        bootstrap.load_runtime(self.repo, "martaxi-boss/VPS", SHA)
        after = self.git("status", "--porcelain")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
