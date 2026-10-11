"""Offline guards for the one-shot authenticated Codex dual VPS smoke test."""
from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/codex-dual-vps-smoke.yml").read_text(
    encoding="utf-8"
)
SCRIPT = (ROOT / "ops/codex-dual-vps-smoke.sh").read_text(
    encoding="utf-8"
)


class CodexDualVPSSmokeContractTests(unittest.TestCase):
    def test_actual_executor_is_pinned_and_private(self) -> None:
        self.assertIn("364ade7ca0e5bca1e788d04cad8bbe071cd22f88", SCRIPT)
        self.assertIn("https://github.com/martaxi-boss/Project-leader-codex.git", SCRIPT)
        self.assertIn("python3 -m codex.dual run", SCRIPT)
        self.assertIn("--execute", SCRIPT)
        self.assertIn('test ! -e "$source"', SCRIPT)
        self.assertIn('cd "$source"', SCRIPT)
        self.assertIn("$HOME/codex-agent/node_modules/.bin/codex", SCRIPT)
        self.assertIn('"$codex_cli" login status', SCRIPT)
        self.assertIn("flock -n 8", SCRIPT)
        self.assertIn("flock -n 9", SCRIPT)
        self.assertNotIn("sudo ", SCRIPT)
        self.assertNotIn("git push", SCRIPT)
        self.assertNotIn("git commit", SCRIPT)
        self.assertNotIn("sshpass", SCRIPT)

    def test_order_uses_two_disjoint_minimal_low_jobs(self) -> None:
        manifest = json.loads(SCRIPT.split("<<'ORDER'\n", 1)[1].split("\nORDER", 1)[0])
        self.assertEqual(manifest["target_repository"],
                         "martaxi-boss/Project-leader-codex")
        self.assertEqual(manifest["mode"], "parallel")
        self.assertEqual(len(manifest["tasks"]), 2)
        paths = [task["paths"][0] for task in manifest["tasks"]]
        self.assertEqual(paths, ["codex-smoke/alpha.txt", "codex-smoke/beta.txt"])
        self.assertEqual({task["reasoning_effort"] for task in manifest["tasks"]},
                         {"low"})
        self.assertTrue(all(len(task["paths"]) == 1 for task in manifest["tasks"]))
        self.assertTrue(all("typo" in task["task"] for task in manifest["tasks"]))

    def test_actual_simultaneous_execution_and_scope_must_be_proved(self) -> None:
        self.assertIn("simultaneous_processes", SCRIPT)
        self.assertIn('tag, name, stamp = line.split("\\t")', SCRIPT)
        self.assertIn('start < finish', SCRIPT)
        self.assertIn('worker.get("new_paths") == [owned]', SCRIPT)
        self.assertIn('worker.get("out_of_scope") == []', SCRIPT)
        self.assertIn('worker.get("ref_changes") == []', SCRIPT)
        self.assertIn('worker.get("commit_detected") is False', SCRIPT)
        self.assertIn('proof["source_checkout_unchanged"]', SCRIPT)
        self.assertIn('git_sha = dual._git(base, "rev-parse", "HEAD")', SCRIPT)
        self.assertIn('cleanliness = dual._git(base, "status", "--porcelain")', SCRIPT)
        self.assertIn('proof["status"] = "PASS" if (', SCRIPT)

    def test_owner_only_dispatch_and_no_ssh_on_pull_request(self) -> None:
        self.assertIn("on:\n  issues:\n    types: [opened]\n  pull_request:", WORKFLOW)
        self.assertIn("github.event.issue.user.login == github.repository_owner", WORKFLOW)
        self.assertIn("'[codex dual smoke] Test two isolated Codex agents'", WORKFLOW)
        self.assertIn("if: github.event_name == 'pull_request'", WORKFLOW)
        self.assertIn('bash -n ops/codex-dual-vps-smoke.sh', WORKFLOW)
        self.assertIn('permissions: {}\n', WORKFLOW)
        self.assertIn("cancel-in-progress: false", WORKFLOW)
        self.assertIn("persist-credentials: false", WORKFLOW)
        self.assertIn("github.event.repository.default_branch", WORKFLOW)
        self.assertIn("secrets.VPS_SSH_PASSWORD", WORKFLOW)
        self.assertIn("steps.execute.outcome == 'success'", WORKFLOW)

    def test_ssh_identity_must_be_pinned_before_secret_access(self) -> None:
        self.assertIn("SHA256:Q7y5zs6sXWHtznlMQS/IQjcqPKdr7YEku1hwINLvdxc", WORKFLOW)
        self.assertIn("ssh-keygen -lf", WORKFLOW)
        self.assertIn("HostKeyAlgorithms=ssh-ed25519", WORKFLOW)
        self.assertIn("StrictHostKeyChecking=yes", WORKFLOW)
        self.assertIn("UserKnownHostsFile=", WORKFLOW)
        self.assertNotIn("StrictHostKeyChecking=accept-new", WORKFLOW)
        self.assertIn("host-key-probe:", WORKFLOW)
        self.assertIn("ops/codex_resource_policy.py", WORKFLOW)

    def test_live_smoke_never_bypasses_shared_account_budget(self) -> None:
        self.assertIn("$HOME/codex-bridge/.account-budget", SCRIPT)
        self.assertIn('reserve "$budget_root" "$budget_job_base-1" low', SCRIPT)
        self.assertIn('reserve "$budget_root" "$budget_job_base-2" low', SCRIPT)
        self.assertIn('settle "$budget_root" "$budget_job_base-$idx"', SCRIPT)
        self.assertIn('"observed": False', SCRIPT)
        self.assertIn('trap finish_smoke EXIT', SCRIPT)
        self.assertIn('shared_soft_budget_unavailable', SCRIPT)

    def test_public_report_is_allowlisted_without_model_output(self) -> None:
        self.assertIn('len(proof.get("workers", []))', WORKFLOW)
        self.assertIn('state not in ("PASS", "FAIL", "FAILED"', WORKFLOW)
        self.assertIn('"internal_sanitized_diagnostic"', WORKFLOW)
        self.assertNotIn("runner.stderr", WORKFLOW)
        self.assertNotIn("runner.json", WORKFLOW)
        self.assertNotIn("worker-events.tsv", WORKFLOW)
        self.assertNotIn("cat $HOME", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
