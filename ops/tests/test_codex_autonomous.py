"""Tests for trusted Codex publisher: no green result by assertion alone."""
import importlib.util
import json
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

OPS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS))
spec = importlib.util.spec_from_file_location('codex_autonomous_publish', OPS / 'codex-autonomous-publish.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

SHA = 'a' * 40
BRANCH = 'codex/issue-1-321-1'
REQUIRED = {
    ('Control contract tests', 'pull_request'),
    ('Validate control plane', 'pull_request'),
    ('Package ChatGPT plugins', 'pull_request'),
    ('Trusted authorization gate', 'pull_request_target'),
}


def success(name, event='pull_request', sha=SHA, branch=BRANCH, conclusion='success'):
    return {'name': name, 'event': event, 'head_sha': sha, 'head_branch': branch,
            'status': 'completed', 'conclusion': conclusion, 'created_at': '2026-10-10T09:00:00Z'}


class CheckGateTests(unittest.TestCase):
    def runs(self):
        return [success(name, event) for name, event in REQUIRED]

    def test_exact_head_four_required_checks_pass(self):
        state, _ = publisher.classify_runs(self.runs(), REQUIRED, SHA, BRANCH)
        self.assertEqual('PASS', state)

    def test_missing_gate_cannot_be_green(self):
        runs = [r for r in self.runs() if r['name'] != 'Trusted authorization gate']
        state, _ = publisher.classify_runs(runs, REQUIRED, SHA, BRANCH)
        self.assertEqual('WAIT', state)

    def test_stale_sha_never_counts_as_pass(self):
        runs = [dict(r, head_sha='b'*40) for r in self.runs()]
        self.assertEqual('WAIT', publisher.classify_runs(runs, REQUIRED, SHA, BRANCH)[0])

    def test_different_branch_never_counts_as_pass(self):
        runs = [dict(r, head_branch='old/branch') for r in self.runs()]
        self.assertEqual('WAIT', publisher.classify_runs(runs, REQUIRED, SHA, BRANCH)[0])

    def test_ci_failure_blocks_merge(self):
        runs = self.runs()
        runs[0]['conclusion'] = 'failure'
        self.assertEqual('BLOCKED', publisher.classify_runs(runs, REQUIRED, SHA, BRANCH)[0])

    def test_unrelated_active_ci_still_blocks_early_merge(self):
        runs = self.runs() + [dict(success('VPS SSH Access PR Check'),
                                  status='in_progress', conclusion=None)]
        self.assertEqual('WAIT', publisher.classify_runs(runs, REQUIRED, SHA, BRANCH)[0])

    def test_pending_ci_never_counts_as_pass(self):
        runs = self.runs()
        runs[0]['status'] = 'in_progress'
        runs[0]['conclusion'] = None
        self.assertEqual('WAIT', publisher.classify_runs(runs, REQUIRED, SHA, BRANCH)[0])

    def test_no_workflow_reports_no_green(self):
        self.assertEqual('WAIT', publisher.classify_runs([], REQUIRED, SHA, BRANCH)[0])

    def test_project_leader_material_merge_needs_e2_record(self):
        self.assertIn('E2', publisher.premerge_policy_gate(
            'martaxi-boss/Project-leader', ['SOURCES.md']))

    def test_vps_operational_code_not_silently_merged(self):
        self.assertIn('test gate', publisher.premerge_policy_gate(
            'martaxi-boss/VPS', ['ops/telegram_gateway.py']))

    def test_pink_target_requires_independent_validation_and_never_auto_merges(self):
        repo = "martaxi-boss/pink-iptv"
        self.assertIn(repo, publisher.ALLOWED)
        self.assertEqual(publisher.ALLOWED[repo], set())
        state, reason = publisher.classify_runs([], publisher.ALLOWED[repo], SHA, BRANCH)
        self.assertEqual(state, "BLOCKED")
        self.assertIn("independent", reason.lower())
        policy = publisher.premerge_policy_gate(repo, ["backend/app/vpn.py"])
        self.assertIn("NEVER auto-merge", policy)
        self.assertIn("PINK IPTV", policy)
        result = publisher.staged_pr_result(
            repo, "https://github.com/martaxi-boss/pink-iptv/pull/200",
            SHA, policy, state, reason)
        self.assertEqual(result["status"], "PR_NEEDS_ATTENTION")
        self.assertNotIn("merge_sha", result)
        self.assertIn("independent", result["reason"].lower())
        # Even documentation-only PINK changes cannot use the VPS docs
        # shortcut that permits unattended main merges.
        self.assertIn("NEVER auto-merge", publisher.premerge_policy_gate(
            repo, ["README.md"]))

    def test_specialization_never_auto_merges_or_touches_original_project_leader(self):
        repo = "martaxi-boss/Project-leader-codex"
        required = {
            ("Codex specialization tests", "pull_request"),
            ("Control contract tests", "pull_request"),
            ("Validate control plane", "pull_request"),
            ("Package ChatGPT plugins", "pull_request"),
        }
        self.assertEqual(publisher.ALLOWED[repo], required)
        self.assertEqual("PASS", publisher.classify_runs(
            [success(name, event=event) for name, event in required],
            required, SHA, BRANCH)[0])
        policy = publisher.premerge_policy_gate(repo, ["README.md"])
        self.assertIn("PR-ONLY", policy)
        self.assertIn("NEVER auto-merge", policy)
        self.assertIn("NEVER auto-merge", publisher.premerge_policy_gate(
            repo, ["codex/dual.py"]))
        result = publisher.staged_pr_result(
            repo, "https://github.com/martaxi-boss/Project-leader-codex/pull/9",
            SHA, policy, "PASS", "Exact head CI passed")
        self.assertEqual(result["status"], "PR_STAGED")
        self.assertNotIn("merge_sha", result)

    def test_specialization_direct_publisher_waits_ci_without_auto_merge(self):
        source = (OPS / "codex-autonomous-publish.py").read_text(encoding="utf-8")
        self.assertIn('if pr_only or repo == "martaxi-boss/Project-leader-codex":',
                      source)
        self.assertIn("state, evidence = wait_for_checks(repo, sha, branch, ALLOWED[repo])",
                      source)
        self.assertIn("return staged_pr_result(repo, url, sha, blocking_policy, state, evidence)",
                      source)

    def test_vps_docs_may_progress_to_ci(self):
        self.assertIsNone(publisher.premerge_policy_gate(
            'martaxi-boss/VPS', ['README.md']))

    def test_vps_its_own_independent_gate(self):
        required = publisher.ALLOWED['martaxi-boss/VPS']
        self.assertEqual('PASS', publisher.classify_runs(
            [success('Codex autonomous validation')], required, SHA, BRANCH)[0])


class SpecializationRouteTests(unittest.TestCase):
    def test_normal_authorization_stages_match_target_slug(self):
        flow = (OPS.parent / ".github/workflows/codex-autonomous.yml").read_text(
            encoding="utf-8")
        remote = (OPS / "codex-autonomous-remote.sh").read_text(encoding="utf-8")
        loader = (OPS / "codex-project-leader-bootstrap.py").read_text(
            encoding="utf-8")
        self.assertIn("'TARGET_REPOSITORY=martaxi-boss/Project-leader-codex'", flow)
        self.assertIn("TARGET_REPOSITORY=martaxi-boss/Project-leader-codex)", remote)
        self.assertIn('"martaxi-boss/Project-leader-codex"', loader)

    def test_normal_executor_pins_ssh_before_any_password_is_used(self):
        flow = (OPS.parent / ".github/workflows/codex-autonomous.yml").read_text(
            encoding="utf-8")
        self.assertIn("Pin Owner-provided SSH host key before using any VPS credential", flow)
        self.assertIn("ssh-keyscan -T 15 -t ed25519", flow)
        self.assertIn("SHA256:Q7y5zs6sXWHtznlMQS/IQjcqPKdr7YEku1hWlNLvdxc", flow)
        self.assertEqual(flow.count("StrictHostKeyChecking=yes"), 5)
        self.assertNotIn("StrictHostKeyChecking=accept-new", flow)
        self.assertLess(flow.index("Pin Owner-provided SSH host key"),
                        flow.index("Prepare isolated SSH client"))


class SerialResultHandshakeTests(unittest.TestCase):
    def test_reusable_executor_exposes_verified_publication_outcome(self):
        flow = (OPS.parent / ".github/workflows/codex-autonomous.yml").read_text(
            encoding="utf-8")
        self.assertIn("value: ${{ jobs.execute.outputs.publication_status }}", flow)
        self.assertIn("publication_status: ${{ steps.publish.outputs.publication_status }}",
                      flow)
        self.assertIn('"publication_status=" + status +', flow)
        self.assertIn('{"MERGED", "NO_CHANGE", "PR_STAGED"}', flow)

    def test_serial_second_worker_requires_merged_or_allowed_no_change(self):
        flow = (OPS.parent / ".github/workflows/agent-switch.yml").read_text(
            encoding="utf-8")
        second = flow.split("  codex_serial_2:", 1)[1].split(
            "  codex_serial_blocked:", 1)[0]
        self.assertIn("needs.codex_serial_1.outputs.publication_status == 'MERGED'",
                      second)
        self.assertIn("needs.codex_serial_1.outputs.publication_status == 'NO_CHANGE'",
                      second)
        self.assertIn("PR_STAGED", flow.split("  codex_serial_blocked:", 1)[1])
        self.assertIn("CODEX_2_NOT_STARTED:", flow)

class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'target.txt').write_text('martaxi-boss/Project-leader\n')
        (self.root / 'base-sha.txt').write_text(SHA+'\n')
        (self.root / 'codex-task.txt').write_text(
            'TARGET_REPOSITORY=martaxi-boss/Project-leader\nFix one doc.\n')
        (self.root / 'patch.diff').write_bytes(b'')
        self.runtime = {
            'loader_version': 1,
            'source_repository': 'martaxi-boss/Project-leader',
            'canonical_revision': SHA,
            'plugin_version': '0.7.0',
            'target_repository': 'martaxi-boss/Project-leader',
            'target_revision': SHA,
            'mode': 'PINNED_CANONICAL_SKILL',
        }
        self.save_runtime()

    def save_runtime(self):
        (self.root / 'project-leader-runtime.json').write_text(
            json.dumps(self.runtime) + '\n')

    def test_allowlisted_target(self):
        self.assertEqual('martaxi-boss/Project-leader', publisher.validate_metadata(self.root)[0])

    def test_rejects_unknown_target(self):
        (self.root / 'target.txt').write_text('attacker/repo\n')
        with self.assertRaises(ValueError):
            publisher.validate_metadata(self.root)

    def test_rejects_task_mismatch(self):
        (self.root / 'codex-task.txt').write_text('TARGET_REPOSITORY=martaxi-boss/VPS\n')
        with self.assertRaises(ValueError):
            publisher.validate_metadata(self.root)

    def test_rejects_malformed_sha(self):
        (self.root / 'base-sha.txt').write_text('not-a-sha\n')
        with self.assertRaises(ValueError):
            publisher.validate_metadata(self.root)

    def test_rejects_oversized_patch(self):
        with (self.root / 'patch.diff').open('wb') as f:
            f.truncate(publisher.MAX_PATCH_BYTES + 1)
        with self.assertRaises(ValueError):
            publisher.validate_metadata(self.root)

    def test_missing_project_leader_runtime_blocks_publication(self):
        (self.root / 'project-leader-runtime.json').unlink()
        with self.assertRaises(ValueError):
            publisher.validate_metadata(self.root)

    def test_wrong_project_leader_runtime_sha_blocks_publication(self):
        self.runtime['canonical_revision'] = 'b' * 40
        self.save_runtime()
        with self.assertRaises(ValueError):
            publisher.validate_metadata(self.root)

    def test_wrong_project_leader_runtime_source_blocks_publication(self):
        self.runtime['source_repository'] = 'untrusted/project-leader'
        self.save_runtime()
        with self.assertRaises(ValueError):
            publisher.validate_metadata(self.root)

    def test_vps_target_accepts_distinct_canonical_runtime_revision(self):
        (self.root / 'target.txt').write_text('martaxi-boss/VPS\n')
        (self.root / 'codex-task.txt').write_text(
            'TARGET_REPOSITORY=martaxi-boss/VPS\nFix a doc.\n')
        self.runtime['target_repository'] = 'martaxi-boss/VPS'
        self.runtime['canonical_revision'] = 'b' * 40
        self.save_runtime()
        self.assertEqual('martaxi-boss/VPS',
                         publisher.validate_metadata(self.root)[0])


class TwoWorkerPublicationTests(unittest.TestCase):
    """Parallel workers get distinct PR names and can never claim auto-merge."""

    def test_single_codex_branch_is_unchanged(self):
        self.assertEqual(
            publisher.worker_branch_name("99", "456", "1"),
            "codex/issue-99-456-1",
        )

    def test_two_workers_have_different_branches(self):
        self.assertEqual(
            publisher.worker_branch_name("99", "456", "1", "1"),
            "codex/issue-99-456-1-1",
        )
        self.assertEqual(
            publisher.worker_branch_name("99", "456", "1", "2"),
            "codex/issue-99-456-1-2",
        )

    def test_untrusted_worker_identity_fails_closed(self):
        with self.assertRaises(ValueError):
            publisher.worker_branch_name("99", "456", "1", "../secrets")

    def test_parallel_ready_pr_never_claims_a_merge(self):
        result = publisher.staged_pr_result(
            "martaxi-boss/VPS", "https://github.com/martaxi-boss/VPS/pull/100",
            SHA, None, "PASS", "Exact SHA checks passed",
        )
        self.assertEqual(result["status"], "PR_STAGED")
        self.assertNotIn("merge_sha", result)
        self.assertIn("no merge attempted", result["reason"])

    def test_operational_code_keeps_independent_test_gate(self):
        policy = publisher.premerge_policy_gate(
            "martaxi-boss/VPS", ["ops/agent_switch.py"]
        )
        result = publisher.staged_pr_result(
            "martaxi-boss/VPS", "https://github.com/martaxi-boss/VPS/pull/100",
            SHA, policy, "PASS", "Exact SHA checks passed",
        )
        self.assertEqual(result["status"], "PR_STAGED")
        self.assertIn("independent project-specific test gate", result["reason"])

    def test_failed_ci_never_becomes_ready(self):
        result = publisher.staged_pr_result(
            "martaxi-boss/VPS", "https://github.com/martaxi-boss/VPS/pull/100",
            SHA, None, "BLOCKED", "Named CI failed",
        )
        self.assertEqual(result["status"], "PR_NEEDS_ATTENTION")
        self.assertEqual(result["reason"], "Named CI failed")



class SharedCodexAccountSlotsTests(unittest.TestCase):
    """All active Codex entrypoints must obey the same VPS account budget."""

    def test_every_entrypoint_has_two_identical_lock_names_before_model(self):
        paths = [
            "codex-autonomous-remote.sh",
            "codex-vps-remote.sh",
            "codex-project-leader-remote.sh",
        ]
        for name in paths:
            with self.subTest(name=name):
                script = (OPS / name).read_text(encoding="utf-8")
                self.assertIn('.codex-slot-1.lock', script)
                self.assertIn('.codex-slot-2.lock', script)
                self.assertNotIn('.codex-slot-3.lock', script)
                self.assertIn('flock -n 8', script)
                self.assertIn('flock -n 9', script)
                self.assertIn('slot=0', script)
                self.assertIn('[ "$slot" -ne 0 ]', script)
                exec_call = '"$cli" exec' if name == 'codex-autonomous-remote.sh' else '"$codex" exec'
                self.assertLess(script.index('flock -n 8'), script.index(exec_call))
                subprocess.run(['bash', '-n', str(OPS / name)], check=True)



class NoChangeAndQueueSafetyTests(unittest.TestCase):
    """Loss, false-success and failure-cleanup regressions are fail-closed."""

    def test_empty_patch_without_owner_consent_never_passes(self):
        result = publisher.no_change_result("martaxi-boss/VPS", allowed=False)
        self.assertEqual("NO_CHANGE_UNVERIFIED", result["status"])
        self.assertIn("NOT_VERIFIED", result["reason"])

    def test_explicit_read_only_no_change_is_truthfully_scoped(self):
        result = publisher.no_change_result("martaxi-boss/VPS", allowed=True)
        self.assertEqual("NO_CHANGE", result["status"])
        self.assertIn("not independently verified", result["reason"])

    def test_github_queue_does_not_replace_earlier_pending_codex_order(self):
        workflow = (OPS.parent / ".github/workflows/codex-autonomous.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("  queue: max", workflow)
        self.assertIn("  cancel-in-progress: false", workflow)

    def test_serial_dependent_skip_has_durable_owner_notice(self):
        workflow = (OPS.parent / ".github/workflows/agent-switch.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("codex_serial_blocked:", workflow)
        self.assertIn("CODEX_2_NOT_STARTED:", workflow)

    def test_shared_soft_budget_failure_is_reported_without_raw_private_logs(self):
        remote = (OPS / "codex-autonomous-remote.sh").read_text(encoding="utf-8")
        flow = (OPS.parent / ".github/workflows/codex-autonomous.yml").read_text(
            encoding="utf-8")
        self.assertIn("SOFT_BUDGET_POLICY_BLOCKED", remote)
        self.assertIn('> "$base/codex-preflight-signal.txt"', remote)
        self.assertLess(remote.index('codex-preflight-signal.txt'),
                        remote.index('"$cli" exec'))
        self.assertIn('project-leader-runtime.json report.md codex-preflight-signal.txt; do', flow)
        self.assertIn("signal_path.stat().st_size <= 64", flow)
        self.assertIn("signal_path.is_symlink()", flow)
        self.assertIn("== 'SOFT_BUDGET_POLICY_BLOCKED'", flow)
        self.assertIn("('NOT_STARTED' if denied else 'NOT_COMPLETED')", flow)
        self.assertIn("no model started.", flow)
        self.assertNotIn("cli.stderr", flow)
        self.assertNotIn("usage-budget.json", flow)

    def test_failed_codex_runs_attempt_workspace_cleanup(self):
        workflow = (OPS.parent / ".github/workflows/codex-autonomous.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("if: always() && steps.stage.outcome != 'skipped'", workflow)
        self.assertIn("CODEX_ALLOW_NO_CHANGE:", workflow)



class DirectIssueInputDefaultsTests(unittest.TestCase):
    """Original [codex run] Issue route does not set workflow_call inputs."""

    def test_missing_or_empty_boolean_inputs_are_false(self):
        for raw in (None, "", "false", "FALSE"):
            with self.subTest(raw=raw):
                self.assertIs(False, publisher.parse_workflow_boolean(raw, "test"))

    def test_true_remains_explicit_and_enabled(self):
        self.assertIs(True, publisher.parse_workflow_boolean("true", "test"))

    def test_invalid_policy_values_fail_closed(self):
        for raw in ("yes", "0", " false ", 0, True, [], {}):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                publisher.parse_workflow_boolean(raw, "test")



class PrivateOwnerReportDeliveryTests(unittest.TestCase):
    def test_private_report_is_fetched_and_delivered_using_existing_gateway(self):
        flow = (OPS.parent / '.github/workflows/codex-autonomous.yml').read_text(encoding='utf-8')
        self.assertIn('project-leader-runtime.json report.md codex-preflight-signal.txt; do', flow)
        self.assertIn('python3 ops/telegram_gateway.py notify', flow)
        self.assertIn('secrets.TELEGRAM_BOT_TOKEN', flow)
        self.assertIn('secrets.TELEGRAM_CHAT_ID', flow)
        self.assertIn('SENT_TO_PRIVATE_TELEGRAM', flow)
        self.assertIn('NOT_CONFIGURED', flow)
        self.assertIn('INVALID_PRIVATE_DESTINATION', flow)
        self.assertIn('OVERSIZED_REPORT_NOT_SENT', flow)

    def test_public_issue_comment_never_loads_raw_agent_report(self):
        flow = (OPS.parent / '.github/workflows/codex-autonomous.yml').read_text(encoding='utf-8')
        a = flow.index('      - name: Publish truthful execution result to Owner Issue')
        b = flow.index('      - name: Remove completed disposable VPS workspace')
        public = flow[a:b]
        self.assertIn('Full model report (not published publicly):', public)
        self.assertIn('codex-private-status.txt', public)
        self.assertNotIn('report.md', public)
        self.assertNotIn('sendDocument', public)

    def test_unconfigured_telegram_keeps_public_status(self):
        flow = (OPS.parent / '.github/workflows/codex-autonomous.yml').read_text(encoding='utf-8')
        self.assertIn('continue-on-error: true', flow)
        self.assertIn('if test -z "$TELEGRAM_BOT_TOKEN"', flow)
        self.assertIn('Weekly Codex quota percentage: UNKNOWN', flow)


if __name__ == '__main__':
    unittest.main()
