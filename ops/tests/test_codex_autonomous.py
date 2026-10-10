"""Tests for trusted Codex publisher: no green result by assertion alone."""
import importlib.util
import json
import sys
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

    def test_vps_docs_may_progress_to_ci(self):
        self.assertIsNone(publisher.premerge_policy_gate(
            'martaxi-boss/VPS', ['README.md']))

    def test_vps_its_own_independent_gate(self):
        required = publisher.ALLOWED['martaxi-boss/VPS']
        self.assertEqual('PASS', publisher.classify_runs(
            [success('Codex autonomous validation')], required, SHA, BRANCH)[0])


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


if __name__ == '__main__':
    unittest.main()
