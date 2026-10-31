"""Quota/continuation contract tests: zero actual model calls or GitHub writes."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ops import codex_quota_resume as q
from ops import agent_switch


class QuotaLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.jsonl = root / "cli.jsonl"
        self.stderr = root / "cli.stderr"
        self.stderr.write_text("")
        self.manifest = json.dumps({
            "target_repository": "martaxi-boss/Project-leader-codex",
            "mode": "serial",
            "serial_independent": True,
            "tasks": [
                {"id": "first", "provider": "codex", "task":
                 "Implement bounded phase 1 and validate its tests"},
                {"id": "second", "provider": "codex", "task":
                 "Implement bounded phase 2 and validate its tests"},
            ],
        })
        self.owner_issue = {
            "number": 154, "user": {"login": q.OWNER},
            "title": "[agents run] continuation test",
            "state": "open", "body": self.manifest,
        }
        self.clock = 2_000_000_000
        self.pause = {
            "version": 1, "source_issue": 154, "stage": 2,
            "run_id": 42, "attempt": 0, "retry_at": self.clock - 1,
            "quota": "provider_error_not_local_ledger",
            "order_digest": q.order_digest(q._order(self.manifest)),
        }
        self.claim = {
            "version": 1, "source_issue": 154, "stage": 2,
            "run_id": 42, "attempt": 1,
            "claimed_at": self.clock - 5,
        }

    @staticmethod
    def comment(marker, item, ident=77, user=q.BOT):
        return {"id": ident, "user": {"login": user},
                "body": marker + "\n" + json.dumps(item)}

    def test_structured_quota_error_requires_actual_error_event(self):
        self.jsonl.write_text(json.dumps({
            "type": "turn.failed", "error": {
                "code": "usage_limit_reached", "message": "Usage limit reached"}}) + "\n")
        self.assertTrue(q.quota_error(self.jsonl, self.stderr))
        self.jsonl.write_text(json.dumps({
            "type": "item.completed", "item": {
                "type": "agent_message", "text": "quota exhausted"}}) + "\n")
        self.assertFalse(q.quota_error(self.jsonl, self.stderr))
        self.jsonl.write_text('{"type":"error","message":"HTTP 429"}\n')
        self.assertFalse(q.quota_error(self.jsonl, self.stderr))
        self.jsonl.write_text('{"type":"turn.failed","error":{"code":"auth_failed"}}\n')
        self.assertFalse(q.quota_error(self.jsonl, self.stderr))

    def test_fatal_cli_quota_error_only_not_arbitrary_stdout(self):
        self.jsonl.write_text("")
        self.stderr.write_text("Error: You have reached your weekly limit\n")
        self.assertTrue(q.quota_error(self.jsonl, self.stderr))
        self.stderr.write_text("model said quota exhausted\n")
        self.assertFalse(q.quota_error(self.jsonl, self.stderr))
        self.stderr.write_text("Error: SSH authentication failed\n")
        self.assertFalse(q.quota_error(self.jsonl, self.stderr))

    def test_retry_backoff_caps_one_model_rejection_per_day(self):
        self.assertEqual([q.delay_seconds(i) for i in (0, 1, 2, 3, 10)],
                         [7200, 14400, 28800, 57600, 86400])
        for invalid in (-1, 1001, 3.5, "0"):
            with self.assertRaises(q.QuotaResumeError):
                q.delay_seconds(invalid)

    def test_due_selection_preserves_claim_and_ignores_owner_forgery(self):
        rows = [self.comment(q.PAUSE, self.pause),
                self.comment(q.CLAIM, self.claim, 78)]
        self.assertEqual(q.due_pauses(rows, now=self.clock), [])
        self.assertEqual(len(q.due_pauses(rows[:1], now=self.clock)), 1)
        self.assertEqual(q.due_pauses(rows[:1], now=self.clock - 3), [])
        fake = self.comment(q.PAUSE, self.pause, 79, user=q.OWNER)
        self.assertEqual(q.due_pauses([fake], now=self.clock), [])

    def test_resume_requires_owner_bot_claim_exact_failure_and_only_pending_stage(self):
        rows = [self.comment(q.PAUSE, self.pause, 77),
                self.comment(q.CLAIM, self.claim, 78)]
        def api(method, path, payload=None):
            if path == "/issues/154":
                return self.owner_issue
            if path.startswith("/issues/154/comments?"):
                return rows
            if path == "/actions/runs/42":
                return {"id": 42, "name": "Agent switch (Owner GitHub order)",
                        "status": "completed", "conclusion": "failure"}
            raise AssertionError(path)
        dispatch = {"source_issue": 154, "stage": 2, "paused_run": 42,
                    "attempt": 1, "claim_comment": 78}
        with patch.object(q, "_api", side_effect=api):
            original, issue_id = q.verify_resume(dispatch, now=self.clock)
            self.assertEqual(issue_id, 154)
            self.assertEqual([t["id"] for t in original["tasks"]],
                             ["first", "second"])
            stages = agent_switch.workflow_values(original, "2")
            self.assertEqual((stages["run_stage_1"], stages["run_stage_2"]),
                             ("false", "true"))
            with self.assertRaises(q.QuotaResumeError):
                q.verify_resume({**dispatch, "stage": 1}, now=self.clock)
            with self.assertRaises(q.QuotaResumeError):
                q.verify_resume({**dispatch, "claim_comment": 77}, now=self.clock)

    def test_attested_first_stage_resume_does_not_launch_second(self):
        paused = {**self.pause, "stage": 1}
        claimed = {**self.claim, "stage": 1}
        rows = [self.comment(q.PAUSE, paused, 77),
                self.comment(q.CLAIM, claimed, 78)]

        def api(method, path, payload=None):
            if path == "/issues/154":
                return self.owner_issue
            if path.startswith("/issues/154/comments?"):
                return rows
            if path == "/actions/runs/42":
                return {"id": 42, "name": "Agent switch (Owner GitHub order)",
                        "status": "completed", "conclusion": "failure"}
            raise AssertionError(path)

        with patch.object(q, "_api", side_effect=api):
            order, source = q.verify_resume({
                "source_issue": 154, "stage": 1, "paused_run": 42,
                "attempt": 1, "claim_comment": 78,
            }, now=self.clock)
        self.assertEqual(source, 154)
        self.assertEqual([t["id"] for t in order["tasks"]], ["first", "second"])
        stages = agent_switch.workflow_values(order, "1")
        self.assertEqual((stages["run_stage_1"], stages["run_stage_2"]),
                         ("true", "false"))

    def test_success_run_or_bot_forgery_never_authorizes_retry(self):
        rows = [self.comment(q.PAUSE, self.pause, 77),
                self.comment(q.CLAIM, self.claim, 78, user=q.OWNER)]
        def api(method, path, payload=None):
            if path == "/issues/154":
                return self.owner_issue
            if path.startswith("/issues/154/comments?"):
                return rows
            if path == "/actions/runs/42":
                return {"id": 42, "name": "Agent switch (Owner GitHub order)",
                        "status": "completed", "conclusion": "success"}
            raise AssertionError(path)
        dispatch = {"source_issue": 154, "stage": 2, "paused_run": 42,
                    "attempt": 1, "claim_comment": 78}
        with patch.object(q, "_api", side_effect=api):
            with self.assertRaises(q.QuotaResumeError):
                q.verify_resume(dispatch, now=self.clock)
            rows[1]["user"]["login"] = q.BOT
            with self.assertRaises(q.QuotaResumeError):
                q.verify_resume(dispatch, now=self.clock)

    def test_verified_ready_second_serial_stage_not_confused_with_quota_failure(self):
        marker = {**self.pause, "attempt": 0, "preceding_status": "PR_STAGED"}
        rows = [self.comment(q.READY, marker, 77),
                self.comment(q.CLAIM, self.claim, 78)]
        def api(method, path, payload=None):
            if path == "/issues/154":
                return self.owner_issue
            if path.startswith("/issues/154/comments?"):
                return rows
            if path == "/actions/runs/42":
                return {"id": 42, "name": "Agent switch (Owner GitHub order)",
                        "status": "completed", "conclusion": "success"}
            raise AssertionError(path)
        with patch.object(q, "_api", side_effect=api):
            order, source = q.verify_resume({
                "source_issue": 154, "stage": 2, "paused_run": 42,
                "attempt": 1, "claim_comment": 78}, now=self.clock)
        self.assertEqual(source, 154)
        self.assertEqual([t["id"] for t in order["tasks"]], ["first", "second"])
        flags = agent_switch.workflow_values(order, "2")
        self.assertEqual((flags["run_stage_1"], flags["run_stage_2"]),
                         ("false", "true"))

    def test_unmerged_dependent_first_pr_never_enables_next_stage(self):
        blocked = json.loads(self.manifest)
        blocked.pop("serial_independent")
        self.owner_issue["body"] = json.dumps(blocked)
        report = Path(self.tmp.name) / "result.json"
        report.write_text(json.dumps({
            "repository": "martaxi-boss/Project-leader-codex",
            "status": "PR_STAGED"}))
        with patch.object(q, "_api", return_value=self.owner_issue) as api:
            self.assertFalse(q.ready_after_first_serial_stage(154, 99, report))
            self.assertEqual(api.call_count, 1)
        report.write_text(json.dumps({
            "repository": "martaxi-boss/Project-leader-codex",
            "status": "MERGED"}))
        writes = []
        def api(method, path, payload=None):
            if method == "GET" and path == "/issues/154":
                return self.owner_issue
            if method == "GET" and path.startswith("/issues/154/comments?"):
                return []
            if method == "POST":
                writes.append((path, payload))
                return {"id": 88}
            raise AssertionError(path)
        with patch.object(q, "_api", side_effect=api):
            self.assertTrue(q.ready_after_first_serial_stage(
                154, 99, report, now=self.clock))
        self.assertTrue(any(p == "/issues/154/comments" for p, _ in writes))
        self.assertTrue(any(p == "/issues/154/labels" for p, _ in writes))

    def test_editing_original_owner_manifest_blocks_prior_quota_checkpoint(self):
        rows = [self.comment(q.PAUSE, self.pause),
                self.comment(q.CLAIM, self.claim, 78)]
        changed = json.loads(self.manifest)
        changed["tasks"][1]["task"] = "Implement a different task after the edit"
        self.owner_issue["body"] = json.dumps(changed)
        def api(method, path, payload=None):
            if path == "/issues/154":
                return self.owner_issue
            if path.startswith("/issues/154/comments?"):
                return rows
            raise AssertionError(path)
        payload = {"source_issue": 154, "stage": 2, "paused_run": 42,
                   "attempt": 1, "claim_comment": 78}
        with patch.object(q, "_api", side_effect=api):
            with self.assertRaises(q.QuotaResumeError):
                q.verify_resume(payload, now=self.clock)

    def test_ambiguous_dispatch_expires_without_replaying_started_claim(self):
        old = {**self.claim, "claimed_at": self.clock - 5401}
        rows = [self.comment(q.PAUSE, self.pause),
                self.comment(q.CLAIM, old, 78)]
        self.assertEqual(len(q.due_pauses(rows, now=self.clock)), 1)
        rows.append(self.comment(q.STARTED, {
            "source_issue": 154, "stage": 2, "run_id": 42,
            "attempt": 1, "claim_comment": 78}, 79))
        self.assertEqual(q.due_pauses(rows, now=self.clock), [])
        rows.pop()
        rows.append(self.comment(q.CLAIM, {**old, "attempt": 1,
                                           "claimed_at": self.clock}, 80))
        self.assertEqual(q.due_pauses(rows, now=self.clock), [])
        def api(method, path, payload=None):
            if path == "/issues/154":
                return self.owner_issue
            if path.startswith("/issues/154/comments?"):
                return rows
            raise AssertionError(path)
        with patch.object(q, "_api", side_effect=api):
            with self.assertRaises(q.QuotaResumeError):
                q.verify_resume({"source_issue": 154, "stage": 2,
                                 "paused_run": 42, "attempt": 1,
                                 "claim_comment": 78}, now=self.clock)

    def test_replay_of_persisted_checkpoint_repairs_missing_label(self):
        previous = self.comment(q.PAUSE, self.pause)
        calls = []
        def api(method, path, payload=None):
            calls.append((method, path))
            if path == "/issues/154":
                return self.owner_issue
            if path.startswith("/issues/154/comments?"):
                return [previous]
            if method == "POST" and path in ("/labels", "/issues/154/labels"):
                return {}
            raise AssertionError((method, path))
        with patch.object(q, "_api", side_effect=api):
            report = q.pause_owner_issue(154, 2, 42, 0, now=self.clock - 7201)
        self.assertEqual(report["order_digest"], self.pause["order_digest"])
        self.assertNotIn(("POST", "/issues/154/comments"), calls)
        self.assertIn(("POST", "/issues/154/labels"), calls)

    def test_verified_dispatch_records_pre_model_start_lease(self):
        rows = [self.comment(q.PAUSE, self.pause, 77),
                self.comment(q.CLAIM, self.claim, 78)]
        posted = []
        def api(method, path, payload=None):
            if path == "/issues/154":
                return self.owner_issue
            if path.startswith("/issues/154/comments?"):
                return rows
            if path == "/actions/runs/42":
                return {"id": 42, "name": "Agent switch (Owner GitHub order)",
                        "status": "completed", "conclusion": "failure"}
            if method == "POST" and path == "/issues/154/comments":
                posted.append(payload["body"])
                return {"id": 79}
            raise AssertionError((method, path))
        payload = {"source_issue": 154, "stage": 2, "paused_run": 42,
                   "attempt": 1, "claim_comment": 78}
        with patch.object(q, "_api", side_effect=api):
            with patch.object(q.time, "time", return_value=self.clock):
                q.record_start(payload)
        self.assertEqual(len(posted), 1)
        self.assertTrue(posted[0].startswith(q.STARTED + "\n"))

    def test_legacy_pause_and_ready_cli_cannot_mutate_or_resume(self):
        for obsolete in (["quota", "pause", "154", "2", "42", "0"],
                         ["quota", "ready", "154", "42", "/tmp/report.json"]):
            with self.subTest(entrypoint=obsolete[1]):
                with patch.object(q, "_api") as gh, patch.object(q, "pause_owner_issue") as pause, patch.object(q, "ready_after_first_serial_stage") as ready:
                    self.assertEqual(q.main(obsolete), 3)
                    gh.assert_not_called()
                    pause.assert_not_called()
                    ready.assert_not_called()
        self.assertEqual(q.main(["quota", "scan"]), 0)

    def test_legacy_scan_is_harmless_and_never_calls_dispatch(self):
        with patch.object(q, "schedule_due") as schedule, patch.object(q, "_api") as api:
            self.assertEqual(q.main(["ops/codex_quota_resume.py", "scan"]), 0)
            schedule.assert_not_called()
            api.assert_not_called()
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/codex-quota-watch.yml").read_text()
        self.assertNotIn("python3 ops/codex_quota_resume.py scan", workflow)
        self.assertIn("ops.codex_quota_supervisor notify", workflow)
        self.assertIn("ops/codex_account_limits.py", workflow)
        self.assertIn("ref: " + "$" + "{{ github.event.repository.default_branch }}", workflow)
        self.assertNotIn("\\" + "$" + "{{", workflow)

    def test_legacy_scheduler_with_due_checkpoint_cannot_dispatch(self):
        # Even a valid overdue checkpoint cannot silently create a worker.
        rows = [self.comment(q.PAUSE, self.pause, 77)]
        self.assertEqual(len(q.due_pauses(rows, now=self.clock)), 1)
        with patch.object(q, "_api") as api:
            with self.assertRaisesRegex(q.QuotaResumeError, "OWNER_ONLY"):
                q.schedule_due(now=self.clock)
            api.assert_not_called()



    def test_owner_only_coordinator_stage_hold_writes_one_durable_record(self):
        issue = {"number": 181, "state": "open",
                 "title": "[coordinator run] Original Owner plan",
                 "body": "The immutable plan with 2 workers",
                 "user": {"login": q.OWNER}}
        run = {"id": 564, "name": "Coordinator to existing Codex router (Owner order)",
               "status": "in_progress", "repository": {"full_name": q.REPO}}
        posted = []
        def api(method, path, payload=None):
            if method == "GET" and path == "/issues/181":
                return issue
            if method == "GET" and path == "/actions/runs/564":
                return run
            if method == "GET" and path.startswith("/issues/181/comments?"):
                return []
            if method == "POST" and path == "/issues/181/comments":
                posted.append(payload["body"])
                return {"id": 98}
            if method == "POST" and path in ("/labels", "/issues/181/labels"):
                return {"id": 1}
            raise AssertionError((method, path))
        with patch.object(q, "_api", side_effect=api):
            meta = q.owner_only_hold(181, "p2-1", 564, "564-1-p2-1")
        self.assertEqual(meta["resumption"], "REQUIRES_NEW_OWNER_ORDER")
        self.assertEqual(meta["worker"], "p2-1")
        self.assertEqual(meta["run_id"], 564)
        self.assertEqual(meta["workspace_key"], "564-1-p2-1")
        self.assertEqual(len(posted), 1)
        self.assertIn(q.HOLD_V2, posted[0])
        self.assertNotIn("The immutable plan", posted[0])
        self.assertNotIn("/dispatches", posted[0])

    def test_owner_only_hold_rejects_unverified_issue_and_worker(self):
        issue = {"number": 181, "state": "open",
                 "title": "[coordinator run] Wrong owner", "body": "text",
                 "user": {"login": "untrusted"}}
        with patch.object(q, "_api", return_value=issue) as api:
            with self.assertRaises(q.QuotaResumeError):
                q.owner_only_hold(181, "p2-1", 564, "564-1-p2-1")
            self.assertEqual(api.call_count, 1)
        with patch.object(q, "_api") as api:
            with self.assertRaises(q.QuotaResumeError):
                q.owner_only_hold(181, "INVALID/WORKER", 564, "564-1-p2-1")
            api.assert_not_called()

    def test_owner_hold_cannot_reference_other_run_or_untrusted_vps_folder(self):
        with patch.object(q, "_api") as api:
            for job in ("555-1-p2-1", "564-1-p2-2",
                        "564-1-p2-1/../../secrets", "564-0-p2-1",
                        "564-1", ""):
                with self.subTest(job=job), self.assertRaises(q.QuotaResumeError):
                    q.owner_only_hold(181, "p2-1", 564, job)
            api.assert_not_called()

    def test_quota_checkpoint_can_read_actual_github_actions_run(self):
        flow = (Path(__file__).resolve().parents[2] /
                ".github/workflows/codex-autonomous.yml").read_text()
        worker = flow.split("  execute:", 1)[1].split("    steps:", 1)[0]
        self.assertIn("      actions: read", worker)
        self.assertIn("      issues: write", worker)
        self.assertIn("      contents: read", worker)
        self.assertNotIn("      actions: write", worker)


    def test_quota_safe_hold_happens_before_private_owner_notice(self):
        root = Path(__file__).resolve().parents[2]
        flow = (root / ".github/workflows/codex-autonomous.yml").read_text()
        stored = flow.index("Secure provider quota checkpoint before Supervisor delivery")
        notice = flow.index("Passive Supervisor sends final publication state")
        self.assertLess(stored, notice)
        self.assertIn("codex_quota_resume.py hold", flow)
        self.assertNotIn("Persist provider quota checkpoint (Owner Issue)", flow)
        remote = (root / "ops/codex-autonomous-remote.sh").read_text()
        quota = remote.index('codex_account_limits.py" read')
        paid = remote.index('exec --model gpt-5.6-sol')
        self.assertLess(quota, paid)
        self.assertIn('quota_status="UNKNOWN"', remote)
        self.assertIn('no artificial reserve', remote)
        self.assertIn('codex_quota_workspace.py" secure', remote)
        self.assertNotIn('CODEX_QUOTA_UNVERIFIED=SAFE_HOLD', remote)
        self.assertIn('CODEX_QUOTA_BLOCKED', remote)
        self.assertNotIn("scheduled retry", remote)



if __name__ == "__main__":
    unittest.main()
