"""Offline security and lifecycle tests; never start models or GitHub writes."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from ops import coordinator_phase_resume as phase

ROOT = Path(__file__).resolve().parents[2]
ISSUE = 188
ISSUE_ID = 31001991
PREVIOUS_RUN = 38410012
SHA = "a" * 40
ORDER = "TARGET_REPOSITORY=martaxi-boss/Project-leader-codex\n\nCorrect only audited docs safely"


def signed_record():
    return {
        "version": 1, "source_issue": ISSUE,
        "previous_run": PREVIOUS_RUN, "next_phase": 2, "total_phases": 3,
        "expected_sha": SHA,
        "owner_digest": hashlib.sha256(ORDER.encode()).hexdigest(),
    }


def mock_api():
    calls = []
    writes = []
    records = []
    state = {"owner": "martaxi-boss", "status": "completed",
             "conclusion": "success", "head": SHA,
             "body": ORDER, "comment_user": phase.BOT}
    marker = phase._marker(phase.READY, signed_record())

    def api(method, route, payload=None):
        calls.append((method, route))
        if method == "GET" and route == f"/issues/{ISSUE}":
            return {"number": ISSUE, "id": ISSUE_ID, "state": "open",
                    "user": {"login": state["owner"]},
                    "title": "[coordinator run] Continue correct docs",
                    "body": state["body"]}
        if method == "GET" and route == "/issues/comments/701":
            return {"id": 701, "user": {"login": state["comment_user"]},
                    "issue_url": phase.API + f"/issues/{ISSUE}",
                    "body": marker}
        if method == "GET" and route == f"/actions/runs/{PREVIOUS_RUN}":
            return {"id": PREVIOUS_RUN, "name": phase.RUN_NAME,
                    "event": "issues", "status": state["status"],
                    "conclusion": state["conclusion"],
                    "repository": {"full_name": phase.CONTROL}}
        if method == "GET" and route.startswith(f"/issues/{ISSUE}/comments?"):
            return records.copy()
        if method == "POST" and route == f"/issues/{ISSUE}/comments":
            writes.append((route, payload))
            result_id = 701 if payload["body"].startswith(phase.READY) else 702
            if result_id == 702:
                records.append({
                    "id": result_id, "user": {"login": phase.BOT},
                    "body": payload["body"],
                })
            return {"id": result_id}
        if method == "POST" and route == "/dispatches":
            writes.append((route, payload))
            return {}
        raise AssertionError(f"unexpected operation {method} {route}")
    return api, calls, writes, records, state


class CoordinatorPhaseReplayTests(TestCase):
    def test_verified_second_phase_is_owner_bound_and_single_use(self):
        api, calls, writes, records, state = mock_api()
        data = {**signed_record(), "checkpoint_comment": 701}
        with patch.object(phase, "_api", side_effect=api), patch.object(
                phase, "_main", return_value=SHA):
            result = phase.verify_dispatch(data)
            self.assertEqual(result["issue_number"], ISSUE)
            self.assertEqual(result["issue_id"], ISSUE_ID)
            self.assertEqual(result["phase_index"], 2)
            self.assertEqual(result["max_phases"], 3)
            self.assertEqual(base64.b64decode(
                result["owner_order_b64"]).decode(), ORDER)
            self.assertEqual(len(writes), 1)
            self.assertTrue(writes[0][1]["body"].startswith(phase.STARTED))
            with self.assertRaisesRegex(
                    phase.PhaseHold, "CONTINUATION_ALREADY_STARTED"):
                phase.verify_dispatch(data)

    def test_owner_changed_and_fake_bot_are_refused_before_model(self):
        for field, value, code in [
            ("owner", "intruder", "OWNER_ISSUE_UNVERIFIED"),
            ("body", ORDER + "\nNew instruction", "OWNER_ORDER_CHANGED"),
            ("comment_user", "intruder", "BOT_CHECKPOINT_UNVERIFIED"),
        ]:
            with self.subTest(field=field):
                api, _, writes, _, state = mock_api()
                state[field] = value
                with patch.object(phase, "_api", side_effect=api), patch.object(
                        phase, "_main", return_value=SHA):
                    with self.assertRaisesRegex(phase.PhaseHold, code):
                        phase.verify_dispatch({
                            **signed_record(), "checkpoint_comment": 701})
                self.assertEqual(writes, [])

    def test_changed_git_head_and_failed_previous_run_block_resume(self):
        for fault in ("head", "conclusion"):
            api, _, writes, _, state = mock_api()
            if fault == "head":
                current = "b" * 40
            else:
                state["conclusion"] = "failure"
                current = SHA
            with patch.object(phase, "_api", side_effect=api), patch.object(
                    phase, "_main", return_value=current):
                with self.assertRaisesRegex(
                        phase.PhaseHold,
                        "TARGET_MAIN_DRIFT" if fault == "head" else
                        "PREVIOUS_RUN_NOT_CERTIFIED"):
                    phase.verify_dispatch({
                        **signed_record(), "checkpoint_comment": 701})
            self.assertEqual(writes, [])

    def test_spoofed_broken_or_overlimit_payload_does_nothing(self):
        wrong = [
            {},
            {**signed_record(), "checkpoint_comment": "701"},
            {**signed_record(), "checkpoint_comment": 701, "next_phase": 9},
            {**signed_record(), "checkpoint_comment": 701, "next_phase": 1},
            {**signed_record(), "checkpoint_comment": 701, "total_phases": 1},
            {**signed_record(), "checkpoint_comment": 701, "expected_sha": "x"},
            {**signed_record(), "checkpoint_comment": 701, "surprise": "overwrite"},
        ]
        for payload in wrong:
            api, calls, writes, _, _ = mock_api()
            with self.subTest(payload=str(payload)[:35]), patch.object(
                    phase, "_api", side_effect=api), patch.object(
                    phase, "_main", return_value=SHA), self.assertRaises(phase.PhaseHold):
                phase.verify_dispatch(payload)
            self.assertFalse(writes)

    def test_emitter_posts_durable_checkpoint_before_single_dispatch(self):
        api, calls, writes, _, state = mock_api()
        with patch.object(phase, "_api", side_effect=api), patch.object(
                phase, "_main", return_value=SHA):
            self.assertEqual(phase.request_next(ISSUE, PREVIOUS_RUN, 1, 3, SHA), 701)
        self.assertEqual([route for route, _ in writes],
                         [f"/issues/{ISSUE}/comments", "/dispatches"])
        posted = writes[1][1]["client_payload"]
        self.assertEqual(posted["checkpoint_comment"], 701)
        self.assertEqual(posted["next_phase"], 2)
        self.assertEqual(writes[1][1]["event_type"], phase.EVENT)
        self.assertIn(phase.READY, writes[0][1]["body"])
        self.assertNotIn(ORDER, writes[0][1]["body"])

    def test_emitter_rejects_terminal_or_stale_head_without_side_effect(self):
        for current, maximum, expected in [
            (3, 3, SHA), (1, 9, SHA), (1, 3, "b"*40),
        ]:
            api, _, writes, _, _ = mock_api()
            with patch.object(phase, "_api", side_effect=api), patch.object(
                    phase, "_main", return_value=SHA), self.assertRaises(
                    phase.PhaseHold):
                phase.request_next(ISSUE, PREVIOUS_RUN, current, maximum, expected)
            self.assertFalse(writes)

    def test_workflows_fail_closed_without_owner_event_or_model_in_pr(self):
        gateway = (ROOT / ".github/workflows/coordinator-owner-order.yml").read_text()
        router = (ROOT / ".github/workflows/agent-switch.yml").read_text()
        worker = (ROOT / ".github/workflows/codex-autonomous.yml").read_text()
        supervisor = (ROOT / "ops/coordinator_supervisor.py").read_text()
        self.assertIn("types: [coordinator_next_phase]", gateway)
        self.assertIn("resume.verify_dispatch(", gateway)
        self.assertIn("needs.plan.outputs.owner_order_b64", gateway)
        self.assertIn("coordinator_owner_order_b64:", router)
        self.assertIn("inputs.issue_number == github.event.client_payload.source_issue", worker)
        self.assertIn("continuation.request_next(", supervisor)
        self.assertIn("if: github.event_name == 'pull_request'", gateway)
        offline = gateway.split("  offline-contract:", 1)[1].split("  plan:", 1)[0]
        self.assertNotIn("secrets.", offline)
        self.assertIn("github.event.issue.user.login == github.repository_owner", gateway)
        self.assertIn("group: coordinator-issue-", gateway)

    def test_supervisor_rejects_attempt_to_expand_original_phase_limit(self):
        from ops import coordinator_supervisor as sup
        # This gate rejects phase scope expansion BEFORE reading any PR.
        with patch.object(sup, "_api") as api:
            with self.assertRaisesRegex(sup.SupervisorHold, "PHASE_BOUNDARY_EXCEEDED"):
                sup.assess(ISSUE, PREVIOUS_RUN,
                           [sup.Worker("PR_STAGED", "https://x", SHA)],
                           3, SHA, current_phase=2, max_phases=3)
            api.assert_not_called()


if __name__ == "__main__":
    import unittest
    unittest.main()
