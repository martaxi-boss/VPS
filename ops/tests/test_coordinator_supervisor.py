"""Offline acceptance tests for independent Project Leader terminal supervisor."""
from __future__ import annotations

import re
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from ops import coordinator_supervisor as sup

ROOT = Path(__file__).resolve().parents[2]
BASE = "a" * 40
SHA = "b" * 40
MERGE = "c" * 40
CANONICAL = "d" * 40
ISSUE = 188
RUN = 40102002
NUMBER = 19
REF = f"codex/issue-{ISSUE}-{RUN}-1"
URL = f"https://github.com/martaxi-boss/Project-leader-codex/pull/{NUMBER}"


def candidate():
    return sup.Worker("PR_STAGED", URL, SHA)


def fixture():
    calls = []
    reviewed = []
    merged = []
    state = {"main": BASE, "owner": "martaxi-boss", "file": "README_CODEX.md",
             "ci": "success", "target_sha": SHA, "changed": False}

    def api(method, route, data=None, *, control=False):
        calls.append((method, route, control))
        if method == "GET" and route == f"repos/{sup.CONTROL}/issues/{ISSUE}":
            return {
                "number": ISSUE, "state": "open", "title": "[coordinator run] Docs",
                "user": {"login": state["owner"]},
                "body": f"TARGET_REPOSITORY={sup.TARGET}\n\nAudit and correct docs",
            }
        if method == "GET" and route == f"repos/{sup.SOURCE}/git/ref/heads/main":
            return {"object": {"sha": CANONICAL}}
        if method == "GET" and route == f"repos/{sup.TARGET}/git/ref/heads/main":
            return {"object": {"sha": state["main"]}}
        if method == "GET" and route == f"repos/{sup.TARGET}/pulls/{NUMBER}":
            return {
                "state": "open", "draft": False, "merged": False, "mergeable": True,
                "user": {"login": "martaxi-boss"},
                "head": {"sha": state["target_sha"], "ref": REF,
                         "repo": {"full_name": sup.TARGET}},
                "base": {"ref": "main", "sha": state["main"]},
                "body": (
                    f"Autonomous Codex change from {sup.CONTROL} issue #{ISSUE}.\n"
                    f"Remote isolated Codex clone base: {chr(96)}{BASE}{chr(96)}.\n"
                    f"Trusted publisher commit: {chr(96)}{SHA}{chr(96)}.\n"
                    "No GitHub write credential was provided to Codex."
                ),
            }
        if method == "GET" and route == f"repos/{sup.TARGET}/pulls/{NUMBER}/files?per_page=100":
            return [{"filename": state["file"], "status": "modified",
                     "additions": 2, "deletions": 1}]
        if method == "GET" and route.startswith(f"repos/{sup.TARGET}/actions/runs?"):
            return {"workflow_runs": [
                {"name": name, "event": event, "head_sha": SHA,
                 "head_branch": REF, "status": "completed",
                 "conclusion": state["ci"], "created_at": "2026-10-13T15:00:00Z"}
                for name, event in sup.REQUIRED
            ]}
        if method == "POST" and route == f"repos/{sup.TARGET}/pulls/{NUMBER}/reviews":
            reviewed.append(data)
            return {"id": 1}
        if method == "PUT" and route == f"repos/{sup.TARGET}/pulls/{NUMBER}/merge":
            merged.append(data)
            state["main"] = MERGE
            return {"sha": MERGE, "merged": True}
        raise AssertionError(f"Unexpected route: {method} {route}")
    return api, calls, reviewed, merged, state


class SupervisorAcceptanceTests(TestCase):
    def test_real_provenance_exact_ci_docs_and_transition(self):
        api, calls, reviews, merges, state = fixture()
        with patch.object(sup, "_api", side_effect=api):
            done = sup.assess(ISSUE, RUN, [candidate()], 1, CANONICAL)
        self.assertEqual(done["status"], "TERMINAL_SUCCESS")
        self.assertEqual(done["merge_sha"], MERGE)
        self.assertEqual(state["main"], MERGE)
        self.assertEqual(merges[0], {"sha": SHA, "merge_method": "merge",
                                    "commit_title": f"Project Leader validated Codex PR #{NUMBER}"})
        self.assertEqual(len(reviews), 1)
        self.assertIn(SHA, reviews[0]["body"])
        self.assertIn(CANONICAL, reviews[0]["body"])
        self.assertNotIn("openai_base_url", str(reviews))

    def test_dependent_phases_hold_for_new_audit_after_approved_merge(self):
        api, _, _, merges, _ = fixture()
        with patch.object(sup, "_api", side_effect=api):
            done = sup.assess(ISSUE, RUN, [candidate()], 3, CANONICAL)
        self.assertEqual(done["status"], "PHASE_VALIDATED_PENDING_REAUDIT")
        self.assertEqual(len(merges), 1)

    def test_non_owner_is_rejected_before_accessing_target(self):
        api, calls, _, merges, state = fixture()
        state["owner"] = "outsider"
        with patch.object(sup, "_api", side_effect=api):
            with self.assertRaisesRegex(sup.SupervisorHold, "OWNER_AUTHORITY_UNVERIFIED"):
                sup.assess(ISSUE, RUN, [candidate()], 1, CANONICAL)
        self.assertEqual(len(calls), 1)
        self.assertEqual(merges, [])

    def test_protected_or_oversized_change_never_merges(self):
        for filename in (".github/workflows/ci.yml", "../private.md",
                         ".codex/config.toml", "README.md", "docs/../abc.md"):
            with self.subTest(filename=filename):
                api, _, reviews, merges, state = fixture()
                state["file"] = filename
                with patch.object(sup, "_api", side_effect=api):
                    with self.assertRaisesRegex(sup.SupervisorHold, "DIFF_OUTSIDE_SAFE_DOC_SCOPE"):
                        sup.assess(ISSUE, RUN, [candidate()], 1, CANONICAL)
                self.assertEqual(reviews, [])
                self.assertEqual(merges, [])

    def test_failed_or_unfinished_ci_cannot_merge(self):
        for status in ("failure", "cancelled", "neutral"):
            api, _, reviews, merges, state = fixture()
            state["ci"] = status
            with patch.object(sup, "_api", side_effect=api):
                with self.assertRaisesRegex(sup.SupervisorHold, "CI_NOT_GREEN"):
                    sup.assess(ISSUE, RUN, [candidate()], 1, CANONICAL)
            self.assertFalse(reviews)
            self.assertFalse(merges)

    def test_unverified_worker_head_and_stale_canonical_do_not_merge(self):
        api, _, reviews, merges, state = fixture()
        state["target_sha"] = "e" * 40
        with patch.object(sup, "_api", side_effect=api):
            with self.assertRaisesRegex(sup.SupervisorHold, "PR_UNVERIFIED"):
                sup.assess(ISSUE, RUN, [candidate()], 1, CANONICAL)
        self.assertFalse(reviews)
        self.assertFalse(merges)
        with patch.object(sup, "_api", side_effect=api):
            with self.assertRaisesRegex(sup.SupervisorHold, "CANONICAL_STALE"):
                sup.assess(ISSUE, RUN, [candidate()], 1, "f" * 40)

    def test_disallowed_worker_status_and_malformed_pr_are_refused(self):
        for x in (
            sup.Worker("NO_CHANGE", URL, SHA),
            sup.Worker("PR_STAGED", "http://evil.test/pull/19", SHA),
            sup.Worker("PR_STAGED", URL, "xyz"),
        ):
            api, _, _, merges, _ = fixture()
            with patch.object(sup, "_api", side_effect=api):
                with self.assertRaises(sup.SupervisorHold):
                    sup.assess(ISSUE, RUN, [x], 1, CANONICAL)
            self.assertFalse(merges)

    def test_two_workers_are_held_instead_of_merging_stale_sibling(self):
        api, _, reviews, merges, _ = fixture()
        second = sup.Worker("PR_STAGED",
                            f"https://github.com/{sup.TARGET}/pull/20", SHA)
        with patch.object(sup, "_api", side_effect=api):
            with self.assertRaises(sup.SupervisorHold):
                sup.assess(ISSUE, RUN, [candidate(), second], 1, CANONICAL)
        self.assertFalse(reviews)
        self.assertFalse(merges)

    def test_only_authenticated_owner_event_may_use_supervisor_secret(self):
        workflow = (ROOT / ".github/workflows/coordinator-owner-order.yml").read_text()
        supervisor = workflow.split("  supervise:", 1)[1]
        self.assertIn("github.event.issue.user.login == github.repository_owner", supervisor)
        self.assertIn("github.event_name == 'issues'", supervisor)
        self.assertIn("needs.dispatch.result == 'success'", supervisor)
        self.assertIn("CODEX_GITHUB_TOKEN: ${{ secrets.CODEX_GITHUB_TOKEN }}", supervisor)
        self.assertIn("uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", supervisor)
        offline = workflow.split("  offline-contract:", 1)[1].split("  plan:", 1)[0]
        self.assertNotIn("secrets.", offline)
        self.assertNotIn("CODEX_GITHUB_TOKEN", offline)
        router = (ROOT / ".github/workflows/agent-switch.yml").read_text()
        executor = (ROOT / ".github/workflows/codex-autonomous.yml").read_text()
        self.assertIn("value: ${{ jobs.preflight.outputs.task_count }}", router)
        self.assertIn("worker_1_canonical_sha:", router)
        self.assertIn("publication_canonical_sha:", executor)
        self.assertIn("project-leader-runtime.json", executor)
        self.assertIn("worker_2_canonical_sha:", router)

    def test_supervisor_is_not_a_second_ai_coordinator(self):
        source = (ROOT / "ops/coordinator_supervisor.py").read_text()
        self.assertNotIn("codex exec", source)
        self.assertNotIn("model_reasoning_effort", source)
        self.assertNotIn("project-leader-bootstrap.py", source)
        self.assertNotIn("sshpass -e", source)
        self.assertTrue(sup._safe_doc("docs/guide.md"))
        self.assertFalse(sup._safe_doc("docs/guide.py"))


if __name__ == "__main__":
    import unittest
    unittest.main()
