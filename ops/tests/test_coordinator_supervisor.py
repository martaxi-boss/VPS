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
SECOND = "f" * 40
UPDATED = "e" * 40
SECOND_MERGE = "9" * 40
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
             "ci": "success", "target_sha": SHA, "changed": False,
             "updated": False, "updated_parents_valid": True,
             "second_ci": "success", "updated_ci": "success",
             "second_file": "docs/second.md", "checks_seen": 0}

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
        if method == "GET" and route in (
                f"repos/{sup.TARGET}/pulls/{NUMBER}",
                f"repos/{sup.TARGET}/pulls/{NUMBER+1}"):
            second = route.endswith("/" + str(NUMBER+1))
            actual_sha = (UPDATED if state["updated"] else SECOND) if second else state["target_sha"]
            actual_ref = REF+"-2" if second else REF
            publisher_sha = SECOND if second else SHA
            return {
                "state": "open", "draft": False, "merged": False, "mergeable": True,
                "user": {"login": "martaxi-boss"},
                "head": {"sha": actual_sha, "ref": actual_ref,
                         "repo": {"full_name": sup.TARGET}},
                "base": {"ref": "main", "sha": state["main"]},
                "body": (
                    f"Autonomous Codex change from {sup.CONTROL} issue #{ISSUE}.\n"
                    f"Remote isolated Codex clone base: {chr(96)}{BASE}{chr(96)}.\n"
                    f"Trusted publisher commit: {chr(96)}{publisher_sha}{chr(96)}.\n"
                    "No GitHub write credential was provided to Codex."
                ),
            }
        if method == "GET" and route in (
                f"repos/{sup.TARGET}/pulls/{NUMBER}/files?per_page=100",
                f"repos/{sup.TARGET}/pulls/{NUMBER+1}/files?per_page=100"):
            filename = (state["second_file"] if "/pulls/20/" in route
                        else state["file"])
            return [{"filename": filename, "status": "modified",
                     "additions": 2, "deletions": 1}]
        if method == "GET" and route.startswith(f"repos/{sup.TARGET}/actions/runs?"):
            from urllib.parse import parse_qs, urlparse
            commit = parse_qs(urlparse(route).query)["head_sha"][0]
            if commit == UPDATED:
                selected = state["updated_ci"]
                state["checks_seen"] += 1
                if selected == "pending_then_success":
                    selected = "in_progress" if state["checks_seen"] == 1 else "success"
                branch, status = REF+"-2", selected
            elif commit == SECOND:
                branch, status = REF+"-2", state["second_ci"]
            else:
                branch, status = REF, state["ci"]
            conclusion = status if status != "in_progress" else None
            return {"workflow_runs": [
                {"name": name, "event": event, "head_sha": commit,
                 "head_branch": branch,
                 "status": "in_progress" if status == "in_progress" else "completed",
                 "conclusion": conclusion, "created_at": "2026-10-13T15:00:00Z"}
                for name, event in sup.REQUIRED
            ]}
        if method == "GET" and route == f"repos/{sup.TARGET}/git/commits/{UPDATED}":
            parents = [SECOND, MERGE] if state["updated_parents_valid"] else [SECOND, BASE]
            return {"parents": [{"sha": sha} for sha in parents]}
        if method == "POST" and route in (
                f"repos/{sup.TARGET}/pulls/{NUMBER}/reviews",
                f"repos/{sup.TARGET}/pulls/{NUMBER+1}/reviews"):
            reviewed.append(data)
            return {"id": 1}
        if method == "POST" and route == f"repos/{sup.CONTROL}/issues/{ISSUE}/comments":
            return {"id": 100}
        if method == "PUT" and route == f"repos/{sup.TARGET}/pulls/{NUMBER+1}/update-branch":
            if data != {"expected_head_sha": SECOND}:
                raise AssertionError("Unexpected update-branch payload")
            state["updated"] = True
            return {"message": "scheduled"}
        if method == "PUT" and route in (
                f"repos/{sup.TARGET}/pulls/{NUMBER}/merge",
                f"repos/{sup.TARGET}/pulls/{NUMBER+1}/merge"):
            merged.append(data)
            new_sha = SECOND_MERGE if route.endswith(f"/{NUMBER+1}/merge") else MERGE
            state["main"] = new_sha
            return {"sha": new_sha, "merged": True}
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

    @staticmethod
    def second_worker():
        return sup.Worker(
            "PR_STAGED",
            f"https://github.com/{sup.TARGET}/pull/{NUMBER+1}", SECOND)

    def test_two_independent_workers_rebase_second_and_recheck_exact_ci(self):
        api, calls, reviews, merges, state = fixture()
        with patch.object(sup, "_api", side_effect=api):
            result = sup.assess(ISSUE, RUN,
                                [candidate(), self.second_worker()], 1, CANONICAL)
        self.assertEqual(result["status"], "TERMINAL_SUCCESS")
        self.assertEqual(result["pull_requests"], [NUMBER, NUMBER+1])
        self.assertEqual(result["merge_sha"], SECOND_MERGE)
        self.assertEqual(state["main"], SECOND_MERGE)
        self.assertEqual([m["sha"] for m in merges], [SHA, UPDATED])
        self.assertEqual(len(reviews), 2)
        paths = [route for method, route, _ in calls]
        self.assertIn(f"repos/{sup.TARGET}/pulls/{NUMBER+1}/update-branch", paths)
        self.assertIn(f"repos/{sup.TARGET}/git/commits/{UPDATED}", paths)
        self.assertTrue(any("head_sha=" + UPDATED in p for p in paths))
        self.assertTrue(any(m == "POST" and "issues" in p for m, p, _ in calls))

    def test_conflicting_parallel_files_hold_before_any_merge(self):
        api, _, reviews, merges, state = fixture()
        state["second_file"] = "README_CODEX.md"
        with patch.object(sup, "_api", side_effect=api):
            with self.assertRaisesRegex(sup.SupervisorHold, "PARALLEL_FILE_CONFLICT"):
                sup.assess(ISSUE, RUN, [candidate(), self.second_worker()], 1, CANONICAL)
        self.assertFalse(reviews)
        self.assertFalse(merges)

    def test_second_initial_ci_failure_blocks_entire_wave(self):
        api, _, reviews, merges, state = fixture()
        state["second_ci"] = "failure"
        with patch.object(sup, "_api", side_effect=api):
            with self.assertRaisesRegex(sup.SupervisorHold, "CI_NOT_GREEN"):
                sup.assess(ISSUE, RUN, [candidate(), self.second_worker()], 1, CANONICAL)
        self.assertFalse(reviews)
        self.assertFalse(merges)

    def test_unverified_git_update_ancestry_holds_after_durable_first_merge(self):
        api, calls, reviews, merges, state = fixture()
        state["updated_parents_valid"] = False
        with patch.object(sup, "_api", side_effect=api):
            with self.assertRaisesRegex(
                    sup.SupervisorHold, "UPDATED_BRANCH_ANCESTRY_UNVERIFIED"):
                sup.assess(ISSUE, RUN, [candidate(), self.second_worker()], 1, CANONICAL)
        self.assertEqual([m["sha"] for m in merges], [SHA])
        self.assertEqual(len(reviews), 1)
        self.assertIn(("POST", f"repos/{sup.CONTROL}/issues/{ISSUE}/comments", True), calls)

    def test_second_fresh_ci_failure_blocks_second_merge(self):
        api, _, reviews, merges, state = fixture()
        state["updated_ci"] = "failure"
        with patch.object(sup, "_api", side_effect=api):
            with self.assertRaisesRegex(sup.SupervisorHold, "CI_NOT_GREEN"):
                sup.assess(ISSUE, RUN, [candidate(), self.second_worker()], 1, CANONICAL)
        self.assertEqual([m["sha"] for m in merges], [SHA])
        self.assertEqual(len(reviews), 1)

    def test_updated_ci_waits_for_completion_but_not_unverified_green(self):
        api, _, _, merges, state = fixture()
        state["updated_ci"] = "pending_then_success"
        with patch.object(sup, "_api", side_effect=api), \
             patch.object(sup.time, "sleep", return_value=None):
            result = sup.assess(ISSUE, RUN,
                                [candidate(), self.second_worker()], 2, CANONICAL)
        self.assertEqual(result["status"], "PHASE_VALIDATED_PENDING_REAUDIT")
        self.assertGreaterEqual(state["checks_seen"], 2)
        self.assertEqual(len(merges), 2)

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
