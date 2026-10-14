"""Proof of general PR-only handoff: no target main merges or fake CI pass."""
from __future__ import annotations
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops import coordinator_pr_integrator as unit

TARGET = "martaxi-boss/pink-iptv"
ISSUE = 133
RUN = 38490000
PR = 71
SHA = "b" * 40
BASE = "a" * 40
CANONICAL = "c" * 40
REF = f"codex/issue-{ISSUE}-{RUN}-1"
URL = f"https://github.com/{TARGET}/pull/{PR}"


def worker():
    return unit.Worker("PR_STAGED", URL, SHA)


def stub(*, owner="martaxi-boss", pr_repo=TARGET, pr_sha=SHA,
         base=BASE, altered=False, issue_target=TARGET):
    calls = []
    def api(method, route, data=None, *, control=False):
        calls.append((method, route, data))
        if method == "GET" and route == f"repos/{unit.CONTROL}/issues/{ISSUE}":
            return {"number": ISSUE, "state": "open",
                    "title": "[coordinator run] PINK repair",
                    "user": {"login": owner},
                    "body": "TARGET_REPOSITORY=" + issue_target + "\n\nCorrige filmes"}
        if method == "GET" and route == f"repos/{unit.SOURCE}/git/ref/heads/main":
            return {"object": {"sha": CANONICAL}}
        if method == "GET" and route == f"repos/{TARGET}/git/ref/heads/main":
            return {"object": {"sha": BASE}}
        if method == "GET" and route == f"repos/{TARGET}/pulls/{PR}":
            return {
                "state": "open", "draft": False, "merged": False,
                "user": {"login": "martaxi-boss"},
                "head": {"sha": pr_sha, "ref": REF,
                         "repo": {"full_name": pr_repo}},
                "base": {"ref": "main", "sha": base},
                "body": (
                    f"Autonomous Codex change from {unit.CONTROL} issue #{ISSUE}.\n\n"
                    f"Remote isolated Codex clone base: `{BASE}`.\n"
                    f"Trusted publisher commit: `{SHA}`.\n"
                    "No GitHub write credential was provided to Codex."
                ),
            }
        if method == "GET" and route == f"repos/{TARGET}/pulls/{PR}/files?per_page=100":
            name = ".github/workflows/deploy.yml" if altered else "clients/extreme/prepare.py"
            return [{"filename": name, "status": "modified",
                     "additions": 1, "deletions": 0}]
        if method == "POST" and route == f"repos/{unit.CONTROL}/issues/{ISSUE}/comments":
            return {"id": 1}
        raise AssertionError("Unexpected API route: " + method + " " + route)
    return api, calls


class ExternalStageTests(unittest.TestCase):
    def test_pink_pr_stage_is_not_merged_or_certified(self):
        api, calls = stub()
        with patch.object(unit, "_api", side_effect=api):
            result = unit.assess_external_stage(
                ISSUE, RUN, [worker()], 2, CANONICAL, TARGET)
        self.assertEqual(result["status"], "PHASE_STAGED_AWAITING_TARGET_CERTIFICATION")
        self.assertIs(result["certified"], False)
        self.assertEqual(result["target_repository"], TARGET)
        self.assertEqual(result["pull_requests"], [PR])
        self.assertFalse(any(method == "PUT" for method, _, _ in calls))
        self.assertFalse(any("reviews" in route for _, route, _ in calls))

    def test_main_logs_staged_without_claiming_completed(self):
        api, calls = stub()
        values = {
            "OWNER_ISSUE": str(ISSUE), "OWNER_RUN": str(RUN),
            "WORKER_COUNT": "1", "PHASE_COUNT": "2",
            "PHASE_NUMBER": "1", "CANONICAL_SHA": CANONICAL,
            "WORKER_1_STATUS": "PR_STAGED",
            "WORKER_1_PR": URL, "WORKER_1_SHA": SHA,
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "phase.out"
            with patch.dict(os.environ, {**values, "GITHUB_OUTPUT": str(path)}):
                with patch.object(unit, "_api", side_effect=api):
                    self.assertEqual(unit.main(), 0)
            self.assertIn("PHASE_STAGED_AWAITING_TARGET_CERTIFICATION",
                          path.read_text())
        notices = [data for method, route, data in calls
                   if method == "POST" and route.endswith("/comments")]
        self.assertEqual(len(notices), 1)
        self.assertIn("No merge", notices[0]["body"])
        self.assertFalse(any(method in ("PUT", "PATCH") for method, _, _ in calls))

    def test_forged_identity_and_stale_sha_are_refused(self):
        for changes in (
                {"owner": "attacker"},
                {"pr_repo": "other-owner/pink-iptv"},
                {"pr_sha": "f" * 40},
                {"base": "f" * 40},
                {"issue_target": "martaxi-boss/VPS"}):
            with self.subTest(changes=changes):
                api, calls = stub(**changes)
                with patch.object(unit, "_api", side_effect=api):
                    with self.assertRaises(unit.IntegratorHold):
                        unit.assess_external_stage(
                            ISSUE, RUN, [worker()], 2, CANONICAL, TARGET)
                self.assertFalse(any(method in ("PUT", "PATCH") for method, _, _ in calls))

    def test_worker_cannot_inject_non_target_url(self):
        api, calls = stub()
        for url in ("https://github.com/other/pink-iptv/pull/71",
                    "http://github.com/" + TARGET + "/pull/71",
                    URL + "?foo=1"):
            with self.subTest(url=url), patch.object(unit, "_api", side_effect=api):
                with self.assertRaisesRegex(unit.IntegratorHold, "PROVENANCE"):
                    unit.assess_external_stage(
                        ISSUE, RUN, [unit.Worker("PR_STAGED", url, SHA)],
                        1, CANONICAL, TARGET)

    def test_duplicate_workers_never_create_fake_parallel_completions(self):
        api, calls = stub()
        with patch.object(unit, "_api", side_effect=api):
            with self.assertRaisesRegex(unit.IntegratorHold, "DUPLICATE_WORKER"):
                unit.assess_external_stage(
                    ISSUE, RUN, [worker(), worker()], 1, CANONICAL, TARGET)

    def test_dependent_phases_never_resume_from_staged_only(self):
        root = Path(__file__).resolve().parents[2]
        owner = (root / ".github/workflows/coordinator-owner-order.yml").read_text()
        self.assertIn("needs.integrate.outputs.phase_status == 'PHASE_VALIDATED_PENDING_NEXT_PHASE'", owner)
        self.assertNotIn("PHASE_STAGED_AWAITING_TARGET_CERTIFICATION", owner)


if __name__ == "__main__":
    unittest.main()
