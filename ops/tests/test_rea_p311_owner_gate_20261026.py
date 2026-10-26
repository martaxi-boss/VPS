"""Offline P311 GitHub owner-button preview gate tests.

All platform evidence is synthetic. In real runs it comes from GitHub REST
GET workflow-run and GET review-history APIs over TLS, never from JSON uploaded
by the requester. No real approvals or REA operations occur in these tests.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from ops import rea_p311_owner_gate_20261026 as gate


class P311GitHubButtonVerificationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        expire = (self.now + timedelta(minutes=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.request = {
            "purpose": gate.PURPOSE, "request_id": "a"*32,
            "operation_sha256": "b"*64,
            "project": "Engenharia Reversa", "expires_at": expire,
        }
        self.path = f"{gate.REQUEST_DIRECTORY}/{self.request['request_id']}.json"
        self.context = {
            "repository": gate.REPO, "actor": gate.OWNER_LOGIN,
            "triggering_actor": gate.OWNER_LOGIN, "event": "push",
            "ref": "refs/heads/" + gate.BRANCH,
            "sha": "c"*40, "attempt": "1", "run_id": "40381893124",
        }
        self.run = {
            "id": 40381893124, "event": "push",
            "head_sha": self.context["sha"],
            "head_branch": gate.BRANCH, "run_attempt": 1,
            "path": gate.WORKFLOW+"@refs/heads/"+gate.BRANCH,
            "actor": {"login": gate.OWNER_LOGIN, "id": gate.OWNER_ID},
        }
        self.review = [{
            "state": "approved",
            "user": {"login": gate.OWNER_LOGIN, "id": gate.OWNER_ID},
            "environments": [{"name": gate.REVIEW_ENVIRONMENT, "id": 121121}],
        }]

    def check(self, context=None, run=None, reviews=None, request=None, path=None):
        return gate.verify_github_review(
            self.context if context is None else context,
            self.run if run is None else run,
            self.review if reviews is None else reviews,
            self.request if request is None else request,
            request_path=self.path if path is None else path, now=self.now)

    def test_one_owner_clicked_approve_for_exact_run_preview_passes(self):
        result = self.check()
        self.assertTrue(result["verified_preview"])
        self.assertEqual(self.request["operation_sha256"], result["operation_sha256"])
        self.assertNotIn("owner_signature", result)
        self.assertNotIn("permission", result)

    def test_no_review_or_unauthenticated_environment_does_not_pass(self):
        for reviews in ([], [{"state": "approved", "user":
                             {"login": gate.OWNER_LOGIN, "id": gate.OWNER_ID},
                              "environments": []}]):
            with self.subTest(reviews=reviews), self.assertRaises(gate.ApprovalGateError):
                self.check(reviews=reviews)

    def test_wrong_or_forged_approver_is_rejected(self):
        for identity in (
            {"login": "attacker", "id": gate.OWNER_ID},
            {"login": gate.OWNER_LOGIN, "id": 12345},
            {"login": "attacker", "id": 12345},
        ):
            with self.subTest(identity=identity), self.assertRaises(gate.ApprovalGateError):
                self.check(reviews=[{**self.review[0], "user": identity}])

    def test_rejected_review_or_second_approval_is_fail_closed(self):
        rejected = {**self.review[0], "state": "rejected"}
        duplicate = [self.review[0], dict(self.review[0])]
        for reviews in ([rejected], [self.review[0], rejected], duplicate):
            with self.subTest(reviews=reviews), self.assertRaises(gate.ApprovalGateError):
                self.check(reviews=reviews)

    def test_unprotected_job_or_wrong_environment_cannot_prove_approval(self):
        env = [{"name": "unprotected-preview", "id": 121121}]
        with self.assertRaises(gate.ApprovalGateError):
            self.check(reviews=[{**self.review[0], "environments": env}])
        with self.assertRaises(gate.ApprovalGateError):
            self.check(reviews=[{**self.review[0],
                                 "environments": [{"name": gate.REVIEW_ENVIRONMENT}]}])

    def test_wrong_branch_sha_or_workflow_is_denied(self):
        for patch in ({"head_sha": "f"*40},
                      {"head_branch": "main"},
                      {"event": "workflow_dispatch"},
                      {"path": ".github/workflows/another.yml@refs/heads/main"},
                      {"run_attempt": 2}):
            with self.subTest(patch=patch), self.assertRaises(gate.ApprovalGateError):
                self.check(run={**self.run, **patch})

    def test_trigger_actor_context_and_reruns_denied(self):
        for patch in ({"actor": "attacker"},
                      {"triggering_actor": "attacker"},
                      {"ref": "refs/heads/main"},
                      {"attempt": "2"},
                      {"event": "workflow_dispatch"},
                      {"run_id": "0123"},
                      {"repository": "attacker/another"}):
            with self.subTest(patch=patch), self.assertRaises(gate.ApprovalGateError):
                self.check(context={**self.context, **patch})

    def test_other_run_or_account_id_cannot_reuse_owner_review(self):
        with self.assertRaises(gate.ApprovalGateError):
            self.check(run={**self.run, "id": 121212})
        with self.assertRaises(gate.ApprovalGateError):
            self.check(run={**self.run, "actor": {"login": gate.OWNER_LOGIN, "id": 1}})

    def test_expired_other_project_or_invalid_request_identifier_denied(self):
        for patch in (
            {"project": "Telegram Robot Leads"},
            {"request_id": "not-a-hex-id"},
            {"operation_sha256": "something"},
            {"expires_at": (self.now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"expires_at": (self.now + timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ):
            with self.subTest(patch=patch), self.assertRaises(gate.ApprovalGateError):
                self.check(request={**self.request, **patch})

    def test_path_mismatch_and_extra_fields_denied(self):
        with self.assertRaises(gate.ApprovalGateError):
            self.check(path=gate.REQUEST_DIRECTORY+"/attacker.json")
        with self.assertRaises(gate.ApprovalGateError):
            self.check(request={**self.request, "owner_signature": "FAKE"})

    def test_selected_request_requires_one_added_file_only(self):
        commit = "a"*40
        with mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                [], 0, f"A\t{self.path}\n", "")
            self.assertEqual(self.path, gate.selected_request_from_commit(commit))
        for output in (
            f"D\t{self.path}\n",
            f"A\t{self.path}\nA\topenssl-secret.pem\n",
            "A\trea-linux/requests/token.json\n",
            f"M\t{self.path}\n",
        ):
            with self.subTest(output=output), mock.patch("subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, output, "")
                with self.assertRaises(gate.ApprovalGateError):
                    gate.selected_request_from_commit(commit)

    def test_unapproved_environments_are_not_authorization_tickets(self):
        review = [{
            "state": "pending",
            "user": {"login": gate.OWNER_LOGIN, "id": gate.OWNER_ID},
            "environments": [{"name": gate.REVIEW_ENVIRONMENT, "id": 20}],
        }]
        with self.assertRaises(gate.ApprovalGateError):
            self.check(reviews=review)
        receipt = self.check()
        self.assertEqual({
            "verified_preview", "request_id", "operation_sha256",
            "run_id", "review_environment"
        }, set(receipt))
        self.assertNotIn("signed_task", receipt)

    def test_token_missing_and_endpoint_not_whitelisted_deny(self):
        with self.assertRaises(gate.ApprovalGateError):
            gate._get_github_api("/users/attacker", token="a"*40)
        with self.assertRaises(gate.ApprovalGateError):
            gate._get_github_api(
                "/repos/martaxi-boss/VPS/actions/runs/1", token="bad")

    def test_owner_preview_workflow_cannot_contact_vps_or_rea(self):
        src = (Path(__file__).resolve().parents[2] /
               gate.WORKFLOW).read_text(encoding="utf-8")
        self.assertIn("environment:\n      name: rea-p311-owner-consent", src)
        self.assertIn("ops/rea_p311_owner_gate_20261026.py --mode verify-review", src)
        self.assertIn("permissions:\n  contents: read\n  actions: read", src)
        self.assertIn('      - "rea-linux/owner-review-requests/*.json"', src)
        for dangerous in ("sshpass", "VPS_SSH_PASSWORD", "REA_P311_SCOPED_TASKS",
                          "tools/call", "sudo ", "curl ", "workflow_dispatch",
                          "contents: write", "deployments: write",
                          "GITHUB_TOKEN: $" + "{{ secrets."):
            with self.subTest(dangerous=dangerous):
                self.assertNotIn(dangerous, src)

    def test_preview_gate_does_not_write_a_signature_or_authorize_mcp(self):
        from ops import rea_scoped_approval_20261026 as scoped
        receipt = self.check()
        self.assertTrue(receipt["verified_preview"])
        self.assertNotIn("owner_signature", receipt)
        self.assertNotIn("approved_tools", receipt)
        self.assertNotIn("grant", receipt)
        self.assertNotEqual(scoped.PURPOSE, gate.PURPOSE)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(gate.ApprovalGateError):
            gate._parse_no_duplicates([("request_id", "a"), ("request_id", "b")])


if __name__ == "__main__":
    unittest.main()

