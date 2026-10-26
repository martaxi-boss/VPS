"""Offline P311 GitHub owner-button preview gate tests.

All platform evidence is synthetic. In real runs it comes from GitHub REST
GET workflow-run and GET review-history APIs over TLS, never from JSON uploaded
by the requester. No real approvals or REA operations occur in these tests.
"""
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
            "environments": [{"name": gate.REVIEW_ENVIRONMENT, "id": gate.REVIEW_ENVIRONMENT_ID}],
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

    def _signed_task_fixture(self):
        from ops import rea_scoped_approval_20261026 as scoped
        key = Ed25519PrivateKey.generate()
        fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        grant = {
            "purpose": scoped.PURPOSE, "grant_id": "f"*32,
            "project": "Engenharia Reversa", "task_id": "P311-SAMPLE-GRANT",
            "origin": scoped.ORIGIN,
            "artifact_root": "/opt/rea-reversa/rea/.rea-private/jobs/p311-review",
            "not_before": fmt(self.now - timedelta(minutes=1)),
            "expires_at": fmt(self.now + timedelta(minutes=40)),
            "allowed_tools": ["inspect_with_objdump"],
            "permitted_effects": ["launchesProcess", "mutatesSession"],
        }
        signature = base64.b64encode(
            key.sign(scoped.canonical_bytes(grant))).decode("ascii")
        return {
            "grant": grant, "owner_signature": signature,
            "project": grant["project"], "task_id": grant["task_id"],
            "origin": grant["origin"], "artifact_root": grant["artifact_root"],
        }

    def test_signed_task_digest_matches_exact_real_owner_review(self):
        task = self._signed_task_fixture()
        digest = gate.signed_task_review_digest(
            task, request_id=self.request["request_id"])
        self.assertEqual(64, len(digest))
        approved = self.check(request={**self.request, "operation_sha256": digest})
        bound = gate.match_verified_review_to_signed_task(approved, task)
        self.assertTrue(bound["bound_preview_only"])
        self.assertEqual(self.context["run_id"], str(bound["run_id"]))
        self.assertEqual(digest, bound["operation_sha256"])
        self.assertNotIn("owner_signature", bound)
        self.assertNotIn("grant", bound)

    def test_owner_review_cannot_authorize_swapped_tool_or_scope(self):
        task = self._signed_task_fixture()
        digest = gate.signed_task_review_digest(
            task, request_id=self.request["request_id"])
        receipt = self.check(request={**self.request, "operation_sha256": digest})
        grant = task["grant"]
        for change in (
            {"task_id": "OTHER-TASK"},
            {"project": "Outro Projeto"},
            {"allowed_tools": ["import_managed_reconstruction"]},
            {"permitted_effects": ["mutatesDevice"]},
            {"artifact_root": "/opt/rea-reversa/rea/.rea-private/jobs/other"},
            {"expires_at": "2026-10-27T20:00:00Z"},
        ):
            altered = dict(task, grant={**grant, **change})
            for key in ("project", "task_id", "artifact_root"):
                if key in change:
                    altered[key] = change[key]
            with self.subTest(change=change), self.assertRaises(
                    gate.ApprovalGateError):
                gate.match_verified_review_to_signed_task(receipt, altered)

    def test_signature_swap_and_review_request_id_replay_denied(self):
        task = self._signed_task_fixture()
        digest = gate.signed_task_review_digest(
            task, request_id=self.request["request_id"])
        receipt = self.check(request={**self.request, "operation_sha256": digest})
        another = self._signed_task_fixture()
        self.assertNotEqual(task["owner_signature"], another["owner_signature"])
        with self.assertRaises(gate.ApprovalGateError):
            gate.match_verified_review_to_signed_task(receipt, another)
        self.assertNotEqual(
            gate.signed_task_review_digest(task, request_id="9"*32),
            digest)

    def test_untrusted_or_unverified_preview_receipt_fails_closed(self):
        task = self._signed_task_fixture()
        digest = gate.signed_task_review_digest(
            task, request_id=self.request["request_id"])
        receipt = self.check(request={**self.request, "operation_sha256": digest})
        for patch in (
            {"verified_preview": False},
            {"run_id": 0}, {"review_environment": "another-environment"},
            {"operation_sha256": "0"*64},
            {"request_id": "invalid"},
            {"owner_signature": "forged"},
        ):
            altered = dict(receipt, **patch)
            with self.subTest(patch=patch), self.assertRaises(
                    gate.ApprovalGateError):
                gate.match_verified_review_to_signed_task(altered, task)

    def test_signed_review_rejects_nonowner_projects_or_malformed_structure(self):
        task = self._signed_task_fixture()
        for altered in (
            {**task, "project": "IPTV"},
            {**task, "owner_signature": "sim"},
            {**task, "grant": {**task["grant"], "tool": "extra"}},
            {**task, "grant": {**task["grant"],
                               "purpose": "REA_OWNER_APPROVAL_V1"}},
            {**task, "other_field": True},
        ):
            with self.subTest(altered=altered), self.assertRaises(
                    gate.ApprovalGateError):
                gate.signed_task_review_digest(
                    altered, request_id=self.request["request_id"])

    def test_same_name_different_environment_identity_denied(self):
        altered = [{**self.review[0],
                    "environments": [{
                        "name": gate.REVIEW_ENVIRONMENT,
                        "id": gate.REVIEW_ENVIRONMENT_ID + 1
                    }]}]
        with self.assertRaises(gate.ApprovalGateError):
            self.check(reviews=altered)

    def test_review_proposal_publishes_only_digest_not_private_task(self):
        task = self._signed_task_fixture()
        expiry = (self.now + timedelta(minutes=10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        path, proposal = gate.prepare_owner_review_request(
            task, expires_at=expiry, request_id="a"*32, now=self.now)
        self.assertEqual(self.path, path)
        self.assertEqual({
            "purpose", "request_id", "operation_sha256",
            "project", "expires_at"
        }, set(proposal))
        import json
        serialized = json.dumps(proposal)
        self.assertNotIn(task["owner_signature"], serialized)
        self.assertNotIn(task["task_id"], serialized)
        self.assertNotIn(task["artifact_root"], serialized)
        receipt = self.check(request=proposal)
        self.assertTrue(gate.match_verified_review_to_signed_task(
            receipt, task)["bound_preview_only"])

    def test_review_proposal_rejects_expiry_after_signed_permission(self):
        task = self._signed_task_fixture()
        expires = (self.now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaises(gate.ApprovalGateError):
            gate.prepare_owner_review_request(
                task, expires_at=expires, request_id="a"*32, now=self.now)
        expired = {**task, "grant": {
            **task["grant"],
            "expires_at": (self.now - timedelta(seconds=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ")}}
        soon = (self.now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaises(gate.ApprovalGateError):
            gate.prepare_owner_review_request(
                expired, expires_at=soon, request_id="a"*32, now=self.now)

    def test_review_request_ids_do_not_reuse_another_button(self):
        task = self._signed_task_fixture()
        expiry = (self.now + timedelta(minutes=12)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        old_path, old = gate.prepare_owner_review_request(
            task, expires_at=expiry, request_id="a"*32, now=self.now)
        new_path, new = gate.prepare_owner_review_request(
            task, expires_at=expiry, request_id="b"*32, now=self.now)
        self.assertNotEqual(old_path, new_path)
        self.assertNotEqual(old["operation_sha256"], new["operation_sha256"])
        approved_old = self.check(request=old)
        with self.assertRaises(gate.ApprovalGateError):
            gate.match_verified_review_to_signed_task(
                {**approved_old, "request_id": "b"*32}, task)

    def test_review_nonce_generated_randomly_not_fixed(self):
        task = self._signed_task_fixture()
        expiry = (self.now + timedelta(minutes=10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        one_path, one = gate.prepare_owner_review_request(
            task, expires_at=expiry, now=self.now)
        two_path, two = gate.prepare_owner_review_request(
            task, expires_at=expiry, now=self.now)
        self.assertNotEqual(one_path, two_path)
        self.assertNotEqual(one["request_id"], two["request_id"])
        self.assertEqual(32, len(one["request_id"]))
        self.assertEqual(64, len(one["operation_sha256"]))

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(gate.ApprovalGateError):
            gate._parse_no_duplicates([("request_id", "a"), ("request_id", "b")])


if __name__ == "__main__":
    unittest.main()

