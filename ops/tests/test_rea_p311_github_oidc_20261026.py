"""P311 GitHub OIDC cryptographic proof tests with ONLY ephemeral fixture keys.

No OIDC token from the real owner's GitHub account is captured, uploaded or
printed. No environment rules are changed and no SSH or MCP calls occur.
"""
import base64
from contextlib import redirect_stdout
import io
import json
import hashlib
import os
from pathlib import Path
import tempfile
from datetime import datetime, timedelta, timezone
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ops import rea_p311_github_oidc_20261026 as oidc
from ops import rea_p311_owner_gate_20261026 as gate
from ops import rea_scoped_approval_20261026 as scoped


def b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class P311GithubOIDCReviewTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        timestamp = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
        key = Ed25519PrivateKey.generate()
        self.owner_signer = key
        grant = {
            "purpose": scoped.PURPOSE, "grant_id": "7"*32,
            "project": "Engenharia Reversa", "task_id": "P311-CRYPTO-PREVIEW",
            "origin": scoped.ORIGIN,
            "artifact_root": "/opt/rea-reversa/rea/.rea-private/jobs/p311-oidc",
            "allowed_tools": ["inspect_with_objdump"],
            "permitted_effects": ["launchesProcess", "mutatesSession"],
            "not_before": timestamp(self.now - timedelta(minutes=1)),
            "expires_at": timestamp(self.now + timedelta(minutes=40)),
        }
        self.signed = {
            "grant": grant,
            "owner_signature": base64.b64encode(
                key.sign(scoped.canonical_bytes(grant))).decode("ascii"),
            "project": grant["project"], "task_id": grant["task_id"],
            "origin": grant["origin"], "artifact_root": grant["artifact_root"],
        }
        self.path, self.request = gate.prepare_owner_review_request(
            self.signed, expires_at=timestamp(self.now + timedelta(minutes=15)),
            request_id="a"*32, now=self.now)
        self.run = {
            "id": 40385975218, "event": "push",
            "head_branch": gate.BRANCH, "head_sha": "c"*40,
            "run_attempt": 1,
            "path": gate.WORKFLOW + "@refs/heads/" + gate.BRANCH,
            "actor": {"login": gate.OWNER_LOGIN, "id": gate.OWNER_ID},
        }
        self.ctx = {
            "repository": gate.REPO, "actor": gate.OWNER_LOGIN,
            "triggering_actor": gate.OWNER_LOGIN, "event": "push",
            "ref": "refs/heads/" + gate.BRANCH,
            "sha": self.run["head_sha"], "run_id": str(self.run["id"]),
            "attempt": "1",
        }
        self.review = [{
            "state": "approved",
            "user": {"login": gate.OWNER_LOGIN, "id": gate.OWNER_ID},
            "environments": [{"name": gate.REVIEW_ENVIRONMENT,
                              "id": gate.REVIEW_ENVIRONMENT_ID}],
        }]
        self.committed = (json.dumps(
            self.request, sort_keys=True, separators=(",", ":")) + "\n").encode()
        blob_sha = hashlib.sha1(
            b"blob " + str(len(self.committed)).encode() + b"\x00" +
            self.committed).hexdigest()
        number_of_lines = len(self.committed.splitlines())
        self.commit = {
            "sha": self.run["head_sha"], "parents": [{"sha": "b"*40}],
            "files": [{"filename": self.path, "status": "added",
                       "sha": blob_sha, "additions": number_of_lines,
                       "deletions": 0, "changes": number_of_lines}],
            "stats": {"additions": number_of_lines, "deletions": 0,
                      "total": number_of_lines},
        }
        self.private_rsa = rsa.generate_private_key(public_exponent=65537,
                                                    key_size=2048)
        nums = self.private_rsa.public_key().public_numbers()
        self.kid = "p311-temporary-test-key"
        self.jwks = {"keys": [{
            "kid": self.kid, "kty": "RSA", "alg": "RS256", "use": "sig",
            "n": b64url(nums.n.to_bytes((nums.n.bit_length()+7)//8, "big")),
            "e": b64url(nums.e.to_bytes((nums.e.bit_length()+7)//8, "big")),
        }]}
        now = int(self.now.timestamp())
        self.header = {"typ": "JWT", "alg": "RS256", "kid": self.kid}
        self.claims = {
            "iss": oidc.ISSUER,
            "aud": oidc.audience_for_review(self.request),
            "sub": "repo:martaxi-boss@277365554/VPS@1386634013:environment:" +
                   oidc.ENVIRONMENT,
            "iat": now-2, "nbf": now-2, "exp": now+200,
            "jti": "p311-test-unique-token-001",
            "repository": oidc.REPO, "repository_id": oidc.REPOSITORY_ID,
            "repository_owner": oidc.OWNER_LOGIN,
            "repository_owner_id": oidc.OWNER_ID,
            "actor": oidc.OWNER_LOGIN, "actor_id": oidc.OWNER_ID,
            "environment": oidc.ENVIRONMENT,
            "workflow_ref": oidc.WORKFLOW_REF, "sha": self.run["head_sha"],
            "run_id": str(self.run["id"]), "run_attempt": "1",
            "ref": "refs/heads/" + oidc.BRANCH, "ref_type": "branch",
            "event_name": "push", "runner_environment": "github-hosted",
        }

    def mint(self, *, header=None, claims=None, key=None):
        hdr = self.header if header is None else header
        payload = self.claims if claims is None else claims
        packed = ".".join(
            b64url(json.dumps(part, sort_keys=True, separators=(",", ":")).encode())
            for part in (hdr, payload))
        k = self.private_rsa if key is None else key
        signature = k.sign(packed.encode(), padding.PKCS1v15(), hashes.SHA256())
        return packed+"."+b64url(signature)

    def verify(self, jwt=None, *, request=None, run=None, jwks=None, now=None):
        return oidc.verify_github_oidc_jwt(
            self.mint() if jwt is None else jwt,
            self.jwks if jwks is None else jwks,
            public_request=self.request if request is None else request,
            workflow_run=self.run if run is None else run,
            now=self.now if now is None else now)

    def full(self, jwt=None, *, reviews=None, request=None, task=None, run=None):
        return oidc.verify_review_and_oidc_for_signed_task(
            self.ctx, self.run if run is None else run,
            self.review if reviews is None else reviews,
            self.request if request is None else request,
            self.signed if task is None else task,
            self.mint() if jwt is None else jwt, self.jwks,
            request_path=self.path, now=self.now)

    def test_runner_oidc_token_url_pinned_to_github_shards(self):
        examples = (
            "https://pipelines.actions.githubusercontent.com/job/path/idtoken?api-version=2.0",
            "https://pipelinesghubeus6.actions.githubusercontent.com/job/idtoken?api-version=2.0",
        )
        for source in examples:
            with self.subTest(source=source):
                got = oidc._actions_audience_request_url(source, self.request)
                self.assertIn("audience=rea-p311-consent%3A", got)
                self.assertIn("api-version=2.0", got)
                self.assertEqual(source.split("?")[0], got.split("?")[0])
        for malicious in (
            "http://pipelines.actions.githubusercontent.com/job/idtoken?api-version=2.0",
            "https://pipelines.actions.githubusercontent.com.attacker.test/x/idtoken?api-version=2.0",
            "https://pipelines.actions.githubusercontent.com@evil.test/idtoken?api-version=2.0",
            "https://pipelines.actions.githubusercontent.com:8443/idtoken?api-version=2.0",
            "https://pipelines.actions.githubusercontent.com/x/idtoken?api-version=2.0&audience=evil",
            "https://pipelines.actions.githubusercontent.com/x/idtoken?api-version=1.0",
            "https://pipelines.actions.githubusercontent.com/x/idtoken?api-version=2.0#fragment",
            "https://token.actions.githubusercontent.com/.well-known/jwks",
        ):
            with self.subTest(malicious=malicious), self.assertRaises(
                    oidc.GithubOIDCError):
                oidc._actions_audience_request_url(malicious, self.request)

    def test_runner_token_exchange_never_uses_untrusted_provider(self):
        endpoint = ("https://pipelinesghubeus6.actions.githubusercontent.com/"
                    "fake/job/idtoken?api-version=2.0")
        jwt = self.mint()
        class Response:
            def __init__(self, url):
                self.url = url
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return self.url
            def read(self, size):
                return json.dumps({"value": jwt}).encode()
        class Opener:
            def open(self, req, timeout):
                self.req = req
                self.timeout = timeout
                return Response(req.full_url)
        opener = Opener()
        with mock.patch.object(oidc.urlrequest, "build_opener",
                               return_value=opener):
            token = oidc.request_actions_oidc_jwt(
                public_request=self.request, endpoint=endpoint,
                bearer="t"*120)
        self.assertEqual(jwt, token)
        self.assertIn("Authorization", dict(opener.req.header_items()))
        self.assertIn("audience=rea-p311-consent", opener.req.full_url)

    def test_token_exchange_without_job_identity_fails_without_network(self):
        endpoint = ("https://pipelines.actions.githubusercontent.com/"
                    "somejob/idtoken?api-version=2.0")
        with mock.patch.object(oidc.urlrequest, "build_opener") as opener:
            with self.assertRaises(oidc.GithubOIDCError):
                oidc.request_actions_oidc_jwt(
                    public_request=self.request, endpoint=endpoint, bearer="")
            opener.assert_not_called()

    def test_preview_runtime_validates_real_review_and_jwt_without_vps(self):
        with mock.patch.object(gate, "_runtime_context", return_value=self.ctx), \
             mock.patch.object(gate, "selected_request_from_commit",
                               return_value=self.path), \
             mock.patch.object(gate, "_load_request", return_value=self.request), \
             mock.patch.object(gate, "_get_github_api",
                               side_effect=[self.run, self.review]), \
             mock.patch.object(oidc, "request_actions_oidc_jwt",
                               return_value=self.mint()), \
             mock.patch.object(oidc, "load_official_github_jwks",
                               return_value=self.jwks):
            with mock.patch.object(oidc, "verify_github_oidc_jwt",
                                   wraps=oidc.verify_github_oidc_jwt) as verify:
                result = oidc.preview_real_oidc_owner_button(
                    request_path=self.path)
                verify.assert_called_once()
        self.assertTrue(result["oidc_review_preview_only"])
        self.assertEqual(self.run["id"], result["run_id"])
        self.assertNotIn("jwt", result)
        self.assertNotIn("signed_task", result)

    def test_preview_runtime_requires_genuine_human_approval(self):
        with mock.patch.object(gate, "_runtime_context", return_value=self.ctx), \
             mock.patch.object(gate, "selected_request_from_commit",
                               return_value=self.path), \
             mock.patch.object(gate, "_load_request", return_value=self.request), \
             mock.patch.object(gate, "_get_github_api",
                               side_effect=[self.run, []]), \
             mock.patch.object(oidc, "request_actions_oidc_jwt") as mint:
            with self.assertRaises(gate.ApprovalGateError):
                oidc.preview_real_oidc_owner_button(
                    request_path=self.path)
            mint.assert_not_called()

    def test_oidc_preview_job_never_runs_mcp_and_minimizes_token_scope(self):
        from pathlib import Path
        workflow = (Path(__file__).resolve().parents[2] /
                    gate.WORKFLOW).read_text(encoding="utf-8")
        self.assertIn("id-token: write", workflow)
        self.assertEqual(workflow.count("id-token: write"), 1)
        protected = workflow.split("  wait-for-real-owner-button:", 1)[1]
        self.assertIn("environment:\n      name: rea-p311-owner-consent", protected)
        self.assertIn("id-token: write", protected.split("environment:", 1)[0])
        self.assertIn("python\" -m ops.rea_p311_github_oidc_20261026", protected)
        for dangerous in ("VPS_SSH_PASSWORD", "sshpass", "tools/call",
                          "REA_P311_SCOPED_TASKS", "contents: write",
                          "deployments: write", "sudo ", "workflow_dispatch"):
            with self.subTest(dangerous=dangerous):
                self.assertNotIn(dangerous, workflow)

    def _prepare_private_consumption(self):
        from ops import rea_secure_protocol_20261022 as secure
        self.consumption_root = tempfile.TemporaryDirectory()
        self.addCleanup(self.consumption_root.cleanup)
        root = Path(self.consumption_root.name)
        self.revocations = root / "revoked-p311-grants"
        self.revocations.mkdir(mode=0o700)
        self.spent = root / "spent-p311-oidc"
        self.spent.mkdir(mode=0o700)
        self.owner_public = self.owner_signer.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.trusted_contracts = {
            "inspect_with_objdump": (
                secure.AUDITED_EFFECTS["inspect_with_objdump"], "workspace")
        }

    def consume(self, *, reviews=None, jwt=None, task=None, public=None,
                commit=None, committed=None):
        public = self.request if public is None else public
        with mock.patch.object(oidc, "load_official_github_jwks",
                               return_value=self.jwks):
            return oidc.verify_owner_review_oidc_and_consume_once(
                self.ctx, self.run,
                self.review if reviews is None else reviews,
                public, self.signed if task is None else task,
                self.mint() if jwt is None else jwt,
                self.owner_public, self.trusted_contracts,
                request_path=self.path,
                reviewed_commit=self.commit if commit is None else commit,
                committed_request_bytes=(
                    self.committed if committed is None else committed),
                revocation_dir=self.revocations,
                private_spent_dir=self.spent, now=self.now)

    def test_real_signature_stack_consumes_approved_request_once(self):
        self._prepare_private_consumption()
        with mock.patch.object(oidc.os, "fsync", wraps=os.fsync) as sync, \
             mock.patch.object(oidc.os, "open", wraps=os.open) as opened:
            receipt = self.consume()
        self.assertGreaterEqual(sync.call_count, 2)
        self.assertNotEqual(
            sync.call_args_list[0].args[0], sync.call_args_list[-1].args[0])
        self.assertGreaterEqual(
            sum(1 for call in opened.call_args_list if "dir_fd" in call.kwargs), 2)
        self.assertTrue(receipt["verified_spent_preview_only"])
        marker = self.spent / (self.request["request_id"] + ".spent")
        self.assertTrue(marker.is_file())
        self.assertEqual(0o600, marker.stat().st_mode & 0o777)
        contents = marker.read_text()
        self.assertIn(self.request["operation_sha256"], contents)
        self.assertNotIn(self.signed["owner_signature"], contents)
        self.assertNotIn(self.mint(), contents)
        self.assertNotIn(self.claims["jti"], contents)
        with self.assertRaisesRegex(oidc.GithubOIDCError, "already been used"):
            self.consume()
        self.assertEqual(contents, marker.read_text())


    def test_commit_origin_must_match_reviewed_run_before_spending(self):
        self._prepare_private_consumption()
        file = self.commit["files"][0]
        variants = [
            {**self.commit, "sha": "e"*40},
            {**self.commit, "parents": []},
            {**self.commit, "files": [{**file, "status": "modified"}]},
            {**self.commit, "files": [file, {
                "filename": "ops/unapproved.py", "status": "modified"}]},
            {**self.commit, "stats": {
                **self.commit["stats"], "total": file["changes"] + 1}},
        ]
        for invalid in variants:
            with self.subTest(commit=invalid), self.assertRaises(
                    oidc.GithubOIDCError):
                self.consume(commit=invalid)
            self.assertEqual([], list(self.spent.iterdir()))
        self.assertTrue(self.consume()["verified_spent_preview_only"])

    def test_commit_blob_and_public_challenge_cannot_be_substituted(self):
        self._prepare_private_consumption()
        for invalid_blob in (self.committed + b" ",
                             b'{"request_id":"forged"}'):
            with self.subTest(blob=invalid_blob), self.assertRaises(
                    oidc.GithubOIDCError):
                self.consume(committed=invalid_blob)
        with self.assertRaises(oidc.GithubOIDCError):
            self.consume(public={**self.request, "operation_sha256": "e"*64})
        self.assertEqual([], list(self.spent.iterdir()))
        self.assertTrue(self.consume()["verified_spent_preview_only"])

    def test_rejected_review_does_not_consume_one_use_marker(self):
        self._prepare_private_consumption()
        with self.assertRaises(gate.ApprovalGateError):
            self.consume(reviews=[])
        self.assertEqual([], list(self.spent.iterdir()))
        self.assertTrue(self.consume()["verified_spent_preview_only"])

    def test_expired_token_does_not_consume_authorization(self):
        self._prepare_private_consumption()
        expired = {**self.claims, "iat": int(self.now.timestamp()) - 800,
                   "exp": int(self.now.timestamp()) - 500}
        with self.assertRaises(oidc.GithubOIDCError):
            self.consume(jwt=self.mint(claims=expired))
        self.assertEqual([], list(self.spent.iterdir()))

    def test_invalid_owner_key_rejected_even_with_valid_github_button(self):
        self._prepare_private_consumption()
        other_key = Ed25519PrivateKey.generate()
        malicious = dict(self.signed, owner_signature=base64.b64encode(
            other_key.sign(scoped.canonical_bytes(
                self.signed["grant"]))).decode("ascii"))
        public = {**self.request, "operation_sha256":
                  gate.signed_task_review_digest(
                      malicious, request_id=self.request["request_id"])}
        jwt = self.mint(claims={**self.claims,
                    "aud": oidc.audience_for_review(public)})
        # This negative Ed25519 test must pass commit provenance first:
        # simulate GitHub's immutable blob for the SAME malicious challenge.
        committed = (json.dumps(
            public, sort_keys=True, separators=(",", ":")) + "\n").encode()
        blob_sha = hashlib.sha1(
            b"blob " + str(len(committed)).encode() + b"\x00" +
            committed).hexdigest()
        bad_file = {**self.commit["files"][0], "sha": blob_sha}
        reviewed_commit = {**self.commit, "files": [bad_file]}
        with self.assertRaises(scoped.ScopedApprovalError):
            self.consume(task=malicious, public=public, jwt=jwt,
                         commit=reviewed_commit, committed=committed)
        self.assertEqual([], list(self.spent.iterdir()))

    def test_owner_revocation_blocks_consumption_before_state_change(self):
        self._prepare_private_consumption()
        marker = self.revocations / (
            self.signed["grant"]["grant_id"] + ".revoked")
        marker.write_text("revoked\n", encoding="ascii")
        marker.chmod(0o600)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.consume()
        self.assertEqual([], list(self.spent.iterdir()))

    def test_no_private_oneuse_store_blocks_all_proofs(self):
        self._prepare_private_consumption()
        self.spent.rmdir()
        with self.assertRaises(scoped.ScopedApprovalError):
            self.consume()
        self.spent.mkdir(mode=0o700)
        self.spent.chmod(0o777)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.consume()
        self.spent.chmod(0o700)
        self.assertTrue(self.consume()["verified_spent_preview_only"])

    def test_spent_store_symlink_and_preexisting_marker_cannot_be_overwritten(self):
        self._prepare_private_consumption()
        marker = self.spent / (self.request["request_id"] + ".spent")
        marker.write_text("blocked", encoding="ascii")
        marker.chmod(0o600)
        with self.assertRaisesRegex(oidc.GithubOIDCError, "already been used"):
            self.consume()
        self.assertEqual("blocked", marker.read_text())
        marker.unlink()
        self.spent.rmdir()
        fake = self.spent.parent / "another-private-dir"
        fake.mkdir(mode=0o700)
        self.spent.symlink_to(fake)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.consume()


    def _trusted_github_responses(self):
        run = {**self.run, "status": "completed", "conclusion": "success",
            "repository": {
            "full_name": oidc.REPO, "id": int(oidc.REPOSITORY_ID)},
            "head_repository": {
                "full_name": oidc.REPO, "id": int(oidc.REPOSITORY_ID)},
            "triggering_actor": {
                "login": gate.OWNER_LOGIN, "id": gate.OWNER_ID}}
        return [run, self.review, self.commit, {
            "sha": self.commit["files"][0]["sha"], "encoding": "base64",
            "size": len(self.committed),
            "content": base64.b64encode(self.committed).decode("ascii")}]

    def test_trusted_rest_adapter_binds_actual_review_commit_and_jwt(self):
        self._prepare_private_consumption()
        endpoint_calls = []
        fixtures = self._trusted_github_responses()

        def fake_get(resource, *, token, **kwargs):
            endpoint_calls.append(resource)
            self.assertEqual(token, "g"*48)
            return fixtures[len(endpoint_calls)-1]

        with mock.patch.object(oidc, "_p311_github_rest_get",
                               side_effect=fake_get), \
             mock.patch.object(oidc, "load_official_github_jwks",
                               return_value=self.jwks):
            receipt = oidc.verify_trusted_owner_review_oidc_and_consume_once(
                self.run["id"], self.request["request_id"],
                self.signed, self.mint(), self.owner_public,
                self.trusted_contracts, github_token="g"*48,
                revocation_dir=self.revocations,
                private_spent_dir=self.spent, now=self.now)
        self.assertTrue(receipt["verified_spent_preview_only"])
        self.assertEqual(
            endpoint_calls,
            ["/actions/runs/" + str(self.run["id"]),
             "/actions/runs/" + str(self.run["id"]) + "/approvals",
             "/commits/" + self.run["head_sha"],
             "/git/blobs/" + self.commit["files"][0]["sha"]])
        self.assertNotIn("owner_signature", receipt)
        self.assertNotIn("jwt", receipt)


    def test_rest_adapter_rejects_approved_but_failed_or_pending_run(self):
        self._prepare_private_consumption()
        valid_run = self._trusted_github_responses()[0]
        cases = (
            ("in_progress", None),
            ("queued", None),
            ("completed", "failure"),
            ("completed", "cancelled"),
            ("completed", "skipped"),
            ("completed", None),
            (None, "success"),
        )
        for status, conclusion in cases:
            run = {**valid_run, "status": status, "conclusion": conclusion}
            with self.subTest(status=status, conclusion=conclusion), \
                 mock.patch.object(oidc, "_p311_github_rest_get",
                                   return_value=run) as fetch, \
                 self.assertRaisesRegex(
                     oidc.GithubOIDCError, "completed successfully"):
                oidc.fetch_trusted_owner_review_evidence(
                    self.run["id"], self.request["request_id"],
                    github_token="g"*48, now=self.now)
            fetch.assert_called_once()
            self.assertEqual([], list(self.spent.iterdir()))
        # An owner approval from a cancelled workflow is not reusable.
        with mock.patch.object(oidc, "_p311_github_rest_get",
                               return_value={**valid_run,
                                             "status": "completed",
                                             "conclusion": "cancelled"}) as fetch, \
             mock.patch.object(oidc, "load_official_github_jwks",
                               return_value=self.jwks), \
             self.assertRaises(oidc.GithubOIDCError):
            oidc.verify_trusted_owner_review_oidc_and_consume_once(
                self.run["id"], self.request["request_id"],
                self.signed, self.mint(), self.owner_public,
                self.trusted_contracts, github_token="g"*48,
                revocation_dir=self.revocations,
                private_spent_dir=self.spent, now=self.now)
        fetch.assert_called_once()
        self.assertFalse(list(self.spent.iterdir()))

    def test_rest_adapter_rejects_cross_repo_proof_without_spending(self):
        self._prepare_private_consumption()
        for mutation in (
            {"repository": {"full_name": "attacker/VPS",
                            "id": int(oidc.REPOSITORY_ID)}},
            {"head_repository": {"full_name": oidc.REPO,
                                 "id": 7}},
            {"triggering_actor": {"login": "attacker", "id": 777}},
        ):
            run = {**self._trusted_github_responses()[0], **mutation}
            with self.subTest(mutation=mutation), \
                 mock.patch.object(oidc, "_p311_github_rest_get",
                                   return_value=run), \
                 self.assertRaises(oidc.GithubOIDCError):
                oidc.fetch_trusted_owner_review_evidence(
                    self.run["id"], self.request["request_id"],
                    github_token="g"*48, now=self.now)
            self.assertEqual(list(self.spent.iterdir()), [])

    def test_rest_adapter_rejects_tampered_blob_and_wrong_review(self):
        self._prepare_private_consumption()
        base = self._trusted_github_responses()
        for idx, bad_value in (
            (1, []),
            (2, {**self.commit, "sha": "f"*40}),
            (3, {**base[3], "size": len(self.committed) + 1}),
            (3, {**base[3], "content": "not-base64^"}),
        ):
            replies = [*base]
            replies[idx] = bad_value
            with self.subTest(idx=idx), \
                 mock.patch.object(oidc, "_p311_github_rest_get",
                                   side_effect=replies), \
                 self.assertRaises((oidc.GithubOIDCError,
                                    gate.ApprovalGateError)):
                oidc.fetch_trusted_owner_review_evidence(
                    self.run["id"], self.request["request_id"],
                    github_token="g"*48, now=self.now)
            self.assertEqual(list(self.spent.iterdir()), [])

    def test_rest_fetch_rejects_untrusted_url_and_redirected_reply(self):
        for resource in (
            "/../../other-repo",
            "/commits/" + "a"*40 + "?ref=main",
            "//attacker.example/some",
            "/git/blobs/" + "a"*39,
        ):
            with self.subTest(resource=resource), \
                 self.assertRaises(oidc.GithubOIDCError):
                oidc._p311_github_rest_get(resource, token="g"*48)
        class RedirectedResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "https://attacker.example"
            def read(self, _: int): return b'{"fake":true}'
        with mock.patch.object(oidc.urlrequest, "build_opener") as build:
            build.return_value.open.return_value = RedirectedResponse()
            with self.assertRaises(oidc.GithubOIDCError):
                oidc._p311_github_rest_get(
                    "/commits/" + "a"*40, token="g"*48)
            req = build.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url,
                             oidc.GITHUB_API_REPO + "/commits/" + "a"*40)
            self.assertEqual(req.get_header("Authorization"), "Bearer " + "g"*48)


    def _stage_signed_enrollment(self, **kwargs):
        with mock.patch.object(oidc, "_p311_github_rest_get",
                               side_effect=self._trusted_github_responses()), \
             mock.patch.object(oidc, "load_official_github_jwks",
                               return_value=self.jwks):
            return oidc.enroll_trusted_reviewed_task_offline_only(
                self.run["id"], self.request["request_id"],
                self.signed, self.mint(), self.owner_public,
                self.trusted_contracts, github_token="g"*48,
                private_registry_dir=self.private_grant_registry,
                revocation_dir=self.revocations,
                private_spent_dir=self.spent, now=self.now, **kwargs)

    def test_offline_staging_binds_owner_button_oidc_and_private_grant(self):
        self._prepare_private_consumption()
        self.private_grant_registry = (
            Path(self.consumption_root.name) / "approved-p311-tasks")
        self.private_grant_registry.mkdir(mode=0o700)
        receipt = self._stage_signed_enrollment()
        self.assertIs(receipt["registered_offline_stage_only"], True)
        self.assertEqual(receipt["grant_id"], self.signed["grant"]["grant_id"])
        owner_file = self.private_grant_registry / (
            self.signed["grant"]["grant_id"] + ".json")
        self.assertTrue(owner_file.is_file())
        self.assertEqual(0o600, owner_file.stat().st_mode & 0o777)
        self.assertEqual(
            scoped.read_registered_task_grant(
                receipt["grant_id"], self.owner_public,
                private_registry_dir=self.private_grant_registry,
                revocation_dir=self.revocations,
                trusted_contracts=self.trusted_contracts, now=self.now),
            self.signed)
        with self.assertRaisesRegex(oidc.GithubOIDCError, "already been used"):
            self._stage_signed_enrollment()
        self.assertEqual(1, len(list(self.private_grant_registry.iterdir())))

    def test_offline_staging_requires_existing_secure_registry(self):
        self._prepare_private_consumption()
        self.private_grant_registry = (
            Path(self.consumption_root.name) / "approved-p311-tasks")
        with mock.patch.object(oidc, "_p311_github_rest_get") as network, \
             self.assertRaises(scoped.ScopedApprovalError):
            self._stage_signed_enrollment()
        network.assert_not_called()
        self.assertEqual([], list(self.spent.iterdir()))
        self.assertFalse(self.private_grant_registry.exists())

    def test_offline_staging_failed_registration_never_reopens_spent_proof(self):
        self._prepare_private_consumption()
        self.private_grant_registry = (
            Path(self.consumption_root.name) / "approved-p311-tasks")
        self.private_grant_registry.mkdir(mode=0o700)
        with mock.patch.object(scoped, "register_signed_task_grant",
                               side_effect=OSError("synthetic disk outage")), \
             self.assertRaises(OSError):
            self._stage_signed_enrollment()
        spent = self.spent / (self.request["request_id"] + ".spent")
        self.assertTrue(spent.is_file())
        self.assertEqual([], list(self.private_grant_registry.iterdir()))
        with self.assertRaisesRegex(oidc.GithubOIDCError, "already been used"):
            self._stage_signed_enrollment()

    def test_joint_owner_button_and_oidc_signature_are_required(self):
        receipt = self.full()
        self.assertTrue(receipt["owner_button_and_oidc_preview_only"])
        self.assertEqual(self.run["id"], receipt["run_id"])
        self.assertEqual(self.request["operation_sha256"], receipt["operation_sha256"])
        self.assertEqual(self.claims["jti"], receipt["jwt_jti"])
        self.assertFalse(any(k in receipt for k in (
            "owner_signature", "approved_tools", "permission", "grant",
            "private_key", "authorized_mcp")))

    def test_same_name_and_different_repository_id_denied(self):
        claims = dict(self.claims, repository_id="another-repo-id")
        with self.assertRaisesRegex(oidc.GithubOIDCError, "repository_id"):
            self.verify(self.mint(claims=claims))

    def test_oidc_without_correct_environment_or_workflow_denied(self):
        for change in (
            {"environment": "unprotected"},
            {"workflow_ref": "martaxi-boss/VPS/.github/workflows/other.yml"},
            {"ref": "refs/heads/main"},
            {"event_name": "workflow_dispatch"},
            {"runner_environment": "self-hosted"},
            {"actor_id": "0"},
            {"sha": "f"*40}, {"run_id": "123"}, {"run_attempt": "2"},
        ):
            with self.subTest(change=change), self.assertRaises(
                    oidc.GithubOIDCError):
                self.verify(self.mint(claims={**self.claims, **change}))

    def test_jwt_wrong_audience_or_altered_review_digest_denied(self):
        for audience in ("https://github.com/martaxi-boss",
                         "rea-p311-consent:old:hash"):
            with self.subTest(audience=audience), self.assertRaises(
                    oidc.GithubOIDCError):
                self.verify(self.mint(claims={**self.claims, "aud": audience}))
        another = {**self.request, "operation_sha256": "0"*64}
        with self.assertRaises(oidc.GithubOIDCError):
            self.verify(request=another)

    def test_wrong_signing_key_or_untrusted_kid_denied(self):
        evil = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(oidc.GithubOIDCError):
            self.verify(self.mint(key=evil))
        with self.assertRaises(oidc.GithubOIDCError):
            self.verify(self.mint(header={**self.header, "kid": "unknown"}))

    def test_algorithm_confusion_and_header_key_injection_denied(self):
        for bad in ({"alg": "none"},
                    {"alg": "HS256"},
                    {"jku": "https://attacker.example/keys"},
                    {"jwk": self.jwks["keys"][0]},
                    {"crit": ["b64"]},
                    {"x5u": "https://attacker.example/cert.pem"}):
            with self.subTest(bad=bad), self.assertRaises(oidc.GithubOIDCError):
                self.verify(self.mint(header={**self.header, **bad}))

    def test_duplicate_kid_or_fake_trust_store_denied(self):
        with self.assertRaises(oidc.GithubOIDCError):
            self.verify(jwks={"keys": [self.jwks["keys"][0]]*2})
        with self.assertRaises(oidc.GithubOIDCError):
            self.verify(jwks={"keys": [{"kid": self.kid, "kty": "oct"}]})

    def test_expired_future_or_oversized_jwt_denied(self):
        now = int(self.now.timestamp())
        for change in ({"iat": now-900, "exp": now+200},
                       {"iat": now+500},
                       {"nbf": now+500},
                       {"exp": now-40},
                       {"exp": now+1500}):
            with self.subTest(change=change), self.assertRaises(
                    oidc.GithubOIDCError):
                self.verify(self.mint(claims={**self.claims, **change}))
        with self.assertRaises(oidc.GithubOIDCError):
            self.verify("not-a-valid-jwt")

    def test_human_review_rejection_overrides_valid_jwt(self):
        bad = {**self.review[0], "state": "rejected"}
        with self.assertRaises(gate.ApprovalGateError):
            self.full(reviews=[bad])
        with self.assertRaises(gate.ApprovalGateError):
            self.full(reviews=[])

    def test_modified_owner_task_overrides_valid_human_review_and_jwt(self):
        grant = {**self.signed["grant"], "allowed_tools": ["install_adb_package"]}
        with self.assertRaises(gate.ApprovalGateError):
            self.full(task={**self.signed, "grant": grant})

    def test_jwt_signature_is_not_an_ed25519_owner_permission(self):
        proof = self.full()
        from ops import rea_secure_protocol_20261022 as bridge
        self.assertTrue(proof["owner_button_and_oidc_preview_only"])
        # Original bridge never checks this proof instead of owner signature.
        with self.assertRaises(bridge.SecureBridgeError):
            bridge.validate_inner({
                "protocol": 1, "nonce": "c"*32,
                "expires_at": (self.now + timedelta(minutes=10)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "steps": [{"tool": "inspect_with_objdump",
                           "arguments": {"path": "/tmp/p311"}}],
            }, {"inspect_with_objdump": {"inputSchema": {"type": "object"}}},
                {"list_unknowns"}, now=self.now)

    def test_oidc_source_is_pinned_and_not_caller_selected(self):
        with mock.patch.object(oidc, "_read_official_json", side_effect=[
                {"issuer": oidc.ISSUER, "jwks_uri": "https://attacker.example/jwks"}]):
            with self.assertRaises(oidc.GithubOIDCError):
                oidc.load_official_github_jwks()
        with self.assertRaises(oidc.GithubOIDCError):
            oidc._read_official_json("https://attacker.example/jwks")

    def test_immutable_and_previous_github_subject_forms_supported(self):
        old_sub = "repo:martaxi-boss/VPS:environment:" + oidc.ENVIRONMENT
        self.assertIs(self.verify(
            self.mint(claims={**self.claims, "sub": old_sub}))[
            "attested_oidc_preview_only"], True)
        with self.assertRaises(oidc.GithubOIDCError):
            self.verify(self.mint(claims={**self.claims,
                                         "sub": "repo:attacker/VPS:environment:"+
                                                oidc.ENVIRONMENT}))


if __name__ == "__main__":
    unittest.main()

