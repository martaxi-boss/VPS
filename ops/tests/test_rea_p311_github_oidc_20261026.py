"""P311 GitHub OIDC cryptographic proof tests with ONLY ephemeral fixture keys.

No OIDC token from the real owner's GitHub account is captured, uploaded or
printed. No environment rules are changed and no SSH or MCP calls occur.
"""
import base64
from datetime import datetime, timedelta, timezone
import json
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

