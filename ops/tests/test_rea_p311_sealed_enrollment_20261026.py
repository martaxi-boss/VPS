"""Offline integration for P311 encrypted enrollment via the EXISTING REA bridge.

No GitHub request is created, no SSH or MCP tools/call, no owner key is used.
Only isolated test keys and a temporary private filesystem are exercised.
"""
import base64
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import hashlib
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Bridge has a historical plain import used by the existing production workflow.
# Put its containing folder on the *test process only* import path.
OPS = Path(__file__).resolve().parents[1]
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
import rea_mobile_mcp_bridge_20261022 as bridge
import rea_secure_protocol_20261022 as secure
from ops import rea_scoped_approval_20261026 as scoped
from ops import rea_p311_owner_gate_20261026 as owner_gate


class P311SealedEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # The existing Actions SSH bridge always captures encrypted results.
        # Test this trusted server option explicitly, not as a JSON field.
        capture = mock.patch.dict(os.environ, {"REA_MOBILE_ENVELOPE_CAPTURE": "1"})
        capture.start()
        self.addCleanup(capture.stop)
        self.root = Path(self.temp.name)
        home = mock.patch("pathlib.Path.home", return_value=self.root)
        home.start()
        self.addCleanup(home.stop)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.format_time = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.private = secure._private_directory()
        self.owner = Ed25519PrivateKey.generate()
        self.pub = self.owner.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        verifier = self.private / "owner-approval-public.pem"
        verifier.write_bytes(self.pub)
        verifier.chmod(0o600)
        self.revocations = self.private / "revoked-p311-grants"
        self.revocations.mkdir(mode=0o700)
        self.request_private = rsa.generate_private_key(public_exponent=65537,
                                                        key_size=3072)
        keyfile = self.private / "request-private.pem"
        keyfile.write_bytes(self.request_private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        keyfile.chmod(0o600)
        self.reply_private = rsa.generate_private_key(public_exponent=65537,
                                                      key_size=3072)
        spki64 = lambda private: base64.b64encode(
            private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode("ascii")
        self.recipient_key = spki64(self.request_private)
        self.response_key = spki64(self.reply_private)
        self.registry = {
            name: {"inputSchema": {"type": "object"},
                   "annotations": {
                       "readOnlyHint": not bool(flags),
                       "destructiveHint": bool(flags.intersection({
                           "mayDiscardData", "executesForeignCode", "mutatesDevice"
                       })),
                       "openWorldHint": bool(flags.intersection({
                           "launchesProcess", "accessesNetwork"
                       }))
                   }}
            for name, flags in secure.AUDITED_EFFECTS.items()
        }
        self.assertEqual(208, len(self.registry))
        digest = secure.arguments_sha256({"type": "object"})
        patch = mock.patch.dict(secure.AUDITED_SCHEMA_SHA256,
                                {name: digest for name in self.registry},
                                clear=True)
        patch.start()
        self.addCleanup(patch.stop)
        root = "/opt/rea-reversa/rea/.rea-private/jobs/p311-sealed-enrollment"
        tools = ["import_managed_reconstruction", "inspect_with_objdump"]
        effects = sorted(set().union(*(secure.AUDITED_EFFECTS[n] for n in tools)))
        self.grant = {
            "purpose": scoped.PURPOSE, "grant_id": "9" * 32,
            "project": "Engenharia Reversa", "task_id": "P311-ENROLLED-APPROVED",
            "origin": scoped.ORIGIN, "artifact_root": root,
            "allowed_tools": tools, "permitted_effects": effects,
            "not_before": self.format_time(self.now - timedelta(minutes=1)),
            "expires_at": self.format_time(self.now + timedelta(hours=2)),
        }
        signed = base64.b64encode(
            self.owner.sign(scoped.canonical_bytes(self.grant))).decode("ascii")
        self.task = {
            "grant": self.grant, "owner_signature": signed,
            "project": self.grant["project"], "task_id": self.grant["task_id"],
            "origin": self.grant["origin"], "artifact_root": self.grant["artifact_root"],
        }
        self.nonce = "c" * 32
        self.registry_dir = self.private / "approved-p311-tasks"
        self.registry_dir.mkdir(mode=0o700)
        self.run_id = 40385975218
        self.review_id = "b" * 32

    def build(self, *, task=None, nonce=None, expiry=None):
        inner = {
            "protocol": 1,
            "nonce": self.nonce if nonce is None else nonce,
            "expires_at": self.format_time(self.now + timedelta(minutes=25))
                if expiry is None else expiry,
            "signed_task": self.task if task is None else task,
            "review_run_id": self.run_id, "review_request_id": self.review_id,
        }
        return {
            "version": 1, "action": "sealed_task_enroll",
            "sealed": secure.seal_for_client(inner, self.recipient_key, self.response_key),
            "response_key": self.response_key,
        }

    def enroll(self, data=None, *, catalog=None):
        # The GitHub REST validation itself has its own explicit negative
        # tests. In bridge-only tests the trusted approval helper is mocked
        # and still must perform an independently verified owner registration.
        def trusted_review(run_id, request_id, signed_task, public, contracts,
                           *, github_token, private_registry_dir,
                           revocation_dir, now):
            self.assertEqual(self.run_id, run_id)
            self.assertEqual(self.review_id, request_id)
            self.assertEqual("g" * 48, github_token)
            grant_id = scoped.register_signed_task_grant(
                signed_task, public, private_registry_dir=private_registry_dir,
                revocation_dir=revocation_dir, trusted_contracts=contracts,
                now=now)
            return {"registered_button_only_offline_stage": True,
                    "grant_id": grant_id}
        with mock.patch.dict(os.environ, {
                "REA_P311_GITHUB_API_TOKEN": "g" * 48}), \
             mock.patch.object(owner_gate,
                               "enroll_owner_task_by_github_buttons_offline_only",
                               side_effect=trusted_review):
            return bridge.p311_enroll_sealed_owner_task(
                self.build() if data is None else data,
                self.registry if catalog is None else catalog,
                {"list_unknowns"}, now=self.now)


    def test_git_review_is_mandatory_even_for_valid_ed25519(self):
        with mock.patch.dict(os.environ, {
                "REA_P311_SCOPED_TASKS": "enabled",
                "REA_P311_GITHUB_API_TOKEN": ""},
                clear=False), \
             self.assertRaisesRegex(ValueError, "GitHub Actions read credential"):
            bridge.p311_enroll_sealed_owner_task(
                self.build(), self.registry, {"list_unknowns"}, now=self.now)
        self.assertEqual([], list(self.registry_dir.iterdir()))
        self.assertFalse((self.private / "consumed" / self.nonce).exists())

    def test_cannot_inject_untrusted_github_token_inside_encrypted_request(self):
        signed = self.build()
        with mock.patch.dict(os.environ, {
                "REA_P311_SCOPED_TASKS": "enabled",
                "REA_P311_GITHUB_API_TOKEN": ""},
                clear=False), \
             self.assertRaisesRegex(ValueError, "Invalid encrypted owner-task"):
            payload = secure.unseal(signed["sealed"], signed["response_key"])
            payload["github_token"] = "attacker-token"
            attack = dict(signed, sealed=secure.seal_for_client(
                payload, self.recipient_key, self.response_key))
            bridge.p311_enroll_sealed_owner_task(
                attack, self.registry, {"list_unknowns"}, now=self.now)
        self.assertEqual([], list(self.registry_dir.iterdir()))

    def test_wrong_review_id_rejected_before_any_nonce_spend(self):
        payload = secure.unseal(self.build()["sealed"], self.response_key)
        payload["review_request_id"] = "wrong"
        data = self.build()
        data["sealed"] = secure.seal_for_client(
            payload, self.recipient_key, self.response_key)
        with mock.patch.dict(os.environ, {
                "REA_P311_SCOPED_TASKS": "enabled",
                "REA_P311_GITHUB_API_TOKEN": "g"*48}), \
             self.assertRaisesRegex(ValueError, "review identity"):
            bridge.p311_enroll_sealed_owner_task(
                data, self.registry, {"list_unknowns"}, now=self.now)
        self.assertFalse((self.private / "consumed" / self.nonce).exists())


    def test_p311_workflow_passes_review_token_only_by_private_ssh_pipe(self):
        flow = (Path(__file__).resolve().parents[2] /
                ".github/workflows/rea-android-bridge-20261022.yml").read_text()
        self.assertIn("actions: read", flow)
        self.assertIn("REA_P311_REVIEW_RUNNER_TOKEN: $" + "{{ github.token }}", flow)
        self.assertIn('test "$request_action" = "sealed_task_enroll"', flow)
        self.assertIn('os.environ["REA_P311_GITHUB_API_TOKEN"]', flow)
        self.assertIn("rea_p311_owner_gate_20261026.py", flow)
        self.assertIn("rea_p311_github_oidc_20261026.py", flow)
        self.assertIn("trap 'rm -f", flow)
        self.assertNotIn("id-token: write", flow)
        self.assertIn('test "$request_action" = "sealed_task_enroll"', flow)
        self.assertIn("runtime_command=\"REA_P311_SCOPED_TASKS=enabled", flow)
        self.assertIn('if test "$request_action" = "sealed_task_enroll" ||', flow)
        self.assertIn("StrictHostKeyChecking=yes", flow)
        self.assertIn("127.0.0.1", bridge.URL)


    def test_private_registry_is_created_after_real_review_and_not_before(self):
        # Use the same independent signed-grant verifier stub as other bridge
        # tests, but start without the pre-existing private registry.
        self.registry_dir.rmdir()
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            result = self.enroll()
        self.assertEqual(self.grant["grant_id"], result["grant_id"])
        self.assertEqual(0o700, self.registry_dir.stat().st_mode & 0o777)

    def test_one_owner_signature_registers_encrypted_task_once(self):
        request = self.build()
        self.assertIs(request, bridge.validate(request))
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            result = self.enroll(request)
        self.assertTrue(result["registered"])
        self.assertEqual(self.grant["grant_id"], result["grant_id"])
        self.assertFalse(any(k in result for k in ("owner_signature", "private_key")))
        saved = self.registry_dir / (self.grant["grant_id"] + ".json")
        self.assertTrue(saved.is_file())
        self.assertEqual(0o600, saved.stat().st_mode & 0o777)
        self.assertEqual(self.task, json.loads(saved.read_text()))

    def test_no_encrypted_response_never_creates_a_grant_or_claims_nonce(self):
        request = self.build()
        with mock.patch.dict(os.environ, {
                "REA_P311_SCOPED_TASKS": "enabled",
                "REA_MOBILE_ENVELOPE_CAPTURE": "0"}):
            with self.assertRaisesRegex(ValueError, "Encrypted enrollment"):
                self.enroll(request)
        self.assertEqual([], list(self.registry_dir.iterdir()))
        self.assertFalse((self.private / "consumed" / self.nonce).exists())

    def test_default_off_cannot_register_even_with_valid_crypto(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "disabled"}):
            with self.assertRaises(ValueError):
                self.enroll()
        self.assertEqual([], list(self.registry_dir.iterdir()))

    def test_invalid_or_forged_owner_signature_rejected_before_nonce_claim(self):
        tampered = dict(self.task, owner_signature="A" * 88)
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(scoped.ScopedApprovalError):
                self.enroll(self.build(task=tampered))
        self.assertEqual([], list(self.registry_dir.iterdir()))
        self.assertFalse((self.private / "consumed" / self.nonce).exists())

    def test_nonce_replay_denied_and_existing_owner_task_never_replaced(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            self.enroll()
            saved = self.registry_dir / (self.grant["grant_id"] + ".json")
            before = saved.read_bytes()
            with self.assertRaises(secure.SecureBridgeError):
                self.enroll()
            with self.assertRaises(scoped.ScopedApprovalError):
                self.enroll(self.build(nonce="d" * 32))
            self.assertEqual(before, saved.read_bytes())

    def test_revoked_consent_and_missing_revocation_registry_fail_closed(self):
        marker = self.revocations / (self.grant["grant_id"] + ".revoked")
        marker.write_text("revoked\n")
        marker.chmod(0o600)
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(scoped.ScopedApprovalError):
                self.enroll()
        self.assertEqual([], list(self.registry_dir.iterdir()))
        marker.unlink()
        self.revocations.rmdir()
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(scoped.ScopedApprovalError):
                self.enroll()

    def test_outside_project_expiry_and_unknown_mcp_prohibited(self):
        outsider = dict(self.grant, artifact_root="/etc")
        outsider_task = dict(self.task, grant=outsider,
                             artifact_root=outsider["artifact_root"])
        forged = dict(self.grant, allowed_tools=["unregistered_tool"])
        forged_task = dict(self.task, grant=forged)
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            for task in (outsider_task, forged_task):
                with self.subTest(task=task), self.assertRaises(ValueError):
                    self.enroll(self.build(task=task, nonce="e" * 32))
            with self.assertRaises(ValueError):
                self.enroll(self.build(expiry=self.format_time(
                    self.now + timedelta(days=9))))

    def test_plaintext_and_malformed_outer_request_never_accepted(self):
        request = self.build()
        for patch in ({"signed_task": self.task}, {"authorization": True},
                      {"sealed": {"algorithm": "plaintext"}}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                bridge.validate({**request, **patch})

    def _synthetic_680_registry_and_manifest(self):
        # A synthetic 229-tool fixture preserves the real original source
        # release identity, but contains NO real new tool implementation.
        catalog = dict(self.registry)
        effects = dict(secure.AUDITED_EFFECTS)
        for i in range(21):
            name = "p311_only_test_680_tool_%02d" % i
            flags = frozenset({"mutatesSession"})
            effects[name] = flags
            catalog[name] = {
                "inputSchema": {"type": "object"},
                "annotations": {
                    "readOnlyHint": False, "destructiveHint": False,
                    "openWorldHint": False,
                },
            }
        self.assertEqual(229, len(catalog))
        digest = secure.arguments_sha256({"type": "object"})
        manifest = {
            "release": "rea-agents-6.8.0",
            "commit": "160d821ac9a0310afcb8d1fc427862dd6508add5",
            "tree": "15e6fec513dcce08cefdbcf441200986397e2793",
            "tools": {
                name: {"effects": sorted(flags), "input_schema_sha256": digest}
                for name, flags in effects.items()
            },
        }
        path = self.root / "p311-simulated-680-contract.json"
        path.write_bytes(json.dumps(manifest, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8"))
        path.chmod(0o600)
        return catalog, path

    def test_680_229_source_pinned_enrollment_accepts_owner_signed_known_tool(self):
        catalog, manifest = self._synthetic_680_registry_and_manifest()
        signature_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
        with mock.patch.object(secure, "RELEASE_680_MANIFEST_PATH", manifest), mock.patch.object(
                secure, "RELEASE_680_MANIFEST_SHA256", signature_hash), mock.patch.dict(
                os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            registered = self.enroll(catalog=catalog)
        self.assertEqual(self.grant["grant_id"], registered["grant_id"])
        self.assertEqual(0o600, (self.registry_dir /
                         (self.grant["grant_id"]+".json")).stat().st_mode & 0o777)

    def test_680_catalog_manifest_tampering_prevents_enrollment(self):
        catalog, manifest = self._synthetic_680_registry_and_manifest()
        original_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        with mock.patch.object(secure, "RELEASE_680_MANIFEST_PATH", manifest), mock.patch.object(
                secure, "RELEASE_680_MANIFEST_SHA256", original_digest), mock.patch.dict(
                os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self.enroll(catalog=catalog)
        self.assertEqual([], list(self.registry_dir.iterdir()))

    def test_success_result_is_encrypted_on_existing_actions_return(self):
        request = self.build()
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            result = self.enroll(request)
        rawpath = self.root / "private-raw-output.txt"
        requestpath = self.root / "request.json"
        encryptedpath = self.root / "encrypted-result.json"
        raw = json.dumps(result, sort_keys=True).encode()
        rawpath.write_text(
            "REA_P311_OWNER_ENROLLMENT=PASS\n"
            "REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode() + "\n")
        requestpath.write_text(json.dumps(request))
        with redirect_stdout(io.StringIO()):
            bridge.encrypt_result(rawpath, requestpath, encryptedpath)
        artifact = json.loads(encryptedpath.read_text())
        self.assertEqual("RSA-OAEP-SHA256+A256GCM", artifact["algorithm"])
        self.assertNotIn(self.grant["task_id"], encryptedpath.read_text())
        self.assertNotIn(self.grant["grant_id"], encryptedpath.read_text())


if __name__ == "__main__":
    unittest.main()

