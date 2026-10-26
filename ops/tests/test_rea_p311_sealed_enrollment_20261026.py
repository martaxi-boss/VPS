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


class P311SealedEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
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

    def build(self, *, task=None, nonce=None, expiry=None):
        inner = {
            "protocol": 1,
            "nonce": self.nonce if nonce is None else nonce,
            "expires_at": self.format_time(self.now + timedelta(minutes=25))
                if expiry is None else expiry,
            "signed_task": self.task if task is None else task,
        }
        return {
            "version": 1, "action": "sealed_task_enroll",
            "sealed": secure.seal_for_client(inner, self.recipient_key, self.response_key),
            "response_key": self.response_key,
        }

    def enroll(self, data=None):
        return bridge.p311_enroll_sealed_owner_task(
            self.build() if data is None else data, self.registry,
            {"list_unknowns"}, now=self.now)

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

    def test_default_off_cannot_register_even_with_valid_crypto(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "disabled"}):
            with self.assertRaises(ValueError):
                self.enroll()
        self.assertFalse(self.registry_dir.exists())

    def test_invalid_or_forged_owner_signature_rejected_before_nonce_claim(self):
        tampered = dict(self.task, owner_signature="A" * 88)
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(scoped.ScopedApprovalError):
                self.enroll(self.build(task=tampered))
        self.assertFalse(self.registry_dir.exists())
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
        self.assertFalse(self.registry_dir.exists())
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
            registered = bridge.p311_enroll_sealed_owner_task(
                self.build(), catalog, {"list_unknowns"}, now=self.now)
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
                bridge.p311_enroll_sealed_owner_task(
                    self.build(), catalog, {"list_unknowns"}, now=self.now)
        self.assertFalse(self.registry_dir.exists())

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

