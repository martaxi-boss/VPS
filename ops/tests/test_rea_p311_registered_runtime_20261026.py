"""P311 full 208-tool sealed request resolves private signed-grant ID.

This is an offline rehearsal of the existing bridge admission only: it does
NOT make a real MCP tools/call, connect to VPS or use user's signing key.
"""
import base64
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ops import rea_secure_protocol_20261022 as secure
from ops import rea_scoped_approval_20261026 as scoped


class P311RegisteredRuntimeAdmittanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch("pathlib.Path.home", return_value=Path(self.tmp.name))
        p.start()
        self.addCleanup(p.stop)
        self.private = secure._private_directory()
        self.owner = Ed25519PrivateKey.generate()
        self.public = self.owner.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        verifier = self.private / "owner-approval-public.pem"
        verifier.write_bytes(self.public)
        verifier.chmod(0o600)
        self.revoked = self.private / "revoked-p311-grants"
        self.revoked.mkdir(mode=0o700)
        self.registered = self.private / "approved-p311-tasks"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        fmt = lambda x: x.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.artifacts = "/opt/rea-reversa/rea/.rea-private/jobs/p311-registry-test"
        tools = ["import_managed_reconstruction", "inspect_with_objdump"]
        effects = sorted(set().union(*(secure.AUDITED_EFFECTS[n] for n in tools)))
        self.grant = {
            "purpose": scoped.PURPOSE, "grant_id": "f" * 32,
            "project": "Engenharia Reversa", "task_id": "P311-ONE-GRANT",
            "origin": scoped.ORIGIN, "artifact_root": self.artifacts,
            "not_before": fmt(self.now - timedelta(minutes=1)),
            "expires_at": fmt(self.now + timedelta(hours=4)),
            "allowed_tools": tools,
            "permitted_effects": effects,
        }
        self.signed = {
            "grant": self.grant, "owner_signature": base64.b64encode(
                self.owner.sign(scoped.canonical_bytes(self.grant))).decode("ascii"),
            "project": self.grant["project"], "task_id": self.grant["task_id"],
            "origin": self.grant["origin"], "artifact_root": self.artifacts,
        }
        self.contracts = {
            "inspect_with_objdump":
                (secure.AUDITED_EFFECTS["inspect_with_objdump"], "workspace"),
            "import_managed_reconstruction":
                (secure.AUDITED_EFFECTS["import_managed_reconstruction"], "sensitive"),
        }
        self.registry = {}
        for name, fx in secure.AUDITED_EFFECTS.items():
            self.registry[name] = {
                "inputSchema": {"type": "object"},
                "annotations": {
                    "readOnlyHint": not bool(fx),
                    "destructiveHint": bool(fx.intersection(
                        {"mayDiscardData", "executesForeignCode", "mutatesDevice"})),
                    "openWorldHint": bool(fx.intersection(
                        {"launchesProcess", "accessesNetwork"})),
                },
            }
        self.assertEqual(208, len(self.registry))
        digest = secure.arguments_sha256({"type": "object"})
        policy = mock.patch.dict(secure.AUDITED_SCHEMA_SHA256,
                                 {n: digest for n in self.registry}, clear=True)
        policy.start()
        self.addCleanup(policy.stop)
        scoped.register_signed_task_grant(
            self.signed, self.public, private_registry_dir=self.registered,
            revocation_dir=self.revoked, trusted_contracts=self.contracts,
            now=self.now)
        self.params = {"path": self.artifacts + "/inert-sample.bin"}
        from ops.tests.test_rea_secure_protocol_20261022 import approved
        # Workspace uses its existing independent authorization. Only
        # the sensitive operation can reuse the GitHub-reviewed task grant.
        self.body = {
            "protocol": 1, "nonce": "a" * 32,
            "expires_at": fmt(self.now + timedelta(minutes=30)),
            "steps": [
                {"tool": "inspect_with_objdump", "arguments": self.params,
                 "authorization": approved("inspect_with_objdump", self.params)},
                {"tool": "import_managed_reconstruction", "arguments": self.params},
            ],
            "scoped_task_id": self.grant["grant_id"],
        }

    def valid(self, body=None):
        return secure.validate_inner(
            self.body if body is None else body, self.registry,
            {"list_unknowns"}, now=self.now)

    def test_github_registered_grant_applies_only_to_sensitive_not_workspace(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            self.assertEqual(["workspace", "sensitive"], self.valid())
            # A later request with its own nonce can reuse owner consent.
            another = dict(self.body, nonce="b" * 32)
            self.assertEqual(["workspace", "sensitive"], self.valid(another))
        self.assertNotIn("owner_signature", self.body)
        self.assertNotIn("grant", self.body)
        self.assertIn("authorization", self.body["steps"][0])
        self.assertNotIn("authorization", self.body["steps"][1])

    def test_inactive_policy_still_rejects_registered_reference(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "disabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self.valid()

    def test_unknown_or_invalid_reference_does_not_authorize_tools(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            for token in ("0" * 32, "../../../etc/passwd", "bogus", None):
                with self.subTest(token=token), self.assertRaises(secure.SecureBridgeError):
                    self.valid(dict(self.body, scoped_task_id=token))

    def test_cannot_mix_unsigned_grant_blob_with_registry_reference(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            extra = dict(self.body, scoped_task=self.signed)
            with self.assertRaises(secure.SecureBridgeError):
                self.valid(extra)

    def test_revoking_registered_owner_permission_blocks_next_batch(self):
        marker = self.revoked / (self.grant["grant_id"] + ".revoked")
        marker.write_text("revoked\n", encoding="ascii")
        marker.chmod(0o600)
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self.valid()

    def test_tamper_with_signed_private_grant_file_is_rejected(self):
        path = self.registered / (self.grant["grant_id"] + ".json")
        raw = path.read_bytes()
        path.write_bytes(raw + b"\n")
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self.valid()

    def test_request_path_cannot_escape_signed_project(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            bad = dict(self.body, steps=[
                {"tool": "inspect_with_objdump", "arguments": {"path": "/etc/passwd"}}])
            with self.assertRaises(secure.SecureBridgeError):
                self.valid(bad)

    def test_old_individually_authorized_read_still_works(self):
        read = dict(self.body, steps=[{"tool": "list_unknowns", "arguments": {}}])
        read.pop("scoped_task_id")
        self.assertEqual(["read"], self.valid(read))


if __name__ == "__main__":
    unittest.main()

