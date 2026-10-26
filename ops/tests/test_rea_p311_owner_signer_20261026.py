"""P311 signer/offline owner consent tests: ephemeral test key, NEVER real owner key."""
import base64
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ops import rea_scoped_approval_20261026 as scoped


SOURCE = Path(__file__).resolve().parents[2] / "rea-linux" / "owner" / "p311_sign_task_grant.py"
SPEC = importlib.util.spec_from_file_location("rea_p311_signer_fixture", SOURCE)
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)


class OwnerTaskConsentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.owner = Ed25519PrivateKey.generate()
        self.owner_file = self.folder / "rea-owner-private.pem"
        self.owner_file.write_bytes(self.owner.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.owner_file.chmod(0o600)
        self.pub = self.owner.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        fmt = lambda ts: ts.strftime(signer.TIME_FORMAT)
        self.grant = {
            "purpose": signer.PURPOSE, "origin": signer.ORIGIN,
            "grant_id": "1" * 32, "project": "Engenharia Reversa",
            "task_id": "P311-SAMPLE-ANALYSIS",
            "not_before": fmt(self.now - timedelta(minutes=1)),
            "expires_at": fmt(self.now + timedelta(hours=4)),
            "artifact_root": "/opt/rea-reversa/rea/.rea-private/jobs/p311-private",
            "allowed_tools": ["inspect_with_objdump", "recover_javascript_sources"],
            "permitted_effects": ["launchesProcess", "mutatesSession",
                                  "writesFilesystem"],
        }
        self.args = {"path": self.grant["artifact_root"] + "/test.bin"}

    def sign(self, grant=None, **kwargs):
        return signer.sign_task(self.grant if grant is None else grant,
                                self.owner_file, approved=True,
                                now=self.now, **kwargs)

    def test_existing_owner_key_can_approve_whole_task_once(self):
        signed = self.sign()
        self.assertTrue(scoped.verify_task_grant(
            signed["grant"], signed["owner_signature"], self.pub,
            project=signed["project"], task_id=signed["task_id"],
            origin=signed["origin"], artifact_root=signed["artifact_root"],
            tool="recover_javascript_sources",
            audited_effects=frozenset({"mutatesSession", "launchesProcess",
                                       "writesFilesystem"}),
            current_risk="sensitive", arguments=self.args, now=self.now))
        self.assertNotIn("private_key", signed)
        self.assertEqual(set(signed), {"grant", "owner_signature",
                                      "project", "task_id", "origin", "artifact_root"})

    def test_refusal_never_signs(self):
        with self.assertRaises(signer.ApprovalError):
            signer.sign_task(self.grant, self.owner_file,
                             approved=False, now=self.now)

    def test_invalid_wrong_project_or_outside_artifact_root_refused(self):
        for patch in ({"project": ""}, {"artifact_root": "/etc"},
                      {"origin": "attacker/repo:main"},
                      {"grant_id": "nope"}):
            with self.subTest(patch=patch), self.assertRaises(signer.ApprovalError):
                self.sign({**self.grant, **patch})

    def test_forbidden_tools_and_effects_not_signed(self):
        for patch in ({"allowed_tools": ["install_adb_package"]},
                      {"permitted_effects": ["executesForeignCode"]},
                      {"allowed_tools": ["close_binary"]},
                      {"allowed_tools": ["recover_javascript_sources",
                                         "inspect_with_objdump"]}):
            with self.subTest(patch=patch), self.assertRaises(signer.ApprovalError):
                self.sign({**self.grant, **patch})

    def test_expired_or_overly_long_grant_rejected(self):
        f = lambda d: d.strftime(signer.TIME_FORMAT)
        for end in (self.now - timedelta(seconds=1),
                    self.now + timedelta(days=9)):
            with self.subTest(end=end), self.assertRaises(signer.ApprovalError):
                self.sign({**self.grant, "expires_at": f(end)})

    def test_private_key_mode_and_symlink_enforced(self):
        self.owner_file.chmod(0o644)
        with self.assertRaises(signer.ApprovalError):
            self.sign()
        self.owner_file.chmod(0o600)
        alias = self.folder / "link.pem"
        alias.symlink_to(self.owner_file)
        with self.assertRaises(signer.ApprovalError):
            signer.sign_task(self.grant, alias, approved=True, now=self.now)

    def test_tampered_signed_manifest_fails_vps_verification(self):
        signed = self.sign()
        modified = {**signed["grant"], "task_id": "ANOTHER"}
        with self.assertRaises(scoped.ScopedApprovalError):
            scoped.verify_task_grant(
                modified, signed["owner_signature"], self.pub,
                project=modified["project"], task_id=modified["task_id"],
                origin=modified["origin"], artifact_root=modified["artifact_root"],
                tool="recover_javascript_sources",
                audited_effects=frozenset({"mutatesSession", "launchesProcess",
                                           "writesFilesystem"}),
                current_risk="sensitive", arguments=self.args, now=self.now)

    def test_duplicate_json_fields_rejected(self):
        manifest = self.folder / "duplicate.json"
        manifest.write_text('{"grant_id":"a","grant_id":"b"}', encoding="utf-8")
        with self.assertRaises(signer.ApprovalError):
            signer._load_manifest(manifest)

    def test_cli_yes_is_one_simple_confirmation_with_private_output(self):
        manifest = self.folder / "proposal.json"
        output = self.folder / "signed.json"
        manifest.write_text(json.dumps(self.grant), encoding="utf-8")
        with mock.patch("builtins.input", return_value="sim"), mock.patch(
                "sys.stdout") as stdout:
            self.assertEqual(0, signer.main([
                "--grant", str(manifest), "--private-key", str(self.owner_file),
                "--output", str(output)]))
        self.assertTrue(output.is_file())
        self.assertEqual(0o600, output.stat().st_mode & 0o777)
        saved = json.loads(output.read_text())
        self.assertEqual(self.sign()["owner_signature"], saved["owner_signature"])
        with self.assertRaises(FileExistsError):
            signer._save_new_private(output, saved)
        self.assertNotIn("private_key", saved)

    def test_cli_no_never_writes_grant(self):
        manifest = self.folder / "proposal.json"
        output = self.folder / "signed-no.json"
        manifest.write_text(json.dumps(self.grant), encoding="utf-8")
        with mock.patch("builtins.input", return_value="nao"), mock.patch("sys.stdout"):
            self.assertEqual(1, signer.main([
                "--grant", str(manifest), "--private-key", str(self.owner_file),
                "--output", str(output)]))
        self.assertFalse(output.exists())

    def test_owner_one_sim_signed_grant_passes_existing_sealed_policy(self):
        from ops import rea_secure_protocol_20261022 as secure
        source = secure.AUDITED_EFFECTS["import_managed_reconstruction"]
        self.assertEqual(frozenset({"mutatesSession"}), source)
        grant = {**self.grant, "allowed_tools": ["import_managed_reconstruction"]}
        signed = self.sign(grant)
        target = {"path": grant["artifact_root"] + "/sample.bin"}
        descriptor = {
            "inputSchema": {"type": "object"},
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
            },
        }
        with mock.patch("pathlib.Path.home", return_value=self.folder):
            public_path = secure._private_directory() / "owner-approval-public.pem"
            public_path.write_bytes(self.pub)
            public_path.chmod(0o600)
            revoked = secure._private_directory() / "revoked-p311-grants"
            revoked.mkdir(mode=0o700)
            with mock.patch.dict(secure.AUDITED_SCHEMA_SHA256, {
                "import_managed_reconstruction":
                    secure.arguments_sha256(descriptor["inputSchema"])}), mock.patch.dict(
                        os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
                body = {
                    "protocol": 1,
                    "nonce": "e" * 32,
                    "expires_at": (self.now + timedelta(minutes=30)).strftime(
                        signer.TIME_FORMAT),
                    "steps": [{
                        "tool": "import_managed_reconstruction",
                        "arguments": target,
                    }],
                    "scoped_task": signed,
                }
                self.assertEqual(["sensitive"], secure.validate_inner(
                    body, {"import_managed_reconstruction": descriptor},
                    set(), now=self.now))
                (revoked / (grant["grant_id"] + ".revoked")).write_text("no\n")
                (revoked / (grant["grant_id"] + ".revoked")).chmod(0o600)
                with self.assertRaises(secure.SecureBridgeError):
                    secure.validate_inner(body, {
                        "import_managed_reconstruction": descriptor}, set(),
                        now=self.now)

    def test_private_output_directory_required(self):
        dest = self.folder / "signed.json"
        self.folder.chmod(0o755)
        with self.assertRaises(signer.ApprovalError):
            signer._save_new_private(dest, self.sign())
        self.folder.chmod(0o700)


if __name__ == "__main__":
    unittest.main()

