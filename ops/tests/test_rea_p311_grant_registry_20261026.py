"""No-network P311 tests for the private owner-approved task registry.

TemporaryDirectory represents the *existing* private SSH-home policy, not a
new service. All keys here are ephemeral fixtures, not owner credentials.
"""
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ops import rea_scoped_approval_20261026 as scoped
from ops import rea_secure_protocol_20261022 as secure


class P311PrivateOwnerGrantRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.revoked = self.home / "revoked-p311-grants"
        self.revoked.mkdir(mode=0o700)
        self.registry = self.home / "approved-p311-tasks"
        self.signer = Ed25519PrivateKey.generate()
        self.public = self.signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        stamp = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
        root = "/opt/rea-reversa/rea/.rea-private/jobs/p311-owner-approved"
        self.grant = {
            "purpose": scoped.PURPOSE, "origin": scoped.ORIGIN,
            "grant_id": "d" * 32,
            "project": "Engenharia Reversa", "task_id": "P311-LONG-AUDIT",
            "artifact_root": root,
            "not_before": stamp(self.now - timedelta(minutes=1)),
            "expires_at": stamp(self.now + timedelta(hours=3)),
            "allowed_tools": ["import_managed_reconstruction", "inspect_with_objdump"],
            "permitted_effects": ["launchesProcess", "mutatesSession"],
        }
        self.contracts = {
            "import_managed_reconstruction": (
                secure.AUDITED_EFFECTS["import_managed_reconstruction"], "sensitive"),
            "inspect_with_objdump": (
                secure.AUDITED_EFFECTS["inspect_with_objdump"], "workspace"),
        }
        self.approved = self.sign(self.grant)

    def sign(self, grant):
        signature = base64.b64encode(self.signer.sign(
            scoped.canonical_bytes(grant))).decode("ascii")
        return {
            "grant": grant, "owner_signature": signature,
            "project": grant["project"], "task_id": grant["task_id"],
            "origin": grant["origin"], "artifact_root": grant["artifact_root"],
        }

    def enroll(self, signed=None, **kwargs):
        return scoped.register_signed_task_grant(
            self.approved if signed is None else signed, self.public,
            private_registry_dir=self.registry, revocation_dir=self.revoked,
            trusted_contracts=self.contracts, now=self.now, **kwargs)

    def read(self, grant_id=None, **kwargs):
        return scoped.read_registered_task_grant(
            self.grant["grant_id"] if grant_id is None else grant_id,
            self.public, private_registry_dir=self.registry,
            revocation_dir=self.revoked, trusted_contracts=self.contracts,
            now=self.now, **kwargs)

    def test_valid_grant_is_registered_once_and_auto_found_later(self):
        self.assertFalse(self.registry.exists())
        self.assertEqual(self.grant["grant_id"], self.enroll())
        file = self.registry / (self.grant["grant_id"] + ".json")
        self.assertEqual(0o700, self.registry.stat().st_mode & 0o777)
        self.assertEqual(0o600, file.stat().st_mode & 0o777)
        self.assertEqual(self.approved, self.read())
        self.assertNotIn("private_key", file.read_text())
        self.assertNotIn("BEGIN PRIVATE KEY", file.read_text())

    def test_same_grant_is_never_overwritten(self):
        self.enroll()
        path = self.registry / (self.grant["grant_id"] + ".json")
        original = path.read_bytes()
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll()
        self.assertEqual(original, path.read_bytes())

    def test_fake_key_or_modified_consent_never_creates_registry(self):
        bad = dict(self.approved, owner_signature="A" * 88)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll(signed=bad)
        changed = {**self.approved, "project": "OtherProject"}
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll(signed=changed)
        self.assertFalse(self.registry.exists())

    def test_undeclared_effects_or_missing_source_contract_fails(self):
        extra = self.grant | {"permitted_effects":
                              ["launchesProcess", "mutatesSession", "writesFilesystem"]}
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll(signed=self.sign(extra))
        self.contracts.pop("import_managed_reconstruction")
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll()

    def test_revocation_stops_lookup_and_re_registration(self):
        self.enroll()
        marker = self.revoked / (self.grant["grant_id"] + ".revoked")
        marker.write_bytes(b"revoked\n")
        marker.chmod(0o600)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read()
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll()

    def test_expired_registration_disallowed_and_expired_lookup_fails(self):
        self.enroll()
        with self.assertRaises(scoped.ScopedApprovalError):
            scoped.read_registered_task_grant(
                self.grant["grant_id"], self.public,
                private_registry_dir=self.registry, revocation_dir=self.revoked,
                trusted_contracts=self.contracts,
                now=self.now + timedelta(days=8))

    def test_missing_or_mismatching_registry_file_fails_closed(self):
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read()
        self.enroll()
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read("e" * 32)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read("../../../etc/passwd")

    def test_tampering_with_registered_signature_is_denied(self):
        self.enroll()
        file = self.registry / (self.grant["grant_id"] + ".json")
        data = json.loads(file.read_text())
        data["task_id"] = "ALTERED"
        file.write_bytes(scoped.canonical_bytes(data))
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read()

    def test_noncanonical_or_world_readable_file_is_denied(self):
        self.enroll()
        file = self.registry / (self.grant["grant_id"] + ".json")
        original = file.read_bytes()
        file.write_bytes(original + b"\n")
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read()
        file.write_bytes(original)
        file.chmod(0o644)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read()

    def test_registry_and_approval_marker_symlinks_are_denied(self):
        self.enroll()
        file = self.registry / (self.grant["grant_id"] + ".json")
        other = self.home / "target"
        other.write_bytes(file.read_bytes())
        file.unlink()
        file.symlink_to(other)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read()
        file.unlink()
        self.registry.chmod(0o777)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.read()

    def test_missing_or_unsafe_revocation_registry_is_fail_closed(self):
        self.revoked.chmod(0o777)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll()
        self.revoked.chmod(0o700)
        self.revoked.rmdir()
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll()

    def test_registry_parent_must_be_private_existing_owner_home(self):
        self.home.chmod(0o755)
        with self.assertRaises(scoped.ScopedApprovalError):
            self.enroll()
        self.home.chmod(0o700)


if __name__ == "__main__":
    unittest.main()

