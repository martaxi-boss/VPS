"""Offline, fail-closed integration tests for the disabled P311 staged validator."""
import base64
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ops import rea_scoped_approval_20261026 as scoped
from ops import rea_secure_protocol_20261022 as secure


class P311SealedTaskAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch("pathlib.Path.home", return_value=Path(self.tmp.name))
        patch.start()
        self.addCleanup(patch.stop)
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        verifier = secure._private_directory() / "owner-approval-public.pem"
        verifier.write_bytes(pub)
        verifier.chmod(0o600)
        # A grant MUST NOT become active unless its revocation registry exists.
        self.revocation_registry = secure._private_directory() / "revoked-p311-grants"
        self.revocation_registry.mkdir(mode=0o700)
        self.job_root = "/opt/rea-reversa/rea/.rea-private/jobs/p311-readonly-analysis"
        self.registry = {}
        for name in ("list_unknowns", "inspect_with_objdump",
                     "recover_javascript_sources", "install_adb_package", "close_binary"):
            fx = secure.AUDITED_EFFECTS[name]
            self.registry[name] = {
                "inputSchema": {"type": "object"},
                "annotations": {
                    "readOnlyHint": not bool(fx),
                    "destructiveHint": bool(fx.intersection(
                        {"mayDiscardData", "executesForeignCode", "mutatesDevice"})),
                    "openWorldHint": bool(fx.intersection(
                        {"launchesProcess", "accessesNetwork"})),
                }
            }
        patches = {n: secure.arguments_sha256(d["inputSchema"])
                   for n, d in self.registry.items()}
        pin = mock.patch.dict(secure.AUDITED_SCHEMA_SHA256, patches)
        pin.start()
        self.addCleanup(pin.stop)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        timestamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.grant = {
            "purpose": scoped.PURPOSE,
            "grant_id": "b" * 32,
            "project": "Engenharia Reversa",
            "task_id": "P311-SAFE-FIXTURE",
            "origin": scoped.ORIGIN,
            "not_before": timestamp(self.now - timedelta(minutes=1)),
            "expires_at": timestamp(self.now + timedelta(hours=2)),
            "artifact_root": self.job_root,
            "allowed_tools": ["inspect_with_objdump", "recover_javascript_sources"],
            "permitted_effects": ["launchesProcess", "mutatesSession", "writesFilesystem"],
        }
        self.scope = self._scope()
        self.safe = {"path": self.job_root + "/sample.bin"}
        self.steps = [
            {"tool": "inspect_with_objdump", "arguments": self.safe},
            {"tool": "recover_javascript_sources", "arguments": self.safe},
        ]

    def _scope(self, grant=None, **changes):
        grant = self.grant if grant is None else grant
        obj = {
            "grant": grant,
            "owner_signature": base64.b64encode(
                self.key.sign(scoped.canonical_bytes(grant))).decode("ascii"),
            "project": grant["project"],
            "task_id": grant["task_id"],
            "origin": grant["origin"],
            "artifact_root": grant["artifact_root"],
        }
        obj.update(changes)
        return obj

    def _request(self, steps=None):
        return {
            "protocol": 1,
            "nonce": "1" * 32,
            "expires_at": (self.now + timedelta(minutes=20)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "steps": self.steps if steps is None else steps,
        }

    def _validate(self, scope=None, steps=None):
        return secure.validate_inner(
            self._request(steps), self.registry, {"list_unknowns"},
            now=self.now, scoped_task=self.scope if scope is None else scope)

    def test_default_bridge_still_rejects_unsigned_workspace_and_sensitive(self):
        with self.assertRaises(secure.SecureBridgeError):
            self._validate()
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "disabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self._validate()

    def test_explicit_staged_optin_uses_signed_grant_for_workspace_and_sensitive(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            self.assertEqual(["workspace", "sensitive"], self._validate())

    def test_read_only_original_does_not_need_scoped_signature(self):
        read = [{"tool": "list_unknowns", "arguments": {}}]
        self.assertEqual(["read"], secure.validate_inner(
            self._request(read), self.registry, {"list_unknowns"}, now=self.now))

    def test_false_or_other_owner_signature_is_not_accepted(self):
        invalid = dict(self.scope, owner_signature="A" * 88)
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self._validate(scope=invalid)

    def test_cross_project_context_is_rejected(self):
        wrong = dict(self.scope, project="AnotherProject")
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self._validate(scope=wrong)

    def test_bad_path_and_destructive_effects_remain_protected(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            outside = [{"tool": "inspect_with_objdump",
                        "arguments": {"path": "/usr/bin/true"}}]
            with self.assertRaises(secure.SecureBridgeError):
                self._validate(steps=outside)
            dangerous_grant = dict(self.grant, allowed_tools=["install_adb_package"])
            dangerous = [{"tool": "install_adb_package", "arguments": self.safe}]
            with self.assertRaises(secure.SecureBridgeError):
                self._validate(scope=self._scope(dangerous_grant), steps=dangerous)

    def test_close_binary_cannot_use_task_grant(self):
        signed = dict(self.grant, allowed_tools=["close_binary"])
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self._validate(scope=self._scope(signed), steps=[
                    {"tool": "close_binary", "arguments": self.safe}])

    def _embedded_request(self, scope=None, steps=None):
        body = self._request(steps)
        body["scoped_task"] = self.scope if scope is None else scope
        return body

    def test_encrypted_inner_envelope_accepts_signed_task_only_on_optin(self):
        body = self._embedded_request()
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            self.assertEqual(["workspace", "sensitive"], secure.validate_inner(
                body, self.registry, {"list_unknowns"}, now=self.now))
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "disabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                secure.validate_inner(body, self.registry, {"list_unknowns"},
                                      now=self.now)

    def test_embedded_scope_does_not_admit_forged_or_reused_grants(self):
        forged = self._embedded_request(dict(self.scope, owner_signature="A" * 88))
        swapped = self._embedded_request(dict(self.scope, task_id="OTHER"))
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            for body in (forged, swapped):
                with self.subTest(body=body["scoped_task"]["task_id"]), self.assertRaises(
                        secure.SecureBridgeError):
                    secure.validate_inner(body, self.registry, {"list_unknowns"},
                                          now=self.now)

    def test_embedded_scope_rejects_malformed_and_duplicate_context(self):
        bad = self._embedded_request("true")
        extra = self._embedded_request()
        extra["invented"] = True
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            for body in (bad, extra):
                with self.subTest(body=body), self.assertRaises(
                        secure.SecureBridgeError):
                    secure.validate_inner(body, self.registry, {"list_unknowns"},
                                          now=self.now)
            with self.assertRaises(secure.SecureBridgeError):
                secure.validate_inner(self._embedded_request(),
                                      self.registry, {"list_unknowns"},
                                      now=self.now, scoped_task=self.scope)

    def test_legacy_signed_requests_unchanged_even_if_scoped_mode_opted_in(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            # Enabling the feature never turns an unsigned request into consent.
            with self.assertRaises(secure.SecureBridgeError):
                secure.validate_inner(self._request(), self.registry,
                                      {"list_unknowns"}, now=self.now)
            from ops.tests.test_rea_secure_protocol_20261022 import approved
            step = {"tool": "inspect_with_objdump", "arguments": self.safe,
                    "authorization": approved("inspect_with_objdump", self.safe)}
            self.assertEqual(["workspace"], secure.validate_inner(
                self._request([step]), self.registry, {"list_unknowns"},
                now=self.now))

    def test_revocation_marker_blocks_future_scoped_batches(self):
        directory = secure._private_directory() / "revoked-p311-grants"
        self.assertEqual(directory, self.revocation_registry)
        marker = directory / (self.grant["grant_id"] + ".revoked")
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            self.assertEqual(["workspace", "sensitive"], self._validate())
            marker.write_text("revoked\\n", encoding="ascii")
            marker.chmod(0o600)
            with self.assertRaises(secure.SecureBridgeError):
                self._validate()

    def test_full_rsa_aes_authenticated_envelope_contains_signed_scope(self):
        import json
        from cryptography.hazmat.primitives.asymmetric import rsa
        request_private = rsa.generate_private_key(public_exponent=65537,
                                                   key_size=3072)
        destination = secure._private_directory() / "request-private.pem"
        destination.write_bytes(request_private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        destination.chmod(0o600)
        response_private = rsa.generate_private_key(public_exponent=65537,
                                                    key_size=3072)
        to_b64 = lambda key: base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii")
        request = self._embedded_request()
        sealed = secure.seal_for_client(
            request, to_b64(request_private), to_b64(response_private))
        ciphertext = json.dumps(sealed, sort_keys=True)
        self.assertNotIn(self.grant["project"], ciphertext)
        self.assertNotIn(self.grant["task_id"], ciphertext)
        recovered = secure.unseal(sealed, to_b64(response_private))
        self.assertEqual(request, recovered)
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            self.assertEqual(["workspace", "sensitive"], secure.validate_inner(
                recovered, self.registry, {"list_unknowns"}, now=self.now))
        with self.assertRaises(secure.SecureBridgeError):
            secure.unseal(sealed, to_b64(request_private))
        swapped = dict(sealed)
        swapped["ciphertext"] = base64.b64encode(
            base64.b64decode(swapped["ciphertext"], validate=True)[:-1] +
            bytes([base64.b64decode(swapped["ciphertext"], validate=True)[-1] ^ 1])
        ).decode("ascii")
        with self.assertRaises(secure.SecureBridgeError):
            secure.unseal(swapped, to_b64(response_private))

    def test_expired_task_permission_and_unsupported_schema_fail_closed(self):
        stale = dict(self.grant)
        stale["expires_at"] = (self.now - timedelta(seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self._validate(scope=self._scope(stale))


if __name__ == "__main__":
    unittest.main()

