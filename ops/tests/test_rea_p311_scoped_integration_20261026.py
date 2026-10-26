"""P311 simplified: GitHub is mandatory only for sensitive task grants.

These are offline regressions, no real GitHub clicks, SSH, VPS or MCP calls.
"""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from ops import rea_secure_protocol_20261022 as secure


class P311SimplifiedSensitiveOnlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch("pathlib.Path.home", return_value=Path(self.tmp.name))
        p.start()
        self.addCleanup(p.stop)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.root = "/opt/rea-reversa/rea/.rea-private/jobs/p311-minimal"
        self.registry = {}
        for name in ("list_unknowns", "inspect_with_objdump",
                     "import_managed_reconstruction"):
            flags = secure.AUDITED_EFFECTS[name]
            self.registry[name] = {
                "inputSchema": {"type": "object"},
                "annotations": {
                    "readOnlyHint": not bool(flags),
                    "destructiveHint": bool(flags.intersection({
                        "mayDiscardData", "executesForeignCode", "mutatesDevice"
                    })),
                    "openWorldHint": bool(flags.intersection({
                        "launchesProcess", "accessesNetwork"
                    })),
                },
            }
        digest = secure.arguments_sha256({"type": "object"})
        policy = mock.patch.dict(
            secure.AUDITED_SCHEMA_SHA256,
            {n: digest for n in self.registry})
        policy.start()
        self.addCleanup(policy.stop)
        self.now_text = (self.now + timedelta(minutes=15)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        self.path = {"path": self.root + "/sample.bin"}

    def request(self, steps, **extra):
        return {
            "protocol": 1, "nonce": "a" * 32,
            "expires_at": self.now_text, "steps": steps, **extra,
        }

    def validate(self, payload, *, scope=None):
        return secure.validate_inner(
            payload, self.registry, {"list_unknowns"},
            now=self.now, scoped_task=scope)

    def test_read_only_no_new_approval_or_signature(self):
        self.assertEqual(["read"], self.validate(self.request([
            {"tool": "list_unknowns", "arguments": {}}
        ])))

    def test_workspace_keeps_existing_single_tool_authorization(self):
        from ops.tests.test_rea_secure_protocol_20261022 import approved
        step = {"tool": "inspect_with_objdump", "arguments": self.path}
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self.validate(self.request([step]))
            self.assertEqual(["workspace"], self.validate(self.request([
                {**step, "authorization": approved(
                    "inspect_with_objdump", self.path)}
            ])))

    def test_sensitive_without_registered_button_grant_denied(self):
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}):
            with self.assertRaises(secure.SecureBridgeError):
                self.validate(self.request([{
                    "tool": "import_managed_reconstruction",
                    "arguments": self.path,
                }]))

    def test_inline_scope_cannot_skip_github_buttons(self):
        task = {"signed_task": "untrusted", "owner_signature": "fake"}
        body = self.request([{"tool": "import_managed_reconstruction",
                              "arguments": self.path}], scoped_task=task)
        for enabled in ("enabled", "disabled"):
            with self.subTest(enabled=enabled), mock.patch.dict(
                    os.environ, {"REA_P311_SCOPED_TASKS": enabled}), \
                 self.assertRaises(secure.SecureBridgeError):
                self.validate(body)
        with mock.patch.dict(os.environ, {
                "REA_P311_SCOPED_TASKS": "enabled"}), \
             self.assertRaisesRegex(secure.SecureBridgeError,
                                    "GitHub-approved registered"):
            self.validate(self.request([{
                "tool": "import_managed_reconstruction",
                "arguments": self.path}],), scope=task)

    def test_unknown_registered_grant_id_is_never_authority(self):
        payload = self.request([{
            "tool": "import_managed_reconstruction",
            "arguments": self.path
        }], scoped_task_id="b"*32)
        with mock.patch.dict(os.environ, {"REA_P311_SCOPED_TASKS": "enabled"}), \
             self.assertRaises(secure.SecureBridgeError):
            self.validate(payload)


if __name__ == "__main__":
    unittest.main()
