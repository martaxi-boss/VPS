"""P311: proposed task must use pinned REAL 6.8.0-shaped 229-tool contracts.

All files here are synthetic, local, ephemeral fixture copies, never the
production REA catalog, secrets, signer or VPS. No certifying tools.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import stat
import tempfile
from unittest import mock
import unittest

from ops import rea_secure_protocol_20261022 as secure


class P311Release680SourcePinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest_file = self.root / "rea-6.8.0-mcp-contract-manifest.json"
        self.schema = {"type": "object"}
        self.effects = dict(secure.AUDITED_EFFECTS)
        # Simulated 21 new release tools, NOT guessed actual REA tool names.
        self.fixture_name = "p311_fixture_new_tool_01"
        for index in range(21):
            self.effects[f"p311_fixture_new_tool_{index:02}"] = frozenset({"mutatesSession"})
        self.assertEqual(229, len(self.effects))
        sha = secure.arguments_sha256(self.schema)
        self.registry = {
            name: {"inputSchema": self.schema.copy(),
                   "annotations": {
                       "readOnlyHint": not bool(fx),
                       "destructiveHint": bool(fx.intersection({
                           "mayDiscardData", "executesForeignCode", "mutatesDevice"
                       })),
                       "openWorldHint": bool(fx.intersection({
                           "launchesProcess", "accessesNetwork"
                       })),
                   }}
            for name, fx in self.effects.items()
        }
        self.catalogue = {
            name: {"effects": sorted(fx), "input_schema_sha256": sha}
            for name, fx in self.effects.items()
        }
        self._write_manifest()
        self.patches = [
            mock.patch.object(secure, "RELEASE_680_MANIFEST_PATH", self.manifest_file),
            mock.patch.object(secure, "RELEASE_680_MANIFEST_SHA256",
                              hashlib.sha256(self.manifest_file.read_bytes()).hexdigest())
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.params = {
            "project": "Engenharia Reversa", "task_id": "P311-LIVE-680-CONTRACT",
            "artifact_root": "/opt/rea-reversa/rea/.rea-private/jobs/p311-680",
            "chosen_tools": [self.fixture_name],
            "now": datetime.now(timezone.utc).replace(microsecond=0),
            "grant_id": "5" * 32,
        }

    def _write_manifest(self):
        envelope = {
            "release": "rea-agents-6.8.0",
            "commit": "160d821ac9a0310afcb8d1fc427862dd6508add5",
            "tree": "15e6fec513dcce08cefdbcf441200986397e2793",
            "tools": self.catalogue,
        }
        self.manifest_file.write_bytes(json.dumps(
            envelope, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        self.manifest_file.chmod(0o600)

    def plan(self, **kwargs):
        return secure.propose_p311_task_from_live_catalog(
            self.registry, {"list_unknowns"}, **{**self.params, **kwargs})

    def test_source_pinned_229_tool_manifest_can_propose_safe_task(self):
        grant = self.plan()
        self.assertEqual([self.fixture_name], grant["allowed_tools"])
        self.assertEqual(["mutatesSession"], grant["permitted_effects"])
        self.assertNotIn("owner_signature", grant)
        self.assertEqual(self.params["task_id"], grant["task_id"])

    def test_real_680_proposal_can_combine_pinned_legacy_and_new_tools(self):
        proposal = self.plan(chosen_tools=["inspect_with_objdump", self.fixture_name])
        self.assertEqual(sorted(["inspect_with_objdump", self.fixture_name]),
                         proposal["allowed_tools"])
        self.assertEqual(["launchesProcess", "mutatesSession"],
                         proposal["permitted_effects"])

    def test_680_manifest_missing_tampered_or_world_readable_fails_closed(self):
        self.manifest_file.chmod(0o644)
        with self.assertRaises(secure.SecureBridgeError):
            self.plan()
        self.manifest_file.chmod(0o600)
        self.manifest_file.write_bytes(self.manifest_file.read_bytes()+b"\n")
        with self.assertRaises(secure.SecureBridgeError):
            self.plan()
        self.manifest_file.unlink()
        with self.assertRaises(secure.SecureBridgeError):
            self.plan()

    def test_680_schema_drift_fails_owner_proposal(self):
        self.registry[self.fixture_name]["inputSchema"] = {
            "type": "object", "properties": {"command": {"type": "string"}}}
        with self.assertRaises(secure.SecureBridgeError):
            self.plan()

    def test_680_catalog_tool_inventory_and_risk_hint_drift_fails_closed(self):
        self.registry.pop("p311_fixture_new_tool_17")
        with self.assertRaises(secure.SecureBridgeError):
            self.plan()
        self.registry["p311_fixture_new_tool_17"] = {
            "inputSchema": self.schema.copy(),
            "annotations": {"readOnlyHint": True,
                            "destructiveHint": False, "openWorldHint": False},
        }
        with self.assertRaises(secure.SecureBridgeError):
            self.plan(chosen_tools=["p311_fixture_new_tool_17"])

    def test_680_unknown_or_dangerous_tools_never_enter_signed_scope(self):
        for name in ("not_a_tool", "install_adb_package", "close_binary"):
            with self.subTest(name=name), self.assertRaises(secure.SecureBridgeError):
                self.plan(chosen_tools=[name])


if __name__ == "__main__":
    unittest.main()

