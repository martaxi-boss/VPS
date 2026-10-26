"""REA P311: only the canonical live tool inventory may produce unsigned permissions.

Tests intentionally use a FULL 208-tool synthetic registry with source effects
and locally patched dummy schemas. No MCP or VPS access, no owner key used.
"""
from datetime import datetime, timezone
from unittest import mock
import unittest

from ops import rea_secure_protocol_20261022 as secure


class CanonicalRuntimeTaskProposalTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.descriptor = {"type": "object"}
        flags = secure.AUDITED_EFFECTS
        self.registry = {
            name: {
                "inputSchema": self.descriptor.copy(),
                "annotations": {
                    "readOnlyHint": not bool(effects),
                    "destructiveHint": bool(effects.intersection({
                        "mayDiscardData", "executesForeignCode", "mutatesDevice"
                    })),
                    "openWorldHint": bool(effects.intersection({
                        "launchesProcess", "accessesNetwork"
                    })),
                },
            } for name, effects in flags.items()
        }
        self.assertEqual(208, len(self.registry))
        self.pin = secure.arguments_sha256(self.descriptor)
        pins = {name: self.pin for name in self.registry}
        patch = mock.patch.dict(secure.AUDITED_SCHEMA_SHA256, pins, clear=True)
        patch.start()
        self.addCleanup(patch.stop)
        self.settings = {
            "project": "Engenharia Reversa",
            "task_id": "P311-REAL-INVENTORY",
            "artifact_root": "/opt/rea-reversa/rea/.rea-private/jobs/p311-test",
            "chosen_tools": ["inspect_with_objdump"],
            "now": self.now,
            "lifetime_seconds": 3600,
            "grant_id": "3" * 32,
        }

    def plan(self, registry=None, **kwargs):
        return secure.propose_p311_task_from_live_catalog(
            self.registry if registry is None else registry, {"list_unknowns"},
            **{**self.settings, **kwargs},
        )

    def test_full_verified_inventory_can_prepare_single_task_without_signed_authority(self):
        proposal = self.plan()
        self.assertEqual(["inspect_with_objdump"], proposal["allowed_tools"])
        self.assertEqual(["launchesProcess", "mutatesSession"],
                         proposal["permitted_effects"])
        self.assertEqual("Engenharia Reversa", proposal["project"])
        self.assertNotIn("owner_signature", proposal)
        self.assertNotIn("private_key", proposal)

    def test_full_canonical_catalog_mandatory_for_proposal(self):
        incomplete = dict(self.registry)
        incomplete.pop("list_unknowns")
        with self.assertRaises(secure.SecureBridgeError):
            self.plan(incomplete)
        unknown = dict(self.registry)
        unknown.pop("list_unknowns")
        unknown["attacker_tool"] = self.registry["inspect_with_objdump"]
        with self.assertRaises(secure.SecureBridgeError):
            self.plan(unknown)

    def test_mcp_schema_drift_or_annotation_injection_denied(self):
        registry = {n: {**desc} for n, desc in self.registry.items()}
        registry["inspect_with_objdump"] = {
            **registry["inspect_with_objdump"],
            "inputSchema": {"type": "object", "additionalProperties": True},
        }
        with self.assertRaises(secure.SecureBridgeError):
            self.plan(registry)
        registry = {n: {**desc} for n, desc in self.registry.items()}
        registry["inspect_with_objdump"] = {
            **registry["inspect_with_objdump"],
            "annotations": {"readOnlyHint": True,
                            "destructiveHint": False, "openWorldHint": False},
        }
        with self.assertRaises(secure.SecureBridgeError):
            self.plan(registry)

    def test_approved_tools_must_be_safe_under_both_effects_and_classifier(self):
        for tool in ("install_adb_package", "close_binary",
                     "execute_rizin_command", "inspect_web_page",
                     "list_unknowns"):
            with self.subTest(tool=tool), self.assertRaises(secure.SecureBridgeError):
                self.plan(chosen_tools=[tool])

    def test_high_risk_named_tool_without_dangerous_effects_requires_extra_care(self):
        effects = secure.AUDITED_EFFECTS["import_managed_reconstruction"]
        self.assertEqual(frozenset({"mutatesSession"}), effects)
        proposal = self.plan(chosen_tools=["import_managed_reconstruction"])
        self.assertEqual(["import_managed_reconstruction"], proposal["allowed_tools"])
        # The name is sensitive in the original policy, not downgraded to read.
        self.assertEqual("sensitive", secure.classify(
            "import_managed_reconstruction",
            self.registry["import_managed_reconstruction"], {"list_unknowns"}))

    def test_missing_or_mismatched_source_effect_policy_is_never_granted(self):
        with mock.patch.dict(secure.AUDITED_EFFECTS, {
                "inspect_with_objdump": frozenset({"executesForeignCode"})}):
            with self.assertRaises(secure.SecureBridgeError):
                self.plan()


if __name__ == "__main__":
    unittest.main()

