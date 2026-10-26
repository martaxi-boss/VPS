"""No-network, no-VPS offline tests of a disabled staged owner-signed task grant."""
import base64
from datetime import datetime, timedelta, timezone
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ops import rea_scoped_approval_20261026 as a


class ScopedTaskAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.grant = {
            "purpose": a.PURPOSE, "grant_id": "a" * 32,
            "project": "Engenharia Reversa", "task_id": "DOPAMINE-AUDIT-001",
            "origin": a.ORIGIN,
            "not_before": fmt(now - timedelta(minutes=1)),
            "expires_at": fmt(now + timedelta(hours=12)),
            "allowed_tools": ["inspect_macho", "recover_javascript_sources"],
            "permitted_effects": ["launchesProcess", "mutatesSession", "writesFilesystem"],
            "artifact_root": "/opt/rea-reversa/rea/.rea-private/jobs/dopamine-audit",
        }
        self.params = {
            "project": self.grant["project"], "task_id": self.grant["task_id"],
            "origin": self.grant["origin"],
            "artifact_root": self.grant["artifact_root"],
            "tool": "recover_javascript_sources",
            "audited_effects": frozenset({"launchesProcess", "writesFilesystem", "mutatesSession"}),
            "current_risk": "sensitive", "now": now,
            "arguments": {"path": self.grant["artifact_root"] + "/sample.bin"},
        }

    def signed(self, grant=None):
        grant = grant if grant is not None else self.grant
        return base64.b64encode(self.key.sign(a.canonical_bytes(grant))).decode("ascii")

    def check(self, grant=None, sig=None, public=None, **override):
        return a.verify_task_grant(
            self.grant if grant is None else grant,
            self.signed() if sig is None else sig,
            self.public if public is None else public,
            **{**self.params, **override})

    def _reviewable_mcp_catalog(self):
        from ops import rea_secure_protocol_20261022 as secure
        names = ("inspect_with_objdump", "recover_javascript_sources",
                 "install_adb_package", "inspect_web_page",
                 "close_binary", "list_unknowns", "undeclared_plugin")
        source = secure.AUDITED_EFFECTS
        registry = {}
        for name in names:
            flags = source.get(name, frozenset())
            registry[name] = {
                "inputSchema": {"type": "object", "properties": {}},
                "annotations": {
                    "readOnlyHint": not bool(flags),
                    "destructiveHint": bool(flags.intersection({
                        "mayDiscardData", "executesForeignCode", "mutatesDevice"})),
                    "openWorldHint": bool(flags.intersection({
                        "launchesProcess", "accessesNetwork"})),
                },
            }
        pins = {n: secure.arguments_sha256(d["inputSchema"])
                for n, d in registry.items() if n in source}
        classifier = lambda n, d: ("read" if not source.get(n) else
                                   "sensitive" if n in ("install_adb_package",
                                                        "recover_javascript_sources") else
                                   "workspace")
        selection = lambda catalog, digests=pins: a.propose_task_tools(
            catalog, source, digests, schema_digest=secure.arguments_sha256,
            classify_tool=classifier)
        return registry, pins, selection

    def test_system_selects_only_safe_reviewable_tools_not_user_named(self):
        registry, _pins, select = self._reviewable_mcp_catalog()
        self.assertEqual(["inspect_with_objdump", "recover_javascript_sources"],
                         select(registry))

    def test_tool_selection_rejects_schema_or_annotations_drift(self):
        registry, pins, select = self._reviewable_mcp_catalog()
        bad_pins = dict(pins, inspect_with_objdump="0" * 64)
        self.assertEqual(["recover_javascript_sources"],
                         select(registry, bad_pins))
        registry["recover_javascript_sources"]["annotations"]["openWorldHint"] = False
        self.assertEqual(["inspect_with_objdump"], select(registry))

    def test_tool_selection_rejects_unknown_and_destructive_effects(self):
        registry, _pins, select = self._reviewable_mcp_catalog()
        selected = select(registry)
        for name in ("undeclared_plugin", "close_binary", "list_unknowns",
                     "inspect_web_page", "install_adb_package"):
            with self.subTest(tool=name):
                self.assertNotIn(name, selected)

    def test_valid_scoped_signed_analysis(self):
        self.assertTrue(self.check())

    def test_tampering_or_other_signer_fails(self):
        other = dict(self.grant, project="Outro Projeto")
        with self.assertRaises(a.ScopedApprovalError):
            self.check(grant=other)
        stranger = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(a.ScopedApprovalError):
            self.check(public=stranger)

    def test_cross_project_task_origin_and_root_denied(self):
        for values in ({"project": "IPTV"}, {"task_id": "OTHER"},
                       {"origin": "another/repo:main"}, {"artifact_root": "/tmp"}):
            with self.subTest(values=values), self.assertRaises(a.ScopedApprovalError):
                self.check(**values)

    def test_permission_scope_rejects_destructive_or_network(self):
        for name, fx in (
            ("install_adb_package", {"mutatesDevice"}),
            ("gdb_console", {"executesForeignCode"}),
            ("close_binary", {"mayDiscardData"}),
            ("recover_javascript_sources", {"accessesNetwork"}),
        ):
            with self.subTest(name=name), self.assertRaises(a.ScopedApprovalError):
                self.check(tool=name, audited_effects=frozenset(fx))

    def test_standing_grant_never_grants_special_evidence_workflows(self):
        for tool in a.NEVER_STANDING_TOOLS:
            with self.subTest(tool=tool), self.assertRaises(a.ScopedApprovalError):
                self.check(tool=tool, audited_effects=frozenset({"mutatesSession"}))

    def test_unknown_tool_schema_or_expiry_denied(self):
        with self.assertRaises(a.ScopedApprovalError):
            self.check(tool="unknown-new-tool")
        with self.assertRaises(a.ScopedApprovalError):
            self.check(audited_effects=frozenset({"unknownEffect"}))
        with self.assertRaises(a.ScopedApprovalError):
            self.check(now=self.params["now"] + timedelta(days=8))
        with self.assertRaises(a.ScopedApprovalError):
            self.check(current_risk="read")

    def test_unsorted_or_wildcard_grant_denied_even_if_signed(self):
        for replacement in (["*"], ["z", "a"], ["inspect_macho", "inspect_macho"]):
            changed = dict(self.grant, allowed_tools=replacement)
            with self.subTest(replacement=replacement), self.assertRaises(a.ScopedApprovalError):
                self.check(grant=changed, sig=self.signed(changed))
        longer = dict(self.grant)
        longer["expires_at"] = (self.params["now"] + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaises(a.ScopedApprovalError):
            self.check(grant=longer, sig=self.signed(longer))

    def test_scoped_paths_fail_closed_for_foreign_targets_and_traversal(self):
        root = self.grant["artifact_root"]
        for value in ("/etc/passwd", "/usr/bin/true", root + "/../../secrets",
                      "/opt/rea-reversa/rea/.rea-private/jobs/another-project/item",
                      "relative.bin"):
            with self.subTest(value=value), self.assertRaises(a.ScopedApprovalError):
                self.check(arguments={"path": value})

    def test_unbound_sessions_and_unconfined_signed_roots_denied(self):
        for args in ({}, {"document": "foreign-document"},
                     {"source_paths": ["/etc/passwd"]}):
            with self.subTest(args=args), self.assertRaises(a.ScopedApprovalError):
                self.check(arguments=args)
        arbitrary = dict(self.grant, artifact_root="/etc")
        with self.assertRaises(a.ScopedApprovalError):
            self.check(grant=arbitrary, sig=self.signed(arbitrary), artifact_root="/etc")

    def test_nested_paths_checked(self):
        root = self.grant["artifact_root"]
        self.assertTrue(self.check(arguments={"artifacts": [{"file": root + "/a"}]}))
        with self.assertRaises(a.ScopedApprovalError):
            self.check(arguments={"artifacts": [{"file": root + "/a"},
                                               {"output_path": "/tmp/escape"}]})

    def test_hidden_absolute_paths_and_path_aliases_rejected(self):
        root = self.grant["artifact_root"]
        for args in (
            {"path": root + "/sample", "source_file": "/etc/passwd"},
            {"path": root + "/sample", "metadata": ["/etc/shadow"]},
            {"path": root + "/sample", "input_files": [root + "/ok", "/tmp/escape"]},
            {"path": root + "/sample", "other": {"alternate_dir": "/root"}},
            {"path": root + "/sample", "download": "file:///etc/passwd"},
        ):
            with self.subTest(args=args), self.assertRaises(a.ScopedApprovalError):
                self.check(arguments=args)

    def test_execution_and_network_argument_keys_rejected(self):
        root = self.grant["artifact_root"]
        for key in ("command", "script", "javascript", "code", "source_url",
                    "host", "device_id", "process_id"):
            with self.subTest(key=key), self.assertRaises(a.ScopedApprovalError):
                self.check(arguments={"path": root + "/sample", key: "value"})

    def test_revocation_marker_stops_approved_task(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as base:
            directory = Path(base) / "revoked-p311-grants"
            with self.assertRaises(a.ScopedApprovalError):
                self.check(revocation_dir=directory)
            directory.mkdir(mode=0o700)
            self.assertTrue(self.check(revocation_dir=directory))
            marker = directory / (self.grant["grant_id"] + ".revoked")
            marker.write_text("revoked\\n", encoding="ascii")
            marker.chmod(0o600)
            with self.assertRaises(a.ScopedApprovalError):
                self.check(revocation_dir=directory)

    def test_revocation_symlinks_and_unsafe_permissions_fail_closed(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            directory = root / "revocations"
            directory.mkdir(mode=0o700)
            marker = directory / (self.grant["grant_id"] + ".revoked")
            marker.symlink_to(root / "missing")
            with self.assertRaises(a.ScopedApprovalError):
                self.check(revocation_dir=directory)
            marker.unlink()
            directory.chmod(0o777)
            with self.assertRaises(a.ScopedApprovalError):
                self.check(revocation_dir=directory)
            directory.chmod(0o700)
            alias = root / "symlink-revocations"
            alias.symlink_to(directory)
            with self.assertRaises(a.ScopedApprovalError):
                self.check(revocation_dir=alias)

    def test_missing_or_corrupt_signature_denied(self):
        for signature in ("", "****", "AAAA"):
            with self.subTest(signature=signature), self.assertRaises(a.ScopedApprovalError):
                self.check(sig=signature)


if __name__ == "__main__":
    unittest.main()

