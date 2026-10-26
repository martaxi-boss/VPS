"""Offline, non-destructive regression checks for the REA sealed Actions bridge."""
import base64
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ops import rea_secure_protocol_20261022 as secure


def expires(hours=1):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def request(steps):
    return {
        "protocol": 1,
        "nonce": os.urandom(16).hex(),
        "expires_at": expires(),
        "steps": steps,
    }


def approved(tool, arguments, scope="workspace"):
    return {
        "tool": tool,
        "arguments_sha256": secure.arguments_sha256(arguments),
        "scope": scope,
        "reason": "Autorizacao individual para um teste com artefacto publico.",
        "confirmed_by_owner": True,
        "acknowledgement": (
            "AUTORIZO_OPERACAO_SENSIVEL" if scope == "sensitive"
            else "AUTORIZO_ANALISE_LOCAL"),
    }


class ReaSecureProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        home_patch = mock.patch("pathlib.Path.home", return_value=Path(self.tmp.name))
        home_patch.start()
        self.addCleanup(home_patch.stop)
        self.registry = {
            "list_unknowns": {"annotations": {"readOnlyHint": True}},
            "open_binary": {"annotations": {}},
            "close_binary": {"annotations": {"destructiveHint": True}},
            "undocumented_tool": {"annotations": {}},
            "inspect_with_objdump": {"annotations": {}},
            "install_adb_package": {"annotations": {"destructiveHint": True}},
        }
        for name, descriptor in self.registry.items():
            descriptor["inputSchema"] = {"type": "object"}
            flags = secure.AUDITED_EFFECTS.get(name, frozenset())
            descriptor["annotations"] = {
                "readOnlyHint": not bool(flags),
                "destructiveHint": bool(flags.intersection({"mayDiscardData", "executesForeignCode", "mutatesDevice"})),
                "openWorldHint": bool(flags.intersection({"launchesProcess", "accessesNetwork"})),
                **descriptor["annotations"],
            }
        patches = {name: secure.arguments_sha256(desc["inputSchema"])
                   for name, desc in self.registry.items() if name in secure.AUDITED_EFFECTS}
        schemas = mock.patch.dict(secure.AUDITED_SCHEMA_SHA256, patches)
        schemas.start()
        self.addCleanup(schemas.stop)

    def test_risk_classifier_is_not_blanket_allowance(self):
        self.assertEqual("read", secure.classify(
            "list_unknowns", self.registry["list_unknowns"], {"list_unknowns"}))
        self.assertEqual("workspace", secure.classify(
            "open_binary", self.registry["open_binary"], {"list_unknowns"}))
        self.assertEqual("sensitive", secure.classify(
            "install_adb_package", self.registry["install_adb_package"],
            {"list_unknowns"}))
        self.assertEqual("sensitive", secure.classify(
            "undocumented_tool", self.registry["undocumented_tool"],
            {"list_unknowns"}))
        self.assertEqual("sensitive", secure.classify(
            "close_binary", self.registry["close_binary"], {"list_unknowns"}))


    def test_all_native_risk_classes_without_owner_signatures(self):
        # A single authenticated SSH+RSA sealed request may call any tool
        # actually advertised by the original REA MCP.
        operations = [
            {"tool": "list_unknowns", "arguments": {}},
            {"tool": "inspect_with_objdump",
             "arguments": {"path": "/usr/bin/true", "operation": "file_headers"}},
            {"tool": "install_adb_package",
             "arguments": {"path": "/usr/bin/true"}},
        ]
        self.assertEqual(["native", "native", "native"],
                         secure.validate_inner(request(operations),
                                               self.registry, {"list_unknowns"}))
        self.assertFalse((secure.key_directory() /
                          "owner-approval-public.pem").exists())

    def test_native_transport_does_not_accept_old_signing_fields(self):
        for value in (
            {"tool": "install_adb_package", "arguments": {},
             "authorization": approved("install_adb_package", {}, "sensitive")},
            {"tool": "list_unknowns", "arguments": {}, "owner_signature": "test"},
        ):
            with self.subTest(value=value), self.assertRaises(
                    secure.SecureBridgeError):
                secure.validate_inner(request([value]),
                                      self.registry, {"list_unknowns"})

    def test_native_680_new_tool_from_live_mcp_is_not_legacy_manifest_gated(self):
        advertised = dict(self.registry)
        advertised["REA_original_680_tool"] = {
            "inputSchema": {"type": "object", "additionalProperties": False},
            "annotations": {"readOnlyHint": False,
                            "destructiveHint": False, "openWorldHint": False}}
        # Unknown on the old hard-coded 208 list, but native tools/list
        # and actual schema are the authority.
        result = secure.validate_inner(request([
            {"tool": "REA_original_680_tool", "arguments": {}}]),
            advertised, {"list_unknowns"})
        self.assertEqual(["native"], result)
        # Unknown names are never fabricated or admitted.
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(request([
                {"tool": "not_advertised", "arguments": {}}]),
                advertised, {"list_unknowns"})

    def test_native_session_reads_require_open_but_not_owner_signature(self):
        examples = {
            "read_bytes": {"address": "0x1019f0", "length": 16},
            "read_function_instructions": {"procedure": "entry"},
            "xrefs": {"address": "0x1019f0"},
        }
        registry = dict(self.registry)
        for name, arguments in examples.items():
            registry[name] = {"inputSchema": {"type": "object"},
                              "annotations": {"readOnlyHint": False,
                                              "destructiveHint": False,
                                              "openWorldHint": False}}
            with self.subTest(name=name):
                with self.assertRaises(secure.SecureBridgeError):
                    secure.validate_inner(request([
                        {"tool": name, "arguments": arguments}]),
                        registry, {"list_unknowns"})
                profiles = secure.validate_inner(request([
                    {"tool": "open_binary", "arguments": {
                        "path": "/usr/bin/true", "provider_id": "ghidra"}},
                    {"tool": name, "arguments": arguments}]),
                    registry, {"list_unknowns"})
                self.assertEqual(2, len(profiles))
                self.assertEqual("native", profiles[0])

    def test_schema_expiry_and_replay_constraints_remain(self):
        invalid = request([{"tool": "list_unknowns", "arguments": {}}])
        invalid["expires_at"] = "2000-01-01T00:00:00Z"
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(invalid, self.registry, {"list_unknowns"})
        for nonce in ("invalid", "!" * 32):
            bad = request([{"tool": "list_unknowns", "arguments": {}}])
            bad["nonce"] = nonce
            with self.assertRaises(secure.SecureBridgeError):
                secure.validate_inner(bad, self.registry, {"list_unknowns"})
        body = request([{"tool": "install_adb_package", "arguments": {}}])
        body["steps"][0]["arguments"] = []
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(body, self.registry, {"list_unknowns"})

    def test_live_argument_contract_rejects_invalid_and_remote_schemas(self):
        descriptor = {"inputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object", "additionalProperties": False,
            "required": ["length"], "properties": {"length": {
                "type": "integer", "minimum": 1, "maximum": 16}}}}
        secure.validate_arguments(descriptor, {"length": 8})
        for args in ({}, {"length": "8"}, {"length": 0}, {"length": 17},
                     {"length": 8, "extra": True}, {"length": True}):
            with self.subTest(args=args), self.assertRaises(secure.SecureBridgeError):
                secure.validate_arguments(descriptor, args)
        for schema in ({}, {"type": "object", "$ref": "https://example.invalid/private"}):
            with self.assertRaises(secure.SecureBridgeError):
                secure.validate_arguments({"inputSchema": schema}, {})
        with self.assertRaises(secure.SecureBridgeError):
            secure._authorized_target_paths({"glue_paths": ["/etc/shadow"]})
        with self.assertRaises(secure.SecureBridgeError):
            secure._authorized_target_paths({"left_bundle_path": "/etc/shadow"})

    def test_canonical_effects_cover_all_names_and_schema_drift_fails_closed(self):
        self.assertEqual(208, len(secure.AUDITED_EFFECTS))
        self.assertEqual(set(secure.AUDITED_EFFECTS), set(secure.AUDITED_SCHEMA_SHA256))
        self.assertEqual("sensitive", secure.classify("unknown_read_tool", {
            "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"}},
            {"unknown_read_tool"}))
        self.assertEqual("sensitive", secure.classify("open_binary", {
            "inputSchema": {"type": "object", "properties": {"changed": {"type": "string"}}}},
            {"open_binary"}))
        self.assertEqual("process_or_device_control", secure.effect_category("start_gdb_session"))
        self.assertEqual("data_change_or_unreviewed", secure.effect_category("set_comment"))
        self.assertEqual("analysis_or_temporary_session", secure.effect_category("open_binary"))
        self.assertEqual("read", secure.effect_category("list_unknowns"))

    def test_seal_authenticate_response_key_and_replay(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        public = secure.request_public_key_b64(create=True)
        response_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        response_key = base64.b64encode(response_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        req = request([{"tool": "list_unknowns", "arguments": {}}])
        sealed = secure.seal_for_client(req, public, response_key)
        secure.validate_public_envelope(sealed)
        self.assertEqual(req, secure.unseal(sealed, response_key))
        second_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        swapped = base64.b64encode(second_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        with self.assertRaises(secure.SecureBridgeError):
            secure.unseal(sealed, swapped)
        secure.claim_one_use_nonce(req["nonce"])
        with self.assertRaises(secure.SecureBridgeError):
            secure.claim_one_use_nonce(req["nonce"])
        key_path = secure.key_directory() / "request-private.pem"
        self.assertEqual(0o600, key_path.stat().st_mode & 0o777)


    def test_large_portable_evidence_remains_sealed_and_bounded(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        recipient = secure.request_public_key_b64(create=True)
        response = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        reply = base64.b64encode(response.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii")
        args = {"payload": "A" * 80000}
        body = request([{"tool": "open_binary", "arguments": args}])
        sealed = secure.seal_for_client(body, recipient, reply)
        self.assertGreater(len(sealed["ciphertext"]), 95000)
        self.assertEqual(body, secure.unseal(sealed, reply))
        self.assertEqual(["native"], secure.validate_inner(
            body, self.registry, set()))
        oversized = request([
            {"tool": "open_binary", "arguments": {"payload": "A" * 512000}}])
        with self.assertRaises(secure.SecureBridgeError):
            secure.seal_for_client(oversized, recipient, reply)

    def test_native_lifecycle_close_paired_and_argument_pinned(self):
        import sys
        sys.modules.setdefault("rea_secure_protocol_20261022", secure)
        from ops import rea_mobile_mcp_bridge_20261022 as bridge
        op = {"path": "/usr/bin/true", "provider_id": "ghidra"}
        body = request([
            {"tool": "open_binary", "arguments": op},
            {"tool": "close_binary", "arguments": {}},
        ])
        self.assertEqual(["native", "native"],
                         secure.validate_inner(body, self.registry, set()))
        pins = bridge.p232_guard_inner_batch(body)
        self.assertEqual({"open_binary": secure.arguments_sha256(op),
                          "close_binary": secure.arguments_sha256({})}, pins)
        for name, args in (("open_binary", op), ("close_binary", {})):
            call = {"method": "tools/call", "params": {
                "name": name, "arguments": args}}
            with self.assertRaises(ValueError):
                bridge.p232_guard_live_call(call)
            self.assertIsNone(bridge.p232_guard_live_call(
                call, lifecycle_grants=pins))
        with self.assertRaises(ValueError):
            bridge.p232_guard_live_call(
                {"method": "tools/call", "params": {
                    "name": "open_binary",
                    "arguments": {"path": "/usr/bin/false"}}},
                lifecycle_grants=pins)
        for pair in (
            [body["steps"][0]],
            [body["steps"][1], body["steps"][0]],
            [body["steps"][0], {"tool": "close_binary",
                                "arguments": {"snapshot_path": "/tmp/unsafe"}}],
        ):
            with self.subTest(steps=pair), self.assertRaises(ValueError):
                bridge.p232_guard_inner_batch(request(pair))
        self.assertEqual({}, bridge.p232_guard_inner_batch(request([
            {"tool": "list_unknowns", "arguments": {}}])))

    def _p269_signer_test_fixture(self):
        import importlib.util
        import hashlib
        import json
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        source = Path(__file__).resolve().parents[2] / "rea-linux/owner/owner_approval.py"
        spec = importlib.util.spec_from_file_location("rea_p269_owner_batch", source)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        root = Path(self.tmp.name)
        key = Ed25519PrivateKey.generate()
        private = root / "rea-owner-private.pem"
        private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        private.chmod(0o600)
        batches = [
            request([{"tool":"inspect_adb_client", "arguments":{},
                      "authorization":approved("inspect_adb_client",{}, "sensitive")}]),
            request([
                {"tool":"get_evidence_bundle","arguments":{"detail":"complete"}},
                {"tool":"inspect_with_objdump","arguments":{
                    "path":"/usr/bin/true","operation":"file_headers"
                }, "authorization":approved("inspect_with_objdump", {
                    "path":"/usr/bin/true","operation":"file_headers"
                }, "workspace")},
                {"tool":"inspect_web_network_capture","arguments":{"path":"/usr/bin/true"},
                 "authorization":approved("inspect_web_network_capture",
                     {"path":"/usr/bin/true"}, "sensitive")}
            ])
        ]
        manifest = {"protocol":"REA_OWNER_BATCH_V1","requests":[]}
        for i, body in enumerate(batches):
            filename = "p269-test-" + str(i) + ".json"
            (root / filename).write_bytes(owner.canonical(body) + b"\n")
            manifest["requests"].append({
                "file":filename,
                "unsigned_sha256":hashlib.sha256(owner.canonical(body)).hexdigest()
            })
        manifest_file = root / "p269-manifest.json"
        manifest_file.write_bytes(owner.canonical(manifest) + b"\n")
        return owner,root,key,private,manifest_file,batches

    def test_P269_offline_one_review_many_independent_owner_signatures(self):
        import hashlib
        import json
        owner,root,key,private,manifest,batches = self._p269_signer_test_fixture()
        prompts = []
        def consent(prompt):
            prompts.append(prompt)
            return prompt.split("Type ",1)[1].split(" to sign",1)[0]
        import io
        from contextlib import redirect_stdout
        shown = io.StringIO()
        with redirect_stdout(shown):
            outcome = owner.sign_batch_requests(manifest, private, root,
                                                confirm_callback=consent)
        self.assertIn("TOOL: get_evidence_bundle", shown.getvalue())
        self.assertIn("TOOL: inspect_with_objdump SCOPE: workspace", shown.getvalue())
        self.assertIn("TOOL: inspect_web_network_capture SCOPE: sensitive", shown.getvalue())
        self.assertEqual("SIGNED_EXACT_BATCH_OFFLINE",outcome["status"])
        self.assertEqual(2,outcome["signed_requests"])
        self.assertEqual(2,outcome["individually_signed_sensitive_steps"])
        self.assertEqual(1,len(prompts))
        for i,filename in enumerate(outcome["output_files"]):
            signed = json.loads(Path(filename).read_text())
            unsigned = batches[i]
            self.assertEqual(signed["nonce"],unsigned["nonce"])
            self.assertEqual(signed["expires_at"],unsigned["expires_at"])
            self.assertEqual(len(signed["steps"]),len(unsigned["steps"]))
            step_index = 0 if i == 0 else 2
            step = signed["steps"][step_index]
            auth = step["authorization"]
            signed_message = {
                "purpose":"REA_OWNER_APPROVAL_V1",
                "nonce":signed["nonce"],"expires_at":signed["expires_at"],
                "step_index":step_index, "tool":step["tool"],
                "arguments_sha256":hashlib.sha256(owner.canonical(step["arguments"])).hexdigest(),
                "scope":"sensitive", "reason":auth["reason"],
                "acknowledgement":auth["acknowledgement"]
            }
            key.public_key().verify(
                base64.b64decode(auth["owner_signature"],validate=True),
                owner.canonical(signed_message))
        # One-use output name may not be clobbered by a second approval.
        with self.assertRaises(ValueError):
            owner.sign_batch_requests(manifest,private,root,
                                     confirm_callback=consent)
        self.assertEqual(1,len(prompts))

    def test_P269_refuses_unsigned_digest_tamper_before_owner_prompt(self):
        import json
        owner,root,key,private,manifest,batches = self._p269_signer_test_fixture()
        first = root / "p269-test-0.json"
        altered = json.loads(first.read_text())
        altered["steps"][0]["arguments"]["path"] = "/usr/bin/false"
        first.write_bytes(owner.canonical(altered)+b"\n")
        with self.assertRaises(ValueError) as failure:
            owner.sign_batch_requests(manifest,private,root,
                confirm_callback=lambda _: self.fail("Prompt should not happen"))
        self.assertIn("manifest SHA-256",str(failure.exception))
        self.assertFalse(list(root.glob("signed-*.json")))

    def test_P269_requires_fresh_distinct_nonces_and_declines_without_writing(self):
        import json
        owner,root,key,private,manifest,batches = self._p269_signer_test_fixture()
        body = batches[1]
        body["nonce"] = batches[0]["nonce"]
        second = root / "p269-test-1.json"
        second.write_bytes(owner.canonical(body)+b"\n")
        current = json.loads(manifest.read_text())
        import hashlib
        current["requests"][1]["unsigned_sha256"] = hashlib.sha256(
            owner.canonical(body)).hexdigest()
        manifest.write_bytes(owner.canonical(current)+b"\n")
        with self.assertRaises(ValueError) as failure:
            owner.sign_batch_requests(manifest,private,root,
                confirm_callback=lambda _: self.fail("Prompt should not happen"))
        self.assertIn("Duplicate",str(failure.exception))
        self.assertFalse(list(root.glob("signed-*.json")))


if __name__ == "__main__":
    unittest.main()

