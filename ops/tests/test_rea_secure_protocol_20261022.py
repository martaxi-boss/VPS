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

    def test_individual_authorization_and_digest(self):
        args = {"path": "/usr/bin/true", "provider_id": "ghidra"}
        valid = request([{
            "tool": "open_binary", "arguments": args,
            "authorization": approved("open_binary", args),
        }, {
            "tool": "inspect_with_objdump",
            "arguments": {"path": "/usr/bin/true", "operation": "file_headers"},
            "authorization": approved("inspect_with_objdump",
                {"path": "/usr/bin/true", "operation": "file_headers"}),
        }])
        self.assertEqual(["workspace", "workspace"],
                         secure.validate_inner(valid, self.registry, {"list_unknowns"}))
        altered = request([dict(valid["steps"][0])])
        altered["steps"][0]["arguments"] = {"path": "/usr/bin/true", "provider_id": "other"}
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(altered, self.registry, {"list_unknowns"})

    def test_sensitive_is_explicit_and_exact(self):
        args = {"path": "/usr/bin/true"}
        bad = request([{"tool": "install_adb_package", "arguments": args,
                        "authorization": approved("install_adb_package", args,
                                                   "workspace")}])
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(bad, self.registry, {"list_unknowns"})
        # A user-editable confirmed_by_owner=true is *not* owner proof.
        good = request([{"tool": "install_adb_package", "arguments": args,
                         "authorization": approved("install_adb_package", args,
                                                    "sensitive")}])
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(good, self.registry, {"list_unknowns"})
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key = Ed25519PrivateKey.generate()
        path = secure._private_directory() / "owner-approval-public.pem"
        path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        # Explicit owner-signed assertion covers tool, exact arguments, position,
        # one-use nonce, expiration and risk in one canonical message.
        auth = good["steps"][0]["authorization"]
        payload = {
            "purpose": "REA_OWNER_APPROVAL_V1",
            "nonce": good["nonce"],
            "expires_at": good["expires_at"],
            "step_index": 0,
            "tool": good["steps"][0]["tool"],
            "arguments_sha256": secure.arguments_sha256(args),
            "scope": auth["scope"], "reason": auth["reason"],
            "acknowledgement": auth["acknowledgement"]
        }
        auth["owner_signature"] = base64.b64encode(
            key.sign(secure.canonical_json(payload))).decode()
        self.assertEqual(["sensitive"], secure.validate_inner(
            good, self.registry, {"list_unknowns"}))
        bad_sig = request([dict(good["steps"][0])])
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(bad_sig, self.registry, {"list_unknowns"})
        altered = request([dict(good["steps"][0])])
        altered["nonce"] = good["nonce"]
        altered["expires_at"] = expires(hours=2)
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(altered, self.registry, {"list_unknowns"})

    def test_P262_legacy_sensitive_names_require_exact_owner_signatures(self):
        # These two historically certified tools predate current owner signatures.
        # Verify the existing current policy enforces exact per-tool authorization
        # using an ephemeral unit-test key only. No live owner key or tool call.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        names = ("inspect_web_network_capture", "inspect_adb_client")
        for name in names:
            flags = secure.AUDITED_EFFECTS[name]
            descriptor = {
                "inputSchema": {"type": "object"},
                "annotations": {
                    "readOnlyHint": not bool(flags),
                    "destructiveHint": bool(flags.intersection({
                        "mayDiscardData", "executesForeignCode", "mutatesDevice"})),
                    "openWorldHint": bool(flags.intersection({
                        "launchesProcess", "accessesNetwork"})),
                },
            }
            self.registry[name] = descriptor
            secure.AUDITED_SCHEMA_SHA256[name] = secure.arguments_sha256(
                descriptor["inputSchema"])
        key = Ed25519PrivateKey.generate()
        key_path = secure._private_directory() / "owner-approval-public.pem"
        key_path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        for name in names:
            with self.subTest(name=name):
                self.assertEqual("sensitive", secure.classify(
                    name, self.registry[name], {"list_unknowns"}))
                arguments = {}
                step = {"tool": name, "arguments": arguments,
                        "authorization": approved(name, arguments, "sensitive")}
                body = request([step])
                with self.assertRaises(secure.SecureBridgeError):
                    secure.validate_inner(body, self.registry, {"list_unknowns"})
                auth = step["authorization"]
                payload = {
                    "purpose": "REA_OWNER_APPROVAL_V1",
                    "nonce": body["nonce"],
                    "expires_at": body["expires_at"],
                    "step_index": 0,
                    "tool": name,
                    "arguments_sha256": secure.arguments_sha256(arguments),
                    "scope": "sensitive",
                    "reason": auth["reason"],
                    "acknowledgement": auth["acknowledgement"],
                }
                auth["owner_signature"] = base64.b64encode(
                    key.sign(secure.canonical_json(payload))).decode()
                self.assertEqual(["sensitive"], secure.validate_inner(
                    body, self.registry, {"list_unknowns"}))
                other_name = names[1] if name == names[0] else names[0]
                substitution = request([{"tool": other_name, "arguments": arguments,
                                         "authorization": dict(auth)}])
                substitution["nonce"] = body["nonce"]
                substitution["expires_at"] = body["expires_at"]
                with self.assertRaises(secure.SecureBridgeError):
                    secure.validate_inner(substitution, self.registry,
                                          {"list_unknowns"})

    def test_reviewed_session_operations_require_open_and_exact_approval(self):
        examples = {
            "read_bytes": {"address": "0x1019f0", "length": 16},
            "resolve_containing_procedure": {"address": "0x1019f0"},
            "inspect_native_instruction": {"address": "0x1019f0"},
            "read_function_instructions": {"procedure": "entry"},
            "xrefs": {"address": "0x1019f0"},
            "analyze_function": {"procedure": "entry"},
        }
        registry = dict(self.registry)
        registry.update({name: {"annotations": {"destructiveHint": False,
                                               "readOnlyHint": False, "openWorldHint": False},
                               "inputSchema": {"type": "object"}}
                         for name in examples})
        for name in examples:
            secure.AUDITED_SCHEMA_SHA256[name] = secure.arguments_sha256({"type": "object"})
        allowed = {"list_unknowns"}
        open_args = {"path": "/usr/bin/true", "provider_id": "ghidra"}
        for name, args in examples.items():
            with self.subTest(name=name):
                step = {"tool": name, "arguments": args,
                        "authorization": approved(name, args)}
                without_open = request([step])
                with self.assertRaises(secure.SecureBridgeError):
                    secure.validate_inner(without_open, registry, allowed)
                opened = request([
                    {"tool": "open_binary", "arguments": open_args,
                     "authorization": approved("open_binary", open_args)},
                    step,
                ])
                self.assertEqual(
                    ["workspace", "workspace"],
                    secure.validate_inner(opened, registry, allowed))
                unapproved = dict(step)
                unapproved.pop("authorization")
                with self.assertRaises(secure.SecureBridgeError):
                    secure.validate_inner(
                        request([opened["steps"][0], unapproved]), registry, allowed)
                changed = dict(step)
                changed["arguments"] = {**args, "document": "other-client"}
                with self.assertRaises(secure.SecureBridgeError):
                    secure.validate_inner(
                        request([opened["steps"][0], changed]), registry, allowed)
        long_read = {"address": "0x1019f0", "length": 8192}
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(request([
                {"tool": "open_binary", "arguments": open_args,
                 "authorization": approved("open_binary", open_args)},
                {"tool": "read_bytes", "arguments": long_read,
                 "authorization": approved("read_bytes", long_read)},
            ]), registry, allowed)
        # Canonical annotations always override the reviewed-name allowlist.
        dangerous = dict(registry)
        dangerous["read_bytes"] = {"annotations": {"destructiveHint": True}}
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(request([
                {"tool": "open_binary", "arguments": open_args,
                 "authorization": approved("open_binary", open_args)},
                {"tool": "read_bytes", "arguments": examples["read_bytes"],
                 "authorization": approved("read_bytes", examples["read_bytes"])}
            ]), dangerous, allowed)

    def test_path_escape_and_expiry_fail_closed(self):
        bad = request([{"tool": "open_binary", "arguments": {"path": "/etc/shadow"},
                        "authorization": approved("open_binary", {
                            "path": "/etc/shadow"})}])
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(bad, self.registry, {"list_unknowns"})
        safe = request([{"tool": "list_unknowns", "arguments": {}}])
        safe["expires_at"] = "2000-01-01T00:00:00Z"
        with self.assertRaises(secure.SecureBridgeError):
            secure.validate_inner(safe, self.registry, {"list_unknowns"})

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
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        args = {"payload": "A" * 80000}
        body = request([{"tool": "open_binary", "arguments": args,
                         "authorization": approved("open_binary", args)}])
        sealed = secure.seal_for_client(body, recipient, reply)
        self.assertGreater(len(sealed["ciphertext"]), 95000)
        self.assertEqual(body, secure.unseal(sealed, reply))
        self.assertEqual(["workspace"], secure.validate_inner(body, self.registry, set()))
        too_large = request([{"tool": "open_binary", "arguments": {"payload": "A" * 512000}}])
        with self.assertRaises(secure.SecureBridgeError):
            secure.seal_for_client(too_large, recipient, reply)


    def test_P267_exact_owner_signed_retention_hold_is_one_request_only(self):
        # Source regression for the original P232/P246 gate. The real signed
        # batch goes through validate_inner(owner Ed25519) before this guard.
        # No actual MCP call or bypass is performed in this unit test.
        import hashlib
        import sys
        sys.modules.setdefault("rea_secure_protocol_20261022", secure)
        from ops import rea_mobile_mcp_bridge_20261022 as bridge

        names = bridge.P267_EXACT_SEQUENCE
        steps = [{"tool": name, "arguments": (
            {"path": "/usr/bin/true", "provider_id": "ghidra"}
            if name == "open_binary" else {} if name != "get_evidence_bundle"
            else {"detail": "complete"}
        )} for name in names]
        test_body = {
            "protocol": 1,
            "nonce": "0" * 32,
            "expires_at": expires(1),
            "steps": steps,
        }
        test_pin = hashlib.sha256(secure.canonical_json(test_body)).hexdigest()
        with mock.patch.object(bridge, "P267_SIGNED_CANONICAL_REQUEST_SHA256", test_pin):
            self.assertTrue(bridge.p232_guard_inner_batch(test_body))
            for name in ("open_binary", "close_binary"):
                payload = {"method": "tools/call", "params": {
                    "name": name, "arguments": (
                        {"path": "/usr/bin/true", "provider_id": "ghidra"}
                        if name == "open_binary" else {}
                    )}}
                with self.assertRaises(ValueError):
                    bridge.p232_guard_live_call(payload)
                self.assertIsNone(
                    bridge.p232_guard_live_call(payload, p267_lifecycle=True))
                mutated = {"method": "tools/call", "params": {
                    "name": name, "arguments": {"path": "/usr/bin/true"}
                }}
                with self.assertRaises(ValueError):
                    bridge.p232_guard_live_call(mutated, p267_lifecycle=True)
            changed = {**test_body, "nonce": "1" * 32}
            with self.assertRaises(ValueError):
                bridge.p232_guard_inner_batch(changed)
            other = {**test_body, "steps": [
                *steps[:2], {"tool": "open_binary", "arguments": {
                    "path": "/usr/bin/false", "provider_id": "ghidra"}},
                *steps[3:],
            ]}
            with self.assertRaises(ValueError):
                bridge.p232_guard_inner_batch(other)
        self.assertFalse(bridge.p232_guard_inner_batch(request([
            {"tool": "list_unknowns", "arguments": {}}
        ])))



if __name__ == "__main__":
    unittest.main()

