#!/usr/bin/env python3
"""P246: original REA bridge P232 permanent-MCP lifecycle hold regression.

Run only against the bridge module given as an argument; all HTTP I/O mocked.
No actual MCP tool execution and no owner signing.
"""
import importlib.util
import inspect
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

if len(sys.argv) != 2:
    raise SystemExit("Expected exact original bridge module path")
source = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(source.parent))
spec = importlib.util.spec_from_file_location("rea_p246_guarded_bridge", source)
if spec is None or spec.loader is None:
    raise SystemExit("Unable to load staged original bridge")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class FakeHTTP:
    def __init__(self, data=None):
        if data is None:
            data = {"jsonrpc": "2.0", "id": 9, "result": {"tools": []}}
        self.data = json.dumps(data).encode("utf-8")
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, kind, error, tb):
        return False

    def read(self, max_size):
        return self.data


class P246RetentionHold(unittest.TestCase):
    def test_blocked_names_exact(self):
        self.assertEqual(bridge.P232_BLOCKED_MCP_TOOLS,
                         frozenset({"open_binary", "close_binary"}))

    def test_open_binary_never_reaches_network(self):
        with mock.patch.object(bridge.urllib.request, "urlopen") as network:
            with self.assertRaisesRegex(ValueError, "P232_RETENTION_HOLD"):
                bridge.request_mcp({"jsonrpc": "2.0", "id": 3,
                                    "method": "tools/call",
                                    "params": {"name": "open_binary",
                                               "arguments": {"path": "/usr/bin/true"}}})
            network.assert_not_called()

    def test_close_binary_never_reaches_network(self):
        with mock.patch.object(bridge.urllib.request, "urlopen") as network:
            with self.assertRaisesRegex(ValueError, "P232_RETENTION_HOLD"):
                bridge.request_mcp({"jsonrpc": "2.0", "id": 4,
                                    "method": "tools/call",
                                    "params": {"name": "close_binary",
                                               "arguments": {}}})
            network.assert_not_called()

    def test_open_binary_any_auth_context_is_blocked(self):
        for args in ({}, {"path": "/usr/bin/true"}):
            with self.subTest(args=args):
                bridge.p232_guard_live_call({"method": "tools/call",
                                             "params": {"name": "open_binary",
                                                        "arguments": args,
                                                        "authorization": "ignored"}})

    def test_nonbinary_read_can_reach_mock_network(self):
        with mock.patch.object(bridge.urllib.request, "urlopen",
                               return_value=FakeHTTP()) as network:
            _, result = bridge.request_mcp({"jsonrpc": "2.0", "id": 9,
                                            "method": "tools/call",
                                            "params": {"name": "list_unknowns",
                                                       "arguments": {}}})
            self.assertIn("result", result)
            network.assert_called_once()

    def test_initialize_does_not_break(self):
        with mock.patch.object(bridge.urllib.request, "urlopen",
                               return_value=FakeHTTP()) as network:
            bridge.request_mcp({"jsonrpc": "2.0", "method": "initialize",
                                "params": {}})
            network.assert_called_once()

    def test_catalog_does_not_break(self):
        with mock.patch.object(bridge.urllib.request, "urlopen",
                               return_value=FakeHTTP()) as network:
            bridge.request_mcp({"jsonrpc": "2.0", "method": "tools/list",
                                "params": {}})
            network.assert_called_once()

    def test_missing_params_rejected_before_network(self):
        with mock.patch.object(bridge.urllib.request, "urlopen") as network:
            with self.assertRaisesRegex(ValueError, "P232_RETENTION_HOLD"):
                bridge.request_mcp({"method": "tools/call"})
            network.assert_not_called()

    def test_wrong_params_type_rejected_before_network(self):
        with mock.patch.object(bridge.urllib.request, "urlopen") as network:
            with self.assertRaisesRegex(ValueError, "P232_RETENTION_HOLD"):
                bridge.request_mcp({"method": "tools/call", "params": "close_binary"})
            network.assert_not_called()

    def test_wrong_tool_name_type_rejected(self):
        with self.assertRaisesRegex(ValueError, "P232_RETENTION_HOLD"):
            bridge.p232_guard_live_call({"method": "tools/call",
                                         "params": {"name": ["close_binary"]}})

    def test_readonly_batch_stays_eligible(self):
        batch = {"protocol": 1, "steps": [{"tool": "list_unknowns", "arguments": {}},
                                          {"tool": "get_evidence_bundle",
                                           "arguments": {"detail": "summary"}}]}
        self.assertIsNone(bridge.p232_guard_inner_batch(batch))

    def test_lifecycle_first_step_blocked(self):
        with self.assertRaisesRegex(ValueError, "P232_RETENTION_HOLD"):
            bridge.p232_guard_inner_batch({"steps": [
                {"tool": "close_binary", "arguments": {}},
                {"tool": "list_unknowns", "arguments": {}}]})

    def test_lifecycle_second_step_blocked_atomically(self):
        with self.assertRaisesRegex(ValueError, "P232_RETENTION_HOLD"):
            bridge.p232_guard_inner_batch({"steps": [
                {"tool": "list_unknowns", "arguments": {}},
                {"tool": "open_binary", "arguments": {"path": "/usr/bin/true"}}]})

    def test_invalid_batch_structure_rejected(self):
        for value in (None, [], {"steps": "open_binary"}, {"steps": [None]},
                      {"steps": [{"tool": []}]}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "P232_RETENTION_HOLD"):
                    bridge.p232_guard_inner_batch(value)

    def test_sealed_preflight_before_nonce_claim_and_first_call(self):
        code = inspect.getsource(bridge.main)
        start = code.index('if data["action"] == "sealed_batch"')
        body = code[start:]
        before = body.index("secure.validate_inner(")
        hold = body.index("p232_guard_inner_batch(body)")
        nonce = body.index("secure.claim_one_use_nonce(")
        call = body.index("for idx, (step, risk) in enumerate(")
        self.assertLess(before, hold)
        self.assertLess(hold, nonce)
        self.assertLess(nonce, call)

    def test_live_gate_is_before_urllib_request(self):
        code = inspect.getsource(bridge.request_mcp)
        self.assertLess(code.index("p232_guard_live_call(payload)"),
                        code.index("urllib.request.Request("))

    def test_guard_never_requires_private_key_or_approval(self):
        code = inspect.getsource(bridge.p232_guard_inner_batch)
        self.assertNotIn("owner_signature", code)
        self.assertNotIn("rea-owner-private", code)


if __name__ == "__main__":
    unittest.main(verbosity=1, argv=[sys.argv[0]])
