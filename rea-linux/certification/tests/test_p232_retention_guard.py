"""Regression tests for original REA operator P232 retention HOLD (no MCP calls)."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "owner"))
from rea_p232_retention_guard import (  # noqa: E402
    RetentionGuardError,
    verify_private_inner_batch,
)

def batch(*tools):
    return {
        "protocol": 1,
        "nonce": "1" * 32,
        "expires_at": "2026-10-25T12:45:00Z",
        "steps": [
            {"tool": name, "arguments": kwargs}
            for name, kwargs in tools
        ],
    }


class RetentionGuardTests(unittest.TestCase):
    def test_read_only_bundle_allowed_without_grant(self):
        out = verify_private_inner_batch(batch(("get_evidence_bundle", {})))
        self.assertEqual(out["steps_checked"], 1)
        self.assertEqual(out["session_lifecycle_steps"], 0)

    def test_non_binary_symbol_step_allowed_but_no_authorization_granted(self):
        out = verify_private_inner_batch(batch(
            ("demangle_swift", {"symbols": ["$s4Test3fooyyF"]})))
        self.assertIn("authorizations still apply", out["caveat"])

    def test_open_binary_blocked_even_without_prior_steps(self):
        with self.assertRaisesRegex(RetentionGuardError, "open_binary"):
            verify_private_inner_batch(batch(("open_binary", {"path": "/usr/bin/true"})))

    def test_close_binary_blocked_even_with_no_arguments(self):
        with self.assertRaisesRegex(RetentionGuardError, "close_binary"):
            verify_private_inner_batch(batch(("close_binary", {})))

    def test_snapshot_close_is_still_a_reset(self):
        with self.assertRaisesRegex(RetentionGuardError, "close_binary"):
            verify_private_inner_batch(batch((
                "close_binary", {"snapshot_path": "/opt/rea-reversa/rea/snapshot.json"})))

    def test_mixed_batch_does_not_allow_late_close(self):
        with self.assertRaisesRegex(RetentionGuardError, "close_binary"):
            verify_private_inner_batch(batch(
                ("get_evidence_bundle", {}), ("close_binary", {})))

    def test_mixed_batch_blocks_implicit_open_then_cleanup(self):
        with self.assertRaisesRegex(RetentionGuardError, "open_binary"):
            verify_private_inner_batch(batch(
                ("get_evidence_bundle", {}),
                ("open_binary", {"path": "/usr/bin/true"}),
                ("list_segments", {})))

    def test_rejects_outer_sealed_envelope_instead_of_inner_payload(self):
        with self.assertRaises(RetentionGuardError):
            verify_private_inner_batch({
                "version": 1, "action": "sealed_batch", "sealed": {}, "response_key": "x"
            })

    def test_rejects_malformed_or_empty_steps(self):
        for candidate in (None, [], {}, "close_binary"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RetentionGuardError):
                    verify_private_inner_batch(candidate)
        with self.assertRaises(RetentionGuardError):
            verify_private_inner_batch(batch())

    def test_rejects_step_with_unexpected_fields(self):
        payload = batch(("get_evidence_bundle", {}))
        payload["steps"][0]["mystery_override"] = True
        with self.assertRaises(RetentionGuardError):
            verify_private_inner_batch(payload)

    def test_cli_fail_closed_exit_code_and_no_override_flag(self):
        with tempfile.TemporaryDirectory(prefix="rea-p232-test-") as folder:
            path = Path(folder) / "private-input.json"
            path.write_text(json.dumps(batch(("close_binary", {}))), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "owner" / "rea_p232_retention_guard.py"),
                 "--request", str(path)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 3)
            self.assertIn("REA_P232_RETENTION_GUARD=BLOCK", result.stderr)
            result2 = subprocess.run(
                [sys.executable, str(ROOT / "owner" / "rea_p232_retention_guard.py"),
                 "--request", str(path), "--override"], capture_output=True,
                text=True, check=False)
            self.assertNotEqual(result2.returncode, 0)

    def test_cli_safe_batch_passes_without_mutation(self):
        with tempfile.TemporaryDirectory(prefix="rea-p232-test-") as folder:
            path = Path(folder) / "private-input.json"
            path.write_text(json.dumps(batch(("list_unknowns", {}))), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "owner" / "rea_p232_retention_guard.py"),
                 "--request", str(path)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertIn("REA_P232_RETENTION_GUARD=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
