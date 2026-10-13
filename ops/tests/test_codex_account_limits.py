#!/usr/bin/env python3
"""Provider-authenticated quota must be real; never start a paid model to test."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ops import codex_account_limits as q


class RateLimitProbeTests(unittest.TestCase):
    account = {"account": {"type": "chatgpt", "email": "private@example.com"}}

    @staticmethod
    def rate(used=34, reset=1823456789):
        return {"rateLimits": {"limitId": "codex",
                               "primary": {"usedPercent": used,
                                           "windowDurationMins": 300,
                                           "resetsAt": reset},
                               "secondary": {"usedPercent": 24,
                                             "windowDurationMins": 10080,
                                             "resetsAt": reset + 600},
                               "rateLimitReachedType": None}}

    def test_true_codex_bucket_from_real_protocol_not_synthetic_ledger(self):
        data = q.summarize(self.account, self.rate(), now=1800000000)
        self.assertEqual(data["status"], "AVAILABLE")
        self.assertEqual(data["auth"], "chatgpt")
        self.assertEqual(data["source"], "codex_app_server")
        self.assertEqual(data["windows"][0]["used_percent"], 34)
        self.assertEqual(data["windows"][0]["resets_at"], 1823456789)
        self.assertEqual(data["model_specific_state"], "NOT_VERIFIED")
        self.assertEqual(data["owner_resumption"], "REQUIRES_NEW_OWNER_ORDER")
        self.assertNotIn("private@example.com", json.dumps(data))

    def test_live_provider_blocked_never_infers_percentages(self):
        data = q.summarize(self.account, self.rate(used=100), now=1800000000)
        self.assertEqual(data["status"], "BLOCKED")
        self.assertEqual(data["windows"][0]["used_percent"], 100)
        variant = self.rate(used=21)
        variant["rateLimits"]["rateLimitReachedType"] = "workspace_member_usage_limit_reached"
        self.assertEqual(q.summarize(self.account, variant, now=1800000000)["status"], "BLOCKED")
        variant = self.rate(used=2)
        variant["rateLimits"]["spendControlReached"] = True
        self.assertEqual(q.summarize(self.account, variant, now=1800000000)["status"], "BLOCKED")

    def test_api_keys_missing_codex_bucket_and_unknown_data_refused(self):
        for account in ({"account": {"type": "apiKey"}}, {"account": None}):
            with self.assertRaises(q.ProbeError):
                q.summarize(account, self.rate())
        for body in ({"rateLimits": {"limitId": "fake"}},
                     {"rateLimits": {"limitId": "codex", "primary": None}},
                     self.rate(101),
                     self.rate(-1),
                     self.rate(2, "untrusted"),
                     {"rateLimits": {"limitId": "codex", "primary": {
                         "usedPercent": True}}}):
            with self.subTest(body=body):
                with self.assertRaises(q.ProbeError):
                    q.summarize(self.account, body)

    def test_actual_app_server_rpc_transport_with_fake_offline_server(self):
        fake = r'''#!/usr/bin/env python3
import json, sys
if sys.argv[1:] == ["login", "status"]:
    print("Logged in using ChatGPT")
    raise SystemExit(0)
if sys.argv[1:] != ["app-server", "--stdio"]:
    raise SystemExit(45)
for line in sys.stdin:
    value = json.loads(line)
    key = value.get("id")
    if key is None:
        continue
    if key == 1:
        result = {"userAgent": "offline-fake"}
    elif key == 2:
        result = {"account": {"type": "chatgpt",
                              "email": "NEVER_LEAK_THIS@example.com"}}
    elif key == 3:
        result = {"rateLimits": {"limitId": "codex",
                    "primary": {"usedPercent": 69, "windowDurationMins": 300,
                                "resetsAt": 1823456789},
                    "secondary": None}}
    else:
        raise SystemExit(46)
    print(json.dumps({"id": key, "result": result}), flush=True)
'''
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "codex-test"
            script.write_text(fake, encoding="utf-8")
            script.chmod(0o700)
            with patch.dict(os.environ, {"OPENAI_API_KEY": "", "CODEX_API_KEY": ""}):
                data = q.read_provider(str(script), now=1800000000)
            self.assertEqual(data["status"], "AVAILABLE")
            self.assertEqual(data["windows"][0]["used_percent"], 69)
            self.assertNotIn("NEVER_LEAK_THIS", json.dumps(data))

    def test_script_fail_closed_unknown_without_any_private_material(self):
        with patch.object(q, "read_provider", side_effect=q.ProbeError("CODEX_APP_SERVER_TIMEOUT")):
            import io
            from contextlib import redirect_stdout
            stream = io.StringIO()
            with redirect_stdout(stream):
                code = q.main(["codex_account_limits.py", "read", "/abs/codex"])
            self.assertEqual(code, 3)
            data = json.loads(stream.getvalue())
            self.assertEqual(data["status"], "UNKNOWN")
            self.assertEqual(data["reason"], "CODEX_APP_SERVER_TIMEOUT")
            self.assertNotIn("token", stream.getvalue())

    def test_api_key_environment_fails_before_probing_any_model(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "hidden"}):
            with self.assertRaises(q.ProbeError):
                q.read_provider("/nonexistent/codex")

    def test_no_paid_turn_or_auth_token_api_calls(self):
        import inspect
        source = inspect.getsource(q)
        self.assertNotIn('"thread/start"', source)
        self.assertNotIn('"turn/start"', source)
        self.assertNotIn('"/login"', source)
        self.assertNotIn('refreshToken": True', source)
        self.assertNotIn('"account/rateLimitResetCredit/consume"', source)


if __name__ == "__main__":
    unittest.main()
