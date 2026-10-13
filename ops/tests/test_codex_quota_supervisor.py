#!/usr/bin/env python3
"""Quota Owner notifications only from real Codex snapshots; no model calls."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from ops import codex_quota_supervisor as supervisor
from ops import telegram_gateway, supervisor_audit


class QuotaSupervisorTests(unittest.TestCase):
    @staticmethod
    def sample(status="BLOCKED"):
        return {
            "version": 1, "source": "codex_app_server", "auth": "chatgpt",
            "status": status, "checked_at": 1800000000, "bucket": "codex",
            "model_specific_state": "NOT_VERIFIED",
            "owner_resumption": "REQUIRES_NEW_OWNER_ORDER",
            "windows": [{"window": "primary", "used_percent": 100 if status == "BLOCKED" else 42,
                         "duration_mins": 300, "resets_at": 1823456789}],
        }

    def test_genuine_quota_exhaustion_report_and_real_provider_reset(self):
        message = supervisor.report(self.sample(), 123456)
        self.assertIn("limite real ATINGIDO", message)
        self.assertIn("100% utilizado", message)
        self.assertIn("Reposição indicada pela conta", message)
        self.assertIn("2027-", message)
        self.assertIn("só o Owner decide", message)
        self.assertIn("https://github.com/martaxi-boss/VPS/actions/runs/123456", message)

    def test_available_quota_is_not_authorization_to_relaunch(self):
        message = supervisor.report(self.sample("AVAILABLE"), 999)
        self.assertIn("DISPONÍVEL", message)
        self.assertIn("não garante disponibilidade", message)
        self.assertIn("só o Owner decide", message)

    def test_unverified_rate_limit_is_not_called_available(self):
        sample = {"version": 1, "source": "codex_app_server",
                  "auth": "unverified", "status": "UNKNOWN"}
        self.assertIn("NÃO VERIFICADA", supervisor.report(sample, 999))
        self.assertNotIn("DISPONÍVEL", supervisor.report(sample, 999))

    def test_false_sources_api_keys_and_model_suggestion_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            for sample in (
                    {**self.sample(), "source": "local_token_ledger"},
                    {**self.sample(), "auth": "apiKey"},
                    {**self.sample(), "model_specific_state": "FAKE_OK"},
                    {**self.sample(), "owner_resumption": "AUTO_RETRY"},
            ):
                path.write_text(json.dumps(sample))
                with self.assertRaises(RuntimeError):
                    supervisor.parse_sample(path)

    def test_real_telegram_send_is_audited_and_reported_after_send(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text(json.dumps(self.sample()))
            with (patch.dict(os.environ, {"GITHUB_REPOSITORY": "martaxi-boss/VPS",
                                         "GITHUB_RUN_ID": "123456",
                                         "QUOTA_FORCE_TEST": "0"}),
                  patch.object(telegram_gateway, "BOT_TOKEN", "test"),
                  patch.object(telegram_gateway, "CHAT_ID", "123456"),
                  patch.object(telegram_gateway, "say") as send,
                  patch.object(supervisor_audit, "observation",
                               wraps=supervisor_audit.observation) as audit):
                with redirect_stdout(io.StringIO()) as out:
                    result = supervisor.main(["q", "notify", str(path), "AVAILABLE"])
                self.assertEqual(result, 0)
                audit.assert_called_once()
                self.assertEqual(audit.call_args.kwargs["source"], "quota")
                send.assert_called_once()
                self.assertIn("AUDITORIA OPERACIONAL", send.call_args.args[0])
                self.assertIn("DELIVERED_BLOCKED", out.getvalue())

    def test_no_duplicate_message_if_state_did_not_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text(json.dumps(self.sample("AVAILABLE")))
            with (patch.dict(os.environ, {"GITHUB_REPOSITORY": "martaxi-boss/VPS",
                                         "GITHUB_RUN_ID": "123456",
                                         "QUOTA_FORCE_TEST": "0"}),
                  patch.object(telegram_gateway, "say") as send):
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(supervisor.main(["q", "notify", str(path), "AVAILABLE"]), 11)
                send.assert_not_called()
                self.assertIn("UNCHANGED", out.getvalue())

    def test_delivery_failure_does_not_claim_success_or_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text(json.dumps(self.sample()))
            with (patch.dict(os.environ, {"GITHUB_REPOSITORY": "martaxi-boss/VPS",
                                         "GITHUB_RUN_ID": "123456"}),
                  patch.object(telegram_gateway, "BOT_TOKEN", "test"),
                  patch.object(telegram_gateway, "CHAT_ID", "123456"),
                  patch.object(telegram_gateway, "say",
                               side_effect=RuntimeError("telegram unavailable"))):
                self.assertEqual(supervisor.main(["q", "notify", str(path), ""]), 3)

    def test_supervisor_detects_zero_without_any_worker_message_or_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "real-provider.json"
            sample.write_text(json.dumps(self.sample("BLOCKED")), encoding="utf-8")
            # There is deliberately no Codex worker, model, report or Issue
            # in the observation environment. Supervisor watches independently.
            env = {
                "GITHUB_REPOSITORY": "martaxi-boss/VPS",
                "GITHUB_RUN_ID": "123456",
                "QUOTA_FORCE_TEST": "0",
            }
            with (patch.dict(os.environ, env, clear=True),
                  patch.object(telegram_gateway, "BOT_TOKEN", "test"),
                  patch.object(telegram_gateway, "CHAT_ID", "123456"),
                  patch.object(telegram_gateway, "say") as send,
                  patch.object(supervisor_audit, "observation",
                               wraps=supervisor_audit.observation) as audit):
                with redirect_stdout(io.StringIO()) as output:
                    result = supervisor.main(["q", "watch", str(sample), "AVAILABLE"])
                self.assertEqual(result, 0)
                self.assertIn("DELIVERED_BLOCKED", output.getvalue())
                audit.assert_called_once()
                self.assertEqual(audit.call_args.kwargs["source"], "quota")
                sent = send.call_args.args[0]
                self.assertIn("AUDITORIA OPERACIONAL", sent)
                self.assertIn("limite real ATINGIDO", sent)
                self.assertIn("não depende de mensagens dos trabalhadores", sent)
                self.assertIn("só o Owner decide", sent)

    def test_supervisor_does_not_spam_blocked_or_autoresume_on_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "actual.json"
            path.write_text(json.dumps(self.sample("BLOCKED")))
            with (patch.dict(os.environ, {
                    "GITHUB_REPOSITORY": "martaxi-boss/VPS",
                    "GITHUB_RUN_ID": "123456",
                    "QUOTA_FORCE_TEST": "0"}, clear=True),
                  patch.object(telegram_gateway, "BOT_TOKEN", "test"),
                  patch.object(telegram_gateway, "CHAT_ID", "123456"),
                  patch.object(telegram_gateway, "say") as send):
                self.assertEqual(supervisor.main(["q", "watch", str(path), "BLOCKED"]), 11)
                send.assert_not_called()
                path.write_text(json.dumps(self.sample("AVAILABLE")))
                self.assertEqual(supervisor.main(["q", "watch", str(path), "BLOCKED"]), 0)
                sent = send.call_args.args[0]
                self.assertIn("DISPONÍVEL", sent)
                self.assertIn("só o Owner decide", sent)
                self.assertNotIn("nova ordem automaticamente iniciada", sent)

    def test_only_quota_workflow_is_polled_with_no_codex_worker_execution(self):
        source = (Path(__file__).resolve().parents[2] /
                  ".github/workflows/codex-quota-watch.yml").read_text()
        self.assertIn("- cron: '*/5 * * * *'", source)
        self.assertIn("Supervisor — independent real ChatGPT quota watch", source)
        self.assertIn("python3 -m ops.codex_quota_supervisor notify", source)
        self.assertIn("python3 - read /home/ubuntu/codex-agent/node_modules/.bin/codex", source)
        self.assertIn("account", (Path(__file__).resolve().parents[1] /
                                  "codex_account_limits.py").read_text())
        self.assertNotIn("codex exec", source)
        self.assertNotIn("codex_quota_resume.py scan", source)
        self.assertNotIn("repository_dispatch:", source)
        self.assertNotIn("schedule_due(", source)

    def test_no_quota_estimates_or_worker_dispatch_in_observer(self):
        import inspect
        code = inspect.getsource(supervisor)
        for forbidden in ('"turn/start"', 'workflow_dispatch', 'repository_dispatch',
                          'codex exec', 'schedule_due('):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
