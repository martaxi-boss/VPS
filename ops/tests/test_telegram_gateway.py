#!/usr/bin/env python3
"""Offline safety tests for the Telegram gateway (no bot or GitHub tokens)."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "telegram_gateway.py"
spec = importlib.util.spec_from_file_location("telegram_gateway", SOURCE)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class TelegramGatewayTests(unittest.TestCase):
    def test_parse_audit_commands(self):
        self.assertEqual(gateway.parse_audit("/audit Inspeciona README.md"),
                         "Inspeciona README.md")
        self.assertEqual(gateway.parse_audit("/codex Faz auditoria"),
                         "Faz auditoria")
        self.assertEqual(gateway.parse_audit("Codex, faz uma auditoria"),
                         "faz uma auditoria")
        self.assertIsNone(gateway.parse_audit("Ola, tudo bem?"))

    def test_unauthorized_chat_does_not_trigger_actions(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "github") as gh,
              patch.object(gateway, "telegram") as tg):
            gateway.handle_update({
                "update_id": 10,
                "message": {
                    "chat": {"type": "private", "id": 987654},
                    "from": {"id": 987654, "is_bot": False},
                    "text": "/audit Faz auditoria ao README"
                }
            })
            gh.assert_not_called()
            tg.assert_not_called()

    def test_groups_rejected_even_for_authorized_id(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "github") as gh,
              patch.object(gateway, "telegram") as tg):
            gateway.handle_update({
                "update_id": 11,
                "message": {
                    "chat": {"type": "group", "id": 123456},
                    "from": {"id": 123456, "is_bot": False},
                    "text": "/audit Faz auditoria ao README"
                }
            })
            gh.assert_not_called()
            tg.assert_not_called()

    def test_private_audit_dispatches_exactly_once(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "existing_issue", return_value=None),
              patch.object(gateway, "has_dispatch_marker", return_value=False),
              patch.object(gateway, "github") as gh,
              patch.object(gateway, "say") as send):
            gh.side_effect = [
                {"number": 246}, {},
                {},
            ]
            number = gateway.create_audit(654321, "Ler README em seguranca")
            self.assertEqual(number, 246)
            self.assertEqual(gh.call_count, 3)
            self.assertIn("actions/workflows/codex-chatgpt-bridge.yml/dispatches",
                          gh.call_args_list[1].args[1])
            self.assertEqual(gh.call_args_list[1].args[2]["inputs"]["source"],
                             "telegram")
            send.assert_not_called()

    def test_existing_dispatched_issue_is_not_dispatched_twice(self):
        with (patch.object(gateway, "existing_issue", return_value=999),
              patch.object(gateway, "has_dispatch_marker", return_value=True),
              patch.object(gateway, "github") as gh):
            self.assertEqual(gateway.create_audit(5, "Read-only audit"), 999)
            gh.assert_not_called()

    def test_credential_like_task_rejected(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "create_audit") as create,
              patch.object(gateway, "say") as send):
            gateway.handle_update({
                "update_id": 20,
                "message": {
                    "chat": {"type": "private", "id": 123456},
                    "from": {"id": 123456, "is_bot": False},
                    "text": "/audit Usa password=verysecret123456"
                }
            })
            create.assert_not_called()
            self.assertIn("credenciais", send.call_args[0][0])

    def test_notification_contains_entire_short_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            report.write_text("A auditoria ficou bem.", encoding="utf-8")
            env = {
                "CODEX_JOB_STATUS": "success",
                "CODEX_REPORT_PATH": str(report),
                "CODEX_ISSUE_NUMBER": "17",
                "CODEX_RUN_URL": "https://github.com/example/actions/runs/15"
            }
            with (patch.dict(os.environ, env),
                  patch.object(gateway, "BOT_TOKEN", "test"),
                  patch.object(gateway, "CHAT_ID", "123456"),
                  patch.object(gateway, "say") as send,
                  patch.object(gateway, "telegram") as tg):
                gateway.notify()
                self.assertIn("A auditoria ficou bem.", send.call_args[0][0])
                tg.assert_not_called()

    def test_long_report_sent_as_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            report.write_text("X" * 4200, encoding="utf-8")
            with (patch.dict(os.environ, {"CODEX_REPORT_PATH": str(report)}),
                  patch.object(gateway, "BOT_TOKEN", "test"),
                  patch.object(gateway, "CHAT_ID", "123456"),
                  patch.object(gateway, "say") as send,
                  patch.object(gateway, "telegram") as tg):
                gateway.notify()
                self.assertIn("ficheiro", send.call_args[0][0])
                self.assertEqual(tg.call_args.kwargs["document"][1], b"X" * 4200)


if __name__ == "__main__":
    unittest.main()
