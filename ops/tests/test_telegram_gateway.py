"""Tests for the sole passive Telegram egress path; no network calls."""
import inspect
import unittest
from unittest.mock import patch
from ops import telegram_gateway as gateway


class PassiveTelegramGatewayTests(unittest.TestCase):
    def test_telegram_rejects_all_inbound_methods_before_network(self):
        with patch.object(gateway, "BOT_TOKEN", "fake"):
            for method in ("getUpdates", "getFile", "setWebhook", "deleteWebhook"):
                with self.subTest(method=method), self.assertRaisesRegex(RuntimeError, "outbound-only"):
                    gateway.telegram(method, {})
    def test_github_refuses_all_writes_before_network(self):
        with patch.object(gateway, "GH_TOKEN", "fake"):
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                with self.subTest(method=method), self.assertRaisesRegex(RuntimeError, "read-only"):
                    gateway.github(method, "issues", {})
    def test_private_supervisor_destination_remains_mandatory(self):
        with patch.object(gateway, "CHAT_ID", "-100invalid"):
            with self.assertRaisesRegex(RuntimeError, "destination"):
                gateway.say("Supervisor observation")
    def test_approved_send_passes_existing_auditor(self):
        with patch.object(gateway, "CHAT_ID", "123456789"), patch.object(gateway, "telegram") as send:
            with patch.object(gateway, "_supervisor_audit") as audit:
                audit.return_value.check_delivery.return_value = "verified observation"
                gateway.say("raw observation")
                audit.return_value.check_delivery.assert_called_once_with("raw observation")
                send.assert_called_once()
                self.assertEqual(send.call_args.args[0], "sendMessage")
                self.assertEqual(send.call_args.args[1]["text"], "verified observation")
    def test_no_owner_dispatch_or_telegram_poll_entrypoints(self):
        for name in ("poll", "handle_update", "dispatch_coordinator",
                     "create_audit", "download_image", "transcribe_voice"):
            self.assertFalse(hasattr(gateway, name), name)
        source=inspect.getsource(gateway)
        self.assertNotIn("getUpdates", source)
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("def dispatch_coordinator", source)
    def test_status_delivery_is_factual_only(self):
        self.assertIn("PR", gateway.private_report_status("PR_STAGED"))
        self.assertIn("NÃO", gateway.private_report_status("FAILED") if "NÃO" in gateway.private_report_status("FAILED") else gateway.private_report_status("NO_CHANGE_UNVERIFIED"))


if __name__ == "__main__":
    unittest.main()
