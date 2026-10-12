"""Zero-inference tests for filtered VPS Codex catalog diagnostics."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

OPS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "codex_model_inventory", OPS / "codex-model-inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class CatalogContractTests(unittest.TestCase):
    def test_visible_model_names_and_efforts_only(self):
        raw = json.dumps({"models": [
            {"slug": "gpt-5.6-sol", "visibility": "list",
             "supported_reasoning_levels": [{"effort": "low"}, {"effort": "high"}],
             "model_messages": {"instructions_template": "DO_NOT_PUBLISH"}},
            {"slug": "gpt-6-sol", "visibility": "list",
             "supported_reasoning_levels": [{"effort": "low"}, {"effort": "medium"}]},
            {"slug": "gpt-6-hidden", "visibility": "hidden",
             "base_instructions": "DO_NOT_PUBLISH"},
            {"slug": "../../secrets", "visibility": "list"},
            {"slug": "gpt-5.6-sol", "visibility": "list",
             "supported_reasoning_levels": [{"effort": "high"}]},
        ]})
        got = inventory._parse_catalog(raw)
        self.assertEqual([m["slug"] for m in got], ["gpt-5.6-sol", "gpt-6-sol"])
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(got))
        self.assertNotIn("../../secrets", json.dumps(got))
        self.assertEqual(got[1]["efforts"], ["low", "medium"])

    def test_untrusted_unparseable_or_oversized_payload_not_emitted(self):
        self.assertEqual(inventory._parse_catalog("SYSTEM MESSAGE"), [])
        self.assertEqual(inventory._parse_catalog(json.dumps({"models": [{}] * 200})), [])

    def test_auth_rejected_before_catalog_query(self):
        with mock.patch.object(inventory, "CLI") as fake_cli:
            fake_cli.is_file.return_value = True
            with mock.patch.object(inventory.os, "access", return_value=True):
                with mock.patch.object(inventory, "_execute", side_effect=[
                    ("ok", "codex-cli 0.148.0"), ("ok", "Logged in using API key")]) as run:
                    result = inventory.inspect()
        self.assertEqual(result["status"], "AUTH_UNVERIFIED")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(result["models"], [])

    def test_confirmed_login_uses_resolved_catalog_only(self):
        raw = json.dumps({"models": [{"slug": "gpt-5.6-sol",
                                        "visibility": "list",
                                        "supported_reasoning_levels": [{"effort": "low"},
                                                                     {"effort": "high"}]}]})
        with mock.patch.object(inventory, "CLI") as fake_cli:
            fake_cli.is_file.return_value = True
            with mock.patch.object(inventory.os, "access", return_value=True):
                with mock.patch.object(inventory, "_execute", side_effect=[
                    ("ok", "codex-cli 0.148.0"),
                    ("ok", "Logged in using ChatGPT"),
                    ("ok", raw)]) as run:
                    result = inventory.inspect()
        self.assertEqual(result["status"], "CATALOG_READ")
        self.assertEqual(result["auth_mode"], "chatgpt")
        self.assertEqual(result["cli_version"], "0.148.0")
        self.assertEqual([m["slug"] for m in result["models"]], ["gpt-5.6-sol"])
        self.assertEqual(run.call_count, 3)


    def test_workflow_owner_title_is_case_sensitive_before_ssh_secret(self):
        workflow = (OPS.parent / ".github/workflows/codex-model-inventory.yml").read_text(
            encoding="utf-8")
        self.assertIn("REQUEST_TITLE: ${{ github.event.issue.title }}", workflow)
        self.assertIn('test "$REQUEST_TITLE" = "$expected"', workflow)
        self.assertLess(
            workflow.index("Require case-sensitive Owner issue title"),
            workflow.index("Prepare existing SSH client only after host identity confirmation"),
        )
        self.assertNotIn("StrictHostKeyChecking=accept-new", workflow)
        self.assertIn("StrictHostKeyChecking=yes", workflow)

    def test_workflow_catalog_unknown_cannot_pass_successfully(self):
        workflow = (OPS.parent / ".github/workflows/codex-model-inventory.yml").read_text(
            encoding="utf-8")
        self.assertIn("result['status'] == 'CATALOG_READ'", workflow)
        self.assertIn("result['auth_mode'] == 'chatgpt'", workflow)
        self.assertIn("result['catalog_source'] == 'cli_resolved'", workflow)
        self.assertIn("len(result['models']) > 0", workflow)
        self.assertIn("CATALOG_UNVERIFIED_FAIL_CLOSED", workflow)
        self.assertIn("exit 3", workflow)
        self.assertLess(workflow.index("gh issue comment"), workflow.index("CATALOG_UNVERIFIED_FAIL_CLOSED"))



if __name__ == "__main__":
    unittest.main()
