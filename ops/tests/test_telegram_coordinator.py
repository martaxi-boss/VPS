"""Offline checks for private Telegram orders and Owner-verified Issues."""
import base64
import json
import unittest
from unittest import mock
from pathlib import Path
from ops import telegram_coordinator_authority as auth
from ops import telegram_coordinator_issue as issuer
from ops import telegram_gateway as gateway

BOT = "dummy-test-bot-token-never-authenticated"
PAT = "dummy-test-publisher-token-never-authenticated"
TARGET = "martaxi-boss/pink-iptv"
TASK = "Corrige os filmes e series no PINK IPTV"
TIMESTAMP = 1791945000


def signed(task=TASK, target=TARGET):
    return auth.sign_claim(BOT, 12345, target, task, issued_at=TIMESTAMP)


class FakeAPI:
    def __init__(self, *, login="martaxi-boss", writable=True, prior=None):
        self.login, self.writable, self.prior = login, writable, prior
        self.posts = 0

    def __call__(self, method, route, token, data=None):
        assert token == PAT
        if route == "user":
            return {"login": self.login}
        if route == "repos/" + TARGET:
            return {"full_name": TARGET, "owner": {"login": "martaxi-boss"},
                    "private": False, "archived": False, "default_branch": "main",
                    "permissions": {"push": self.writable}}
        if route.startswith("repos/martaxi-boss/VPS/issues?"):
            return [self.prior] if self.prior else []
        if method == "POST" and route == "repos/martaxi-boss/VPS/issues":
            self.posts += 1
            return {"number": 87, "title": data["title"], "body": data["body"],
                    "user": {"login": "martaxi-boss"}}
        raise AssertionError((method, route))


class AuthTests(unittest.TestCase):
    def test_existing_and_future_owner_projects(self):
        names = [TARGET, "martaxi-boss/VPS", "martaxi-boss/future-project"]
        self.assertEqual(auth.resolve_target(TASK, names), TARGET)
        self.assertEqual(auth.resolve_target("Corrige future project", names),
                         "martaxi-boss/future-project")

    def test_missing_ambiguous_or_foreign_target_rejected(self):
        names = [TARGET, "martaxi-boss/VPS", "other/pink-iptv"]
        for phrase in ("Corrige desconhecido", "Corrige VPS e PINK IPTV",
                       "Corrige o outro serviço"):
            with self.assertRaises(auth.OrderRefused):
                auth.resolve_target(phrase, names)

    def test_read_only_does_not_launch_workers(self):
        for task in ("Olá", "Verifica a VPS", "Audita o PINK IPTV"):
            self.assertFalse(auth.is_execution_request(task))
        self.assertTrue(auth.is_execution_request(TASK))

    def test_signed_claim_has_integrity_and_expires(self):
        encoded, mac = signed()
        verified = auth.verify_claim(BOT, encoded, mac, now=TIMESTAMP+20)
        self.assertEqual((verified["target"], verified["update_id"]), (TARGET, 12345))
        for token, mac_value, now in (
                (BOT, "0"*64, TIMESTAMP+5),
                ("other-bot-token-used-by-attacker", mac, TIMESTAMP+5),
                (BOT, mac, TIMESTAMP+7201),
                (BOT, mac, TIMESTAMP-301)):
            with self.assertRaises(auth.OrderRefused):
                auth.verify_claim(token, encoded, mac_value, now=now)

    def test_no_secrets_cross_owner_or_malformed_voice(self):
        for task, target in (
                (TASK, "attacker/test"),
                ("Corrige api_key=ABCDEF12345678 no PINK IPTV", TARGET),
                ("Corrige\x00 os filmes", TARGET),
                ("Verifica os filmes do PINK IPTV", TARGET)):
            with self.assertRaises(auth.OrderRefused):
                signed(task, target)


class IssueTests(unittest.TestCase):
    def test_creates_only_exact_owner_coordinator_issue(self):
        api = FakeAPI()
        number, created = issuer.issue_from_claim(
            *signed(), BOT, PAT, get=api, now=TIMESTAMP+30)
        self.assertEqual((number, created, api.posts), (87, True, 1))

    def test_foreign_or_nonwritable_publisher_does_not_create_issue(self):
        for api in (FakeAPI(login="github-actions[bot]"),
                    FakeAPI(writable=False)):
            with self.assertRaises(issuer.BridgeRefused):
                issuer.issue_from_claim(*signed(), BOT, PAT, get=api,
                                        now=TIMESTAMP+5)
            self.assertEqual(api.posts, 0)

    def test_bad_hmac_fails_before_external_lookups(self):
        api = FakeAPI()
        encoded, _ = signed()
        with self.assertRaises(issuer.BridgeRefused):
            issuer.issue_from_claim(encoded, "0"*64, BOT, PAT,
                                    get=api, now=TIMESTAMP+5)
        self.assertEqual(api.posts, 0)

    def test_exact_duplicate_is_idempotent_and_forged_duplicate_refused(self):
        prior = {"number": 85, "title": "[coordinator run] Telegram 12345",
                 "body": "TARGET_REPOSITORY=" + TARGET + "\n\n" + TASK,
                 "user": {"login": "martaxi-boss"}}
        api = FakeAPI(prior=prior)
        self.assertEqual(issuer.issue_from_claim(
            *signed(), BOT, PAT, get=api, now=TIMESTAMP+30), (85, False))
        self.assertEqual(api.posts, 0)
        prior["user"]["login"] = "github-actions[bot]"
        with self.assertRaises(issuer.BridgeRefused):
            issuer.issue_from_claim(*signed(), BOT, PAT, get=api,
                                    now=TIMESTAMP+30)


class GatewayTests(unittest.TestCase):
    def test_non_owner_cannot_route_any_order(self):
        msg = {"update_id": 12345, "message": {
            "chat": {"id": 765, "type": "private"},
            "from": {"id": 765, "is_bot": False}, "text": TASK}}
        with mock.patch.object(gateway, "CHAT_ID", "123"), \
             mock.patch.object(gateway, "dispatch_coordinator") as route:
            gateway.handle_update(msg)
            route.assert_not_called()

    def test_owner_natural_text_routes_without_manual_agent_rules(self):
        msg = {"update_id": 12345, "message": {
            "chat": {"id": 765, "type": "private"},
            "from": {"id": 765, "is_bot": False}, "text": TASK}}
        with mock.patch.object(gateway, "CHAT_ID", "765"), \
             mock.patch.object(gateway, "dispatch_coordinator", return_value=TARGET) as route, \
             mock.patch.object(gateway, "say") as response:
            gateway.handle_update(msg)
            route.assert_called_once_with(12345, TASK)
            self.assertIn("ainda serão verificadas", response.call_args[0][0])

    def test_no_owner_pat_in_telegram_bot_poll(self):
        root = Path(__file__).resolve().parents[2]
        bot = (root / ".github/workflows/telegram-codex-gateway.yml").read_text()
        self.assertNotIn("CODEX_GITHUB_TOKEN:",
                         bot.split("  telegram:", 1)[1].split("  observer:", 1)[0])
        trusted = (root / ".github/workflows/telegram-coordinator-owner.yml").read_text()
        self.assertIn("github.actor == 'github-actions[bot]'", trusted)
        self.assertIn("persist-credentials: false", trusted)


if __name__ == "__main__":
    unittest.main()
