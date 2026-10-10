"""No secrets or OAuth URLs may escape the diagnostic classifier."""
import importlib.util
import unittest
from pathlib import Path

f = Path(__file__).resolve().parents[1] / "agy_screen_state.py"
spec = importlib.util.spec_from_file_location("agy_screen_state", f)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ScreenTests(unittest.TestCase):
    def test_signin_menu(self):
        self.assertEqual(m.screen_state("Welcome! Sign in with Google"), "GOOGLE_SIGNIN_MENU")

    def test_code_entry(self):
        self.assertEqual(m.screen_state("Enter authorization code: "), "CODE_ENTRY_PROMPT")

    def test_google_oauth_url_never_returned(self):
        sensitive = "https://accounts.google.com/o/oauth2/v2/auth?client_id=secret-example&state=private"
        self.assertEqual(m.screen_state(sensitive), "GOOGLE_AUTH_URL_PRESENT")
        self.assertNotIn("state", m.screen_state(sensitive))

    def test_untrusted_domain_does_not_count(self):
        self.assertNotEqual(m.screen_state("https://accounts.google.com.evil.test/o/oauth2/auth?client_id=x"), "GOOGLE_AUTH_URL_PRESENT")

    def test_empty_and_other_menu(self):
        self.assertEqual(m.screen_state(""), "EMPTY_SCREEN")
        self.assertEqual(m.screen_state("Welcome to Antigravity"), "OTHER_ONBOARDING_SCREEN")


if __name__ == "__main__":
    unittest.main()
