"""Test safe extraction of the one-time Google OAuth URL."""
import importlib.util
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "antigravity_auth_capture.py"
spec = importlib.util.spec_from_file_location("antigravity_auth_capture", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class OAuthCaptureTests(unittest.TestCase):
    def test_google_oauth_url_extracted(self):
        url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&response_type=code"
        self.assertEqual(mod.login_url("Welcome\n" + url + "\nEnter authorization code:"),
                         url)

    def test_ansi_escape_does_not_leak(self):
        url = "https://accounts.google.com/o/oauth2/auth?client_id=test"
        self.assertEqual(mod.login_url("\x1b[32m" + url + "\x1b[0m"), url)

    def test_non_google_urls_rejected(self):
        for value in ("https://evil.example/o/oauth2/auth?client_id=foo",
                      "http://accounts.google.com/o/oauth2/auth?client_id=x",
                      "https://accounts.google.com.evil.test/o/oauth2/auth?client_id=x",
                      "https://antigravity.google/docs/cli/install/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mod.login_url(value)


if __name__ == "__main__":
    unittest.main()
