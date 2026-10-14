"""Offline security regression: legacy Codex SSH paths must fail closed."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
FINGERPRINT = "SHA256:Q7y5zs6sXWHtznlMQS/IQjcqPKdr7YEku1hWlNLvdxc"
CASES = (
    (".github/workflows/codex-chatgpt-bridge.yml", "codex-bridge-known-hosts", 7),
    (".github/workflows/codex-project-leader-safe-fix.yml", "codex-safe-fix-known-hosts", 6),
    (".github/workflows/codex-sandbox-repair.yml", "codex-sandbox-repair-known-hosts", 1),
    (".github/workflows/agent-providers-readiness.yml", "codex-provider-readiness-known-hosts", 1),
    (".github/workflows/vps-ssh-access-pr-check.yml", "vps-access-pr-known-hosts", 1),
    (".github/workflows/vps-ssh-access-check.yml", "vps-access-push-known-hosts", 1),
)


class CodexSSHTrustTests(unittest.TestCase):
    def test_existing_codex_ssh_routes_use_exact_existing_pin(self):
        for path, hostfile, count in CASES:
            with self.subTest(workflow=path):
                source = (ROOT / path).read_text(encoding="utf-8")
                self.assertNotIn("StrictHostKeyChecking=accept-new", source)
                self.assertEqual(source.count("StrictHostKeyChecking=yes"), count)
                self.assertEqual(source.count("UserKnownHostsFile=$RUNNER_TEMP/" + hostfile), count)
                self.assertEqual(source.count("HostKeyAlgorithms=ssh-ed25519"), count)
                self.assertIn(FINGERPRINT, source)
                self.assertIn("ssh-keyscan -T 15 -t ed25519 146.59.145.3", source)
                self.assertIn("ssh-keygen -lf \"$known_hosts\" -E sha256", source)
                self.assertIn("ssh-keygen -F 146.59.145.3 -f \"$known_hosts\"", source)
                self.assertLess(source.index("Verify pinned VPS SSH identity"),
                                source.index("sshpass -e ssh"))

    def test_ssh_access_probes_do_not_put_password_in_process_arguments(self):
        for path in (".github/workflows/vps-ssh-access-pr-check.yml",
                     ".github/workflows/vps-ssh-access-check.yml"):
            with self.subTest(workflow=path):
                source = (ROOT / path).read_text(encoding="utf-8")
                self.assertNotIn("sshpass -p", source)
                self.assertIn("SSHPASS: ${{ secrets.VPS_SSH_PASSWORD }}", source)
                self.assertNotIn("VPS_SSH_PASSWORD: ${{ secrets.VPS_SSH_PASSWORD }}", source)


if __name__ == "__main__":
    unittest.main()
