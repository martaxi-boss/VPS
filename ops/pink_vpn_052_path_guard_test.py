"""Regression tests: retired Task052 must never restore global installations.

No live VPS interaction is performed. These checks cover only repository source.
"""
import subprocess
import sys
import unittest
from pathlib import Path

import pink_vpn_052_install as installer

HERE = Path(__file__).resolve().parent
PROJECT = Path("/srv/projects/pink-iptv")
LEGACY_PATHS = (
    "/etc/pink-vpn",
    "/etc/pink-iptv",
    "/var/backups/pink-iptv",
    "/var/lib/pink-vpn",
    "/srv/pink-iptv",
)
HISTORIC_MODULES = (
    "pink_vpn_052_install.py",
    "pink_vpn_052_audit.py",
    "pink_vpn_052_gateway.py",
    "pink_vpn_052_peer.py",
    "pink_vpn_052_enrollment.py",
    "pink_vpn_052_proof.py",
)


class Task052Isolation(unittest.TestCase):
    def test_source_contains_no_old_persistent_paths(self):
        for name in HISTORIC_MODULES:
            with self.subTest(module=name):
                text = (HERE / name).read_text(encoding="utf-8")
                for old_path in LEGACY_PATHS:
                    self.assertNotIn(old_path, text)

    def test_legacy_storage_points_only_inside_pink(self):
        self.assertEqual(installer.PROJECT, PROJECT)
        self.assertEqual(installer.ROOT, PROJECT / "vpn/gateway")
        self.assertEqual(installer.BACKUP, PROJECT / "backups/task052")
        self.assertEqual(installer.APP, PROJECT / "backend")

    def test_historical_install_refuses_mutation(self):
        with self.assertRaisesRegex(RuntimeError, "Task052 retired"):
            installer.install(None)

    def test_historical_cli_refuses_every_mutating_mode(self):
        script = HERE / "pink_vpn_052_install.py"
        for mode in ("install", "up", "down", "rollback", "accept"):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    [sys.executable, str(script), mode, "/unused"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("retired", completed.stderr.lower())


if __name__ == "__main__":
    unittest.main()
