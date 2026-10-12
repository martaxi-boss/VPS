"""Safe VPS housekeeping regression: no production, session or cache symlink writes."""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import vps_housekeeping_safe as house
import vps_hygiene_050 as hygiene


class BoundedHousekeepingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "cache"
        self.root.mkdir()
        self.old = self.root / "old.bin"
        self.old.write_bytes(b"regenerable")
        cutoff = time.time() - 3 * 86400
        os.utime(self.old, (cutoff, cutoff))
        self.new = self.root / "new.bin"
        self.new.write_bytes(b"active work - must not delete")
        self.outside = self.base / "important.txt"
        self.outside.write_text("preserve", encoding="utf-8")
        (self.root / "symlink").symlink_to(self.outside)
        self.patches = [
            patch.object(house, "LOCKFILE", str(self.base / "lock")),
            patch.object(house.os, "geteuid", return_value=0),
            patch.object(hygiene, "CACHE_ROOTS", (str(self.base / "absent"), str(self.root))),
            patch.object(hygiene, "package_busy", return_value=False),
            patch.object(hygiene, "cache_open_references", return_value={str(self.root): 0}),
            patch.object(hygiene, "command", side_effect=self.command),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def command(self, args, timeout=15):
        if args[:2] == ["systemctl", "is-active"]:
            return 0, "active"
        if args == ["nginx", "-t"]:
            return 0, ""
        return 0, ""

    def test_audit_does_not_delete_anything(self):
        result = house.run("audit")
        self.assertEqual(result["status"], "AUDIT_ONLY")
        self.assertEqual(result["eligible_files"], 1)
        self.assertTrue(self.old.exists())
        self.assertTrue(self.new.exists())
        self.assertEqual(self.outside.read_text(), "preserve")
        self.assertEqual(result["runtime_sessions_deleted"], 0)

    def test_clean_removes_only_pre_audited_old_cache(self):
        result = house.run("clean")
        self.assertEqual(result["status"], "CLEANED")
        self.assertGreater(result["removed_file_bytes"], 0)
        self.assertFalse(self.old.exists())
        self.assertTrue(self.new.exists())
        self.assertEqual(self.outside.read_text(), "preserve")
        self.assertTrue(result["protected_services_unchanged"])

    def test_blocked_package_manager_cannot_delete(self):
        with patch.object(hygiene, "package_busy", return_value=True):
            result = house.run("clean")
        self.assertEqual(result["status"], "BLOCKED_PACKAGE_MANAGER")
        self.assertTrue(self.old.exists())

    def test_cache_open_reference_cannot_delete(self):
        with patch.object(hygiene, "cache_open_references", return_value={str(self.root): 1}):
            result = house.run("clean")
        self.assertEqual(result["status"], "BLOCKED_OPEN_CACHE_REFERENCES")
        self.assertTrue(self.old.exists())

    def test_symlink_cache_root_fails_before_any_deletion(self):
        link = self.base / "bad-root"
        link.symlink_to(self.root, target_is_directory=True)
        with patch.object(hygiene, "CACHE_ROOTS", (str(link), str(self.root))):
            with self.assertRaises(ValueError):
                house.run("clean")
        self.assertTrue(self.old.exists())
        self.assertEqual(self.outside.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
