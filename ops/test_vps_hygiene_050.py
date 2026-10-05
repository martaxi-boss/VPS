import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import vps_hygiene_050 as hygiene


class CacheSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "cache"
        self.root.mkdir()
        # Place test cache in a non-APT allowlist slot.
        self.roots = (str(self.base / "apt"), str(self.root))
        self.patch = patch.object(hygiene, "CACHE_ROOTS", self.roots)
        self.patch.start()
        self.cutoff = time.time_ns() - 86400 * 1000000000

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def old_file(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("disposable cache")
        os.utime(path, ns=(self.cutoff - 1000000, self.cutoff - 1000000))
        return path

    def test_only_old_regular_cache_files_removed(self):
        old = self.old_file(self.root / "old")
        recent = self.root / "recent"
        recent.write_text("recent work")
        report, entries = hygiene.cache_inventory(str(self.root), self.cutoff)
        self.assertEqual(report["eligible_files"], 1)
        hygiene.remove_candidates(str(self.root), entries)
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists())

    def test_symlink_files_and_directories_preserve_external_data(self):
        outside = self.old_file(self.base / "database" / "data")
        (self.root / "linked-file").symlink_to(outside)
        (self.root / "linked-dir").symlink_to(outside.parent, target_is_directory=True)
        _, entries = hygiene.cache_inventory(str(self.root), self.cutoff)
        self.assertEqual(entries, [])
        self.assertTrue(outside.exists())

    def test_root_and_relative_traversal_are_rejected(self):
        outside = self.old_file(self.base / "production")
        with self.assertRaises(ValueError):
            hygiene.cache_inventory(str(self.base), self.cutoff)
        with self.assertRaises(ValueError):
            hygiene.remove_candidates(str(self.root), [["../production", hygiene.metadata(outside.stat())]])
        self.assertTrue(outside.exists())

    def test_changed_files_are_preserved(self):
        old = self.old_file(self.root / "old")
        _, entries = hygiene.cache_inventory(str(self.root), self.cutoff)
        old.write_text("new cache content from another job")
        result = hygiene.remove_candidates(str(self.root), entries)
        self.assertEqual(result["changed_or_unsafe_files_preserved"], 1)
        self.assertTrue(old.exists())

    def test_swapped_parent_symlink_cannot_delete_outside_file(self):
        inside = self.old_file(self.root / "dir" / "file")
        outside = self.old_file(self.base / "production" / "file")
        _, entries = hygiene.cache_inventory(str(self.root), self.cutoff)
        inside.unlink()
        inside.parent.rmdir()
        inside.parent.symlink_to(outside.parent, target_is_directory=True)
        result = hygiene.remove_candidates(str(self.root), entries)
        self.assertEqual(result["changed_or_unsafe_files_preserved"], 1)
        self.assertTrue(outside.exists())

    def test_missing_authority_prevents_any_cleanup(self):
        with self.assertRaises(ValueError):
            hygiene.validate_payload(None)

    def test_symlink_root_is_rejected(self):
        self.root.rmdir()
        self.root.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            hygiene.cache_inventory(str(self.root), self.cutoff)

    def test_hard_links_are_preserved(self):
        outside = self.old_file(self.base / "outside-data")
        os.link(outside, self.root / "cache-link")
        _, entries = hygiene.cache_inventory(str(self.root), self.cutoff)
        self.assertEqual(entries, [])
        self.assertTrue(outside.exists())

    def test_apt_partial_downloads_and_lock_files_are_preserved(self):
        apt = Path(self.roots[0])
        apt.mkdir()
        package = self.old_file(apt / "old.deb")
        lock = self.old_file(apt / "lock")
        partial = self.old_file(apt / "partial" / "current.deb")
        _, entries = hygiene.cache_inventory(str(apt), self.cutoff)
        self.assertEqual([x[0] for x in entries], ["old.deb"])
        hygiene.remove_candidates(str(apt), entries)
        self.assertFalse(package.exists())
        self.assertTrue(lock.exists())
        self.assertTrue(partial.exists())


if __name__ == "__main__":
    unittest.main()
