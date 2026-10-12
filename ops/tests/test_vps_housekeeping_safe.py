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


    def test_atomic_swap_of_cache_final_name_never_deletes_new_file(self):
        # Simulate a writer replacing an old cache file after its metadata
        # check but immediately before the atomic move to quarantine.
        original_rename = os.rename
        saved = self.base / "writer_saved_old_cache"
        fresh = b"fresh cache written by a concurrent producer"

        def race(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
            if src == "old.bin" and src_dir_fd is not None:
                original_rename(self.old, saved)
                self.old.write_bytes(fresh)
            return original_rename(src, dst, src_dir_fd=src_dir_fd,
                                   dst_dir_fd=dst_dir_fd)

        with patch.object(house.os, "rename", side_effect=race):
            result = house.run("clean")
        self.assertEqual(result["status"], "CLEANED")
        self.assertEqual(result["removed_file_bytes"], 0)
        self.assertEqual(result["changed_or_unsafe_preserved"], 1)
        self.assertEqual(self.old.read_bytes(), fresh)
        self.assertTrue(saved.exists())
        self.assertEqual(self.outside.read_text(), "preserve")

    def test_new_cache_created_after_staging_survives_private_unlink(self):
        original_rename = os.rename
        fresh = b"new cache written after the old name was staged"
        called = []

        def race(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
            result = original_rename(src, dst, src_dir_fd=src_dir_fd,
                                     dst_dir_fd=dst_dir_fd)
            if src == "old.bin" and src_dir_fd is not None:
                called.append(True)
                self.old.write_bytes(fresh)
            return result

        with patch.object(house.os, "rename", side_effect=race):
            result = house.run("clean")
        self.assertTrue(called)
        self.assertEqual(result["status"], "CLEANED")
        self.assertGreater(result["removed_file_bytes"], 0)
        self.assertEqual(self.old.read_bytes(), fresh)
        self.assertEqual(self.outside.read_text(), "preserve")

    def test_quarantine_retains_changed_file_when_name_reoccupied(self):
        original_rename = os.rename
        saved = self.base / "writer_saved_old_cache"

        def race(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
            if src == "old.bin" and src_dir_fd is not None:
                original_rename(self.old, saved)
                self.old.write_bytes(b"new cache candidate")
            outcome = original_rename(src, dst, src_dir_fd=src_dir_fd,
                                      dst_dir_fd=dst_dir_fd)
            if src == "old.bin" and src_dir_fd is not None:
                # Producer replaces the published cache slot again.
                self.old.write_bytes(b"replacement after quarantine")
            return outcome

        with patch.object(house.os, "rename", side_effect=race):
            result = house.run("clean")
        self.assertEqual(result["status"], "BLOCKED_QUARANTINE_RECOVERY")
        self.assertGreater(result["quarantined_for_recovery"], 0)
        self.assertEqual(self.old.read_bytes(), b"replacement after quarantine")
        self.assertEqual(self.outside.read_text(), "preserve")
        self.assertTrue(list(self.root.glob(".vps-hygiene-*")))
        # Subsequent attempts must stop without deleting preserved residue.
        self.assertEqual(house.run("clean")["status"], "BLOCKED_QUARANTINE_RECOVERY")



    def test_new_cache_entry_swapped_before_move_is_preserved(self):
        original_rename = os.rename
        replaced = [False]

        def swapping_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
            if src == "old.bin" and not replaced[0]:
                replaced[0] = True
                original_rename(self.old, self.root / "preserved-original.bin")
                self.old.write_bytes(b"recent cache writer content")
            return original_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

        with patch.object(house.os, "rename", side_effect=swapping_rename):
            result = house.run("clean")
        self.assertTrue(replaced[0])
        self.assertEqual(result["status"], "CLEANED")
        self.assertEqual(result["removed_file_bytes"], 0)
        self.assertGreaterEqual(result["changed_or_unsafe_preserved"], 1)
        self.assertEqual(self.old.read_bytes(), b"recent cache writer content")
        self.assertEqual((self.root / "preserved-original.bin").read_bytes(),
                         b"regenerable")

    def test_recreated_entry_during_restore_is_preserved_and_blocks(self):
        original_rename = os.rename
        replaced = [False]

        def simultaneous_writer(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
            if src == "old.bin" and not replaced[0]:
                replaced[0] = True
                original_rename(self.old, self.root / "preserved-original.bin")
                self.old.write_bytes(b"first writer active data")
                result = original_rename(src, dst, src_dir_fd=src_dir_fd,
                                         dst_dir_fd=dst_dir_fd)
                self.old.write_bytes(b"second writer active data")
                return result
            return original_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

        with patch.object(house.os, "rename", side_effect=simultaneous_writer):
            result = house.run("clean")
        self.assertTrue(replaced[0])
        self.assertEqual(result["status"], "BLOCKED_QUARANTINE_RECOVERY")
        self.assertEqual(result["removed_file_bytes"], 0)
        self.assertGreater(result["quarantined_for_recovery"], 0)
        self.assertEqual(self.old.read_bytes(), b"second writer active data")
        self.assertEqual((self.root / "preserved-original.bin").read_bytes(),
                         b"regenerable")

    def test_existing_quarantine_blocks_new_cleanup(self):
        saved = self.root / ".vps-hygiene-recovery-required"
        saved.mkdir()
        (saved / "candidate").write_bytes(b"preserved for recovery")
        result = house.run("clean")
        self.assertEqual(result["status"], "BLOCKED_QUARANTINE_RECOVERY")
        self.assertTrue(self.old.exists())
        self.assertEqual((saved / "candidate").read_bytes(), b"preserved for recovery")



if __name__ == "__main__":
    unittest.main()
