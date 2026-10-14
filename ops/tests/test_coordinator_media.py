"""Offline no-network regression tests for explicit private Coordinator attachments."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from ops import coordinator_media as media


class CoordinatorMediaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.src = self.root / "photos.jpg"
        self.src.write_bytes(b"\xff\xd8\xff" + b"image-test")
        self.src.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def bundle(self):
        return media.pack([self.src], self.root / "private")

    def test_pack_preserves_original_and_selected_digest(self):
        root = self.bundle()
        items = media.verify(root)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].original.read_bytes(), self.src.read_bytes())
        self.assertEqual(items[0].name, "photos.jpg")
        self.assertEqual(items[0].mime, "image/jpeg")
        self.assertEqual(items[0].original.stat().st_mode & 0o077, 0)
        self.assertEqual(items[0].original.parent.stat().st_mode & 0o077, 0)

    def test_one_gib_limit_without_allocating_one_gib_during_tests(self):
        self.assertEqual(media.MAX_TOTAL_BYTES, 1024 ** 3)
        self.assertEqual(media.MAX_FILE_BYTES, 1024 ** 3)
        self.assertEqual(media.TRANSFER_CHUNK_BYTES, 1024 ** 2)
        # Test the very same aggregate branch with a lowered test-only cap.
        with mock.patch.object(media, "MAX_TOTAL_BYTES", self.src.stat().st_size - 1):
            with self.assertRaisesRegex(media.MediaRefused, "size limit"):
                media.pack([self.src], self.root / "over-limit")
        self.assertFalse((self.root / "over-limit").exists())

    def test_bundle_pack_copies_original_in_streamed_blocks(self):
        large = self.root / "movie.mp4"
        large.write_bytes(b"v" * (media.TRANSFER_CHUNK_BYTES * 3 + 9))
        large.chmod(0o600)
        target = media.pack([large], self.root / "streaming-video")
        items = media.verify(target)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].size, large.stat().st_size)
        self.assertEqual(items[0].sha256, media._sha256(large)[0])

    def test_missing_original_is_refused(self):
        root = self.bundle()
        (root / "file-001.jpg").unlink()
        with self.assertRaisesRegex(media.MediaRefused, "missing"):
            media.verify(root)

    def test_modified_original_is_refused(self):
        root = self.bundle()
        (root / "file-001.jpg").write_bytes(b"tampered")
        with self.assertRaisesRegex(media.MediaRefused, "digest"):
            media.verify(root)

    def test_symlinked_original_is_refused(self):
        root = self.bundle()
        file = root / "file-001.jpg"
        file.unlink()
        file.symlink_to(self.src)
        with self.assertRaisesRegex(media.MediaRefused, "unsafe"):
            media.verify(root)

    def test_private_directory_required(self):
        root = self.bundle()
        root.chmod(0o755)
        with self.assertRaisesRegex(media.MediaRefused, "owner-only"):
            media.verify(root)

    def test_unselected_extra_file_refused(self):
        root = self.bundle()
        (root / "extra.mp4").write_bytes(b"extra")
        with self.assertRaisesRegex(media.MediaRefused, "Unexpected"):
            media.verify(root)

    def test_unknown_media_remains_original_and_is_not_misrepresented(self):
        binary = self.root / "opaque.dat"
        binary.write_bytes(b"opaque information")
        binary.chmod(0o600)
        root = media.pack([binary], self.root / "unknown")
        self.assertEqual(media.verify(root)[0].mime, "application/octet-stream")
        result = media.prepare(root, self.root / "preview")
        self.assertEqual(len(result.images), 0)
        self.assertIn("NOT VERIFIED", result.notes[0])

    def test_visual_image_passed_unchanged(self):
        root = self.bundle()
        result = media.prepare(root, self.root / "preview")
        self.assertEqual(len(result.images), 1)
        self.assertEqual(result.images[0].read_bytes(), self.src.read_bytes())
        self.assertEqual(result.originals[0].sha256, media._sha256(self.src)[0])

    def test_media_video_requires_real_preview_not_fabrication(self):
        binary = self.root / "clip.mp4"
        binary.write_bytes(b"this is not a real mp4")
        binary.chmod(0o600)
        root = media.pack([binary], self.root / "video")
        with self.assertRaisesRegex(media.MediaRefused, "incomplete|generator|duration"):
            media.prepare(root, self.root / "frames")

    def test_reject_manifest_added_paths(self):
        root = self.bundle()
        manifest = root / "manifest.json"
        data = json.loads(manifest.read_text())
        data["files"][0]["stored"] = "../file-001.jpg"
        manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(media.MediaRefused, "Unsafe"):
            media.verify(root)

    def test_reject_duplicate_and_partial_selection(self):
        with self.assertRaisesRegex(media.MediaRefused, "Invalid number"):
            media.pack([], self.root / "empty")
        root = self.bundle()
        manifest = root / "manifest.json"
        data = json.loads(manifest.read_text())
        data["files"].append(dict(data["files"][0]))
        manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(media.MediaRefused, "Unsafe"):
            media.verify(root)

    def test_cannot_overwrite_existing_destination(self):
        root = self.bundle()
        with self.assertRaisesRegex(media.MediaRefused, "already exist"):
            media.pack([self.src], root)


if __name__ == "__main__":
    unittest.main()