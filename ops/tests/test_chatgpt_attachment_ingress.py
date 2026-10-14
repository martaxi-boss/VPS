"""Offline ChatGPT fileParams to private Coordinator inbox contract tests."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ops import chatgpt_attachment_ingress as ingress
from ops import coordinator_media


class ChatGPTFileIngressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inbox = self.root / "inbox"
        self.inbox.mkdir(mode=0o700)
        self.photo = b"\xff\xd8\xff" + b"same original bytes"
        self.video = b"\x00\x00\x00\x14ftyp" + b"the original clip bytes"
        self.urls = {
            "https://files.oaiusercontent.com/private/photo?signature=SECRET1": self.photo,
            "https://files.oaiusercontent.com/private/video?signature=SECRET2": self.video,
        }
        self.files = [
            {"file_id": "file_00000000examplePhoto", "file_name": "original.jpg",
             "mime_type": "image/jpeg", "download_url": list(self.urls)[0]},
            {"file_id": "file_00000000exampleVideo", "file_name": "original.mp4",
             "mime_type": "video/mp4", "download_url": list(self.urls)[1]},
        ]
        self.fetch_calls = []

    def downloader(self, url, target, limit):
        self.fetch_calls.append(url)
        data = self.urls[url]
        target.write_bytes(data)
        target.chmod(0o600)
        return len(data)

    def stage(self, files=None, **kwargs):
        return ingress.stage(self.files if files is None else files, self.inbox,
                             verified_owner="martaxi-boss", downloader=self.downloader,
                             **kwargs)

    def test_two_originals_delivered_unchanged_to_private_coordinator_inbox(self):
        result = self.stage()
        self.assertEqual(result.file_count, 2)
        self.assertRegex(result.bundle_id, r"^[0-9a-f]{32}$")
        self.assertEqual(self.fetch_calls, list(self.urls))
        originals = coordinator_media.verify(self.inbox / result.bundle_id)
        self.assertEqual(originals[0].original.read_bytes(), self.photo)
        self.assertEqual(originals[1].original.read_bytes(), self.video)
        self.assertEqual(result.originals[0].sha256, hashlib.sha256(self.photo).hexdigest())
        self.assertEqual(result.originals[1].sha256, hashlib.sha256(self.video).hexdigest())
        self.assertNotIn("download_url", (self.inbox / result.bundle_id / "manifest.json").read_text())
        self.assertNotIn("signature=", repr(result))
        self.assertEqual((self.inbox / result.bundle_id).stat().st_mode & 0o077, 0)
        self.assertEqual([x.name for x in self.inbox.iterdir()], [result.bundle_id])

    def test_owner_authorization_is_required_before_any_file_download(self):
        with self.assertRaisesRegex(ingress.IngressRefused, "Owner"):
            ingress.stage(self.files, self.inbox, verified_owner="someone-else",
                          downloader=self.downloader)
        self.assertEqual(self.fetch_calls, [])

    def test_reject_duplicate_files_before_network(self):
        with self.assertRaisesRegex(ingress.IngressRefused, "Duplicate"):
            self.stage(files=[self.files[0], self.files[0]])
        self.assertEqual(self.fetch_calls, [])

    def test_reject_untrusted_url_and_presigned_url_redirectors(self):
        invalid = [
            "http://files.oaiusercontent.com/private/photo",
            "https://169.254.169.254/latest/meta-data/",
            "https://localhost:443/f",
            "https://files.oaiusercontent.com.evil.invalid/file",
            "https://files.oaiusercontent.com:8080/file",
            "https://user:pass@files.oaiusercontent.com/file",
            "https://files.oaiusercontent.com//internal",
        ]
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(ingress.IngressRefused):
                    self.stage(files=[dict(self.files[0], download_url=url)])
        self.assertEqual(self.fetch_calls, [])

    def test_reject_missing_and_bogus_file_parameters_before_network(self):
        for invalid in [dict(file_id=self.files[0]["file_id"]),
                        dict(self.files[0], unexpected="bad"),
                        dict(self.files[0], file_name="../../secret"),
                        dict(self.files[0], mime_type="BAD\nTYPE")]:
            with self.assertRaises(ingress.IngressRefused):
                self.stage(files=[invalid])
        self.assertEqual(self.fetch_calls, [])

    def test_incomplete_download_cannot_leave_visible_bundle(self):
        def partial(url, target, limit):
            target.write_bytes(b"half")
            target.chmod(0o600)
            return len(b"half") - 1
        with self.assertRaises(ingress.IngressRefused):
            ingress.stage(self.files, self.inbox, verified_owner="martaxi-boss",
                          downloader=partial)
        self.assertEqual(list(self.inbox.iterdir()), [])

    def test_missing_selected_file_cannot_succeed(self):
        def failing(url, target, limit):
            if "video" in url:
                raise ingress.IngressRefused("Private file download could not be completed")
            return self.downloader(url, target, limit)
        with self.assertRaises(ingress.IngressRefused):
            ingress.stage(self.files, self.inbox, verified_owner="martaxi-boss",
                          downloader=failing)
        self.assertEqual(list(self.inbox.iterdir()), [])

    def test_refuse_open_or_symlinked_inbox(self):
        self.inbox.chmod(0o755)
        with self.assertRaises(ingress.IngressRefused):
            self.stage()
        self.inbox.chmod(0o700)
        other = self.root / "link"
        other.symlink_to(self.inbox, target_is_directory=True)
        with self.assertRaisesRegex(ingress.IngressRefused, "symlink"):
            ingress.stage(self.files, other, verified_owner="martaxi-boss",
                          downloader=self.downloader)
        self.assertEqual(self.fetch_calls, [])

    def test_official_chatgpt_mcp_file_params_contract(self):
        descriptor = json.loads((Path(__file__).parents[1] /
                                 "chatgpt_coordinator_file_tool.json").read_text())
        self.assertEqual(descriptor["_meta"]["openai/fileParams"], ["files"])
        f = descriptor["inputSchema"]["$defs"]["OpenAIFile"]
        self.assertEqual(set(f["properties"]), {"download_url", "file_id", "mime_type", "file_name"})
        self.assertEqual(set(f["required"]), {"download_url", "file_id"})
        self.assertEqual(descriptor["inputSchema"]["properties"]["files"]["type"], "array")
        self.assertFalse(descriptor["annotations"]["readOnlyHint"])


if __name__ == "__main__":
    unittest.main()