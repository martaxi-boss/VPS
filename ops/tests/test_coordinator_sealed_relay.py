"""Offline verified single-use encrypted relay, no remote access or credentials."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

from ops import coordinator_sealed_relay as relay


class SealedRelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inbox = self.root / 'private'
        self.inbox.mkdir(mode=0o700)
        self.session = 'a' * 32
        self.originals = [("photo.jpg", b'\xff\xd8\xff' + b'one'),
                          ("photo-2.png", b'\x89PNG\r\n\x1a\n' + b'two'),
                          ("short-video.mp4", b'\x00\x00\x00\x14ftyp' + b'clip')]
        self.bundle = self.root / 'originals.zip'
        self._bundle()

    def _bundle(self):
        items = []
        with zipfile.ZipFile(self.bundle, 'w', compression=zipfile.ZIP_STORED) as z:
            for idx, (name, data) in enumerate(self.originals, 1):
                extension = Path(name).suffix
                stored = f'file-{idx:03d}{extension}'
                z.writestr(stored, data)
                items.append({'id': f'file-{idx:03d}', 'name': name, 'stored': stored,
                              'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
                              'mime': 'image/jpeg' if idx == 1 else 'image/png' if idx == 2 else 'video/mp4'})
            z.writestr('manifest.json', json.dumps({'version': 1, 'selection': 'owner_explicit', 'files': items}))

    def _cipher(self):
        pub = relay.request_key(self.inbox, self.session)
        encrypted = self.inbox / ('.relay-cipher-' + self.session)
        checksum, length = relay.seal(self.bundle, self.session, pub, encrypted)
        self.assertEqual(length, encrypted.stat().st_size)
        return encrypted, checksum

    def test_end_to_end_three_originals_intact_private_and_one_time(self):
        self.assertEqual(relay.TOTAL_LIMIT, 1024**3)
        encrypted, digest = self._cipher()
        count = relay.stage(self.inbox, self.session, digest)
        self.assertEqual(count, 3)
        stage = self.inbox / self.session
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
        for index, (name, content) in enumerate(self.originals, 1):
            path = stage / ('file-%03d%s' % (index, Path(name).suffix))
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(encrypted.exists())
        self.assertFalse((self.inbox / '.relay-keys' / self.session).exists())
        with self.assertRaises(relay.RelayRefused):
            relay.stage(self.inbox, self.session, digest)

    def test_modified_ciphertext_is_rejected_before_publish(self):
        encrypted, digest = self._cipher()
        data = bytearray(encrypted.read_bytes())
        data[42] ^= 1
        encrypted.write_bytes(data)
        with self.assertRaisesRegex(relay.RelayRefused, 'checksum'):
            relay.stage(self.inbox, self.session, digest)
        self.assertFalse((self.inbox / self.session).exists())

    def test_authenticated_encryption_blocks_forged_checksum_too(self):
        encrypted, _ = self._cipher()
        data = bytearray(encrypted.read_bytes())
        data[-20] ^= 1
        encrypted.write_bytes(data)
        forged_hash = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(relay.RelayRefused, 'integrity'):
            relay.stage(self.inbox, self.session, forged_hash)
        self.assertFalse((self.inbox / self.session).exists())

    def test_rejects_invalid_session_existing_key_and_destination(self):
        with self.assertRaises(relay.RelayRefused):
            relay.request_key(self.inbox, '../oops')
        self._cipher()
        with self.assertRaisesRegex(relay.RelayRefused, 'already'):
            relay.request_key(self.inbox, self.session)
        (self.inbox / self.session).mkdir(mode=0o700)
        with self.assertRaisesRegex(relay.RelayRefused, 'already'):
            relay.stage(self.inbox, self.session,
                        hashlib.sha256((self.inbox / ('.relay-cipher-' + self.session)).read_bytes()).hexdigest())

    def test_extra_zip_member_is_refused(self):
        encrypted, digest = self._cipher()
        other = self.root / 'extras.zip'
        with zipfile.ZipFile(self.bundle) as source, zipfile.ZipFile(other, 'w') as target:
            for item in source.infolist():
                target.writestr(item.filename, source.read(item.filename))
            target.writestr('secret-extra.txt', 'bad')
        # Staging cannot use the unauthenticated original; use a new session.
        session2 = 'b' * 32
        pub2 = relay.request_key(self.inbox, session2)
        extra_cipher = self.inbox / ('.relay-cipher-' + session2)
        extra_digest, _ = relay.seal(other, session2, pub2, extra_cipher)
        with self.assertRaises(relay.RelayRefused):
            relay.stage(self.inbox, session2, extra_digest)
        self.assertFalse((self.inbox / session2).exists())

    def test_reject_shared_inbox(self):
        self.inbox.chmod(0o755)
        with self.assertRaisesRegex(relay.RelayRefused, 'Unsafe'):
            relay.request_key(self.inbox, self.session)

    def test_reject_big_input_without_memory_allocation(self):
        pub = relay.request_key(self.inbox, self.session)
        sparse = self.root / 'oversized-sparse.bin'
        with sparse.open('wb') as f:
            f.truncate(relay.TOTAL_LIMIT + relay.RELAY_OVERHEAD + 1)
        with self.assertRaises(relay.RelayRefused):
            relay.seal(sparse, self.session, pub, self.root / 'too-big.bin')


if __name__ == '__main__':
    unittest.main()