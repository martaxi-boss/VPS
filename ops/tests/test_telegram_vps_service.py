"""Offline regression tests: no secrets, Telegram network or Codex calls."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'telegram_vps_service.py'
spec = importlib.util.spec_from_file_location('telegram_vps_service', SOURCE)
import sys
sys.path.insert(0, str(SOURCE.parent))
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class TelegramVPSServiceTests(unittest.TestCase):
    def test_authorized_chat_only(self):
        update = {'message': {'chat': {'type': 'private', 'id': 123456},
                              'from': {'id': 123456, 'is_bot': False}}}
        with patch.object(service.gate, 'CHAT_ID', '123456'):
            self.assertTrue(service.private_message(update))
            update['message']['chat']['type'] = 'group'
            self.assertFalse(service.private_message(update))
            update['message']['chat']['type'] = 'private'
            update['message']['from']['id'] = 100
            self.assertFalse(service.private_message(update))

    def test_presence_audio_and_malformed_audio_do_not_use_codex(self):
        self.assertEqual(service.classify('Codex, estás aí?', voice=True)[0], 'presence')
        self.assertEqual(service.classify('termofil, codex, codex', voice=True)[0], 'blocked')
        self.assertEqual(service.classify('Verifica o estado da VPS', voice=True)[0], 'audit')

    def test_security_restrictions(self):
        for text in ('Codex, instala o serviço na VPS', 'Codex, apaga ficheiros',
                     'Codex, verifica token=abcdef0123456789'):
            self.assertEqual(service.classify(text, voice=True)[0], 'blocked')
        self.assertEqual(service.classify('Codex, verifica o README.md')[0], 'audit')
        self.assertEqual(service.classify('/fix código')[0], 'blocked')

    def test_update_persisted_only_once(self):
        with tempfile.TemporaryDirectory() as path, patch.object(service.gate, 'CHAT_ID', '123456'):
            bridge = service.Listener(Path(path))
            update = {'update_id': 6, 'message': {'chat': {'id': 123456, 'type': 'private'},
                     'from': {'id': 123456, 'is_bot': False}, 'text': 'Codex, verifica a VPS'}}
            with patch.object(service, 'safe_send') as send:
                bridge.receive(update)
                bridge.receive(update)
                self.assertEqual(send.call_count, 1)
            self.assertTrue((Path(path) / 'pending' / '6.json').exists())
            bridge.lock.close()

    def test_interrupted_audit_is_not_automatically_retried(self):
        with tempfile.TemporaryDirectory() as path:
            folder = Path(path) / 'inflight'
            folder.mkdir()
            (folder / '7.json').write_text('{}')
            bridge = service.Listener(Path(path))
            self.assertFalse((folder / '7.json').exists())
            self.assertEqual(bridge.status('7'), 'interrupted')
            bridge.lock.close()


if __name__ == '__main__':
    unittest.main()
