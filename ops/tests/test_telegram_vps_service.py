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

    def test_agent_names_are_explicitly_routed(self):
        self.assertEqual(service.classify('Boa tarde Codex'), ('presence', 'Codex'))
        self.assertEqual(service.classify('Boa tarde Gemini'), ('presence', 'Gemini'))
        self.assertEqual(service.classify('Boa tarde Geminai'), ('presence', 'Gemini'))
        self.assertEqual(service.classify('Gemini, verifica a VPS')[0], 'blocked')
        self.assertEqual(service.classify('Gemini, verifica a VPS',
                                          active_agent='Codex')[0], 'blocked')
        self.assertEqual(service.classify('Verifica a VPS', voice=True,
                                          active_agent='Gemini')[0], 'blocked')
        self.assertEqual(service.classify('Verifica a VPS', voice=True,
                                          active_agent='Codex')[0], 'audit')
        self.assertEqual(service.classify('Verifica a VPS',
                                          active_agent='Codex')[0], 'audit')
        self.assertEqual(service.classify('Olá Codex, verifica o estado da VPS')[0], 'audit')
        self.assertEqual(service.classify('Codex, como estás hoje?')[0], 'blocked')

    def test_selection_persists_and_late_audio_cannot_switch_newer_agent(self):
        with tempfile.TemporaryDirectory() as path, patch.object(service.gate, 'CHAT_ID', '123456'):
            bridge = service.Listener(Path(path))
            def update(uid, text=None, voice=None):
                msg = {'chat': {'id': 123456, 'type': 'private'},
                       'from': {'id': 123456, 'is_bot': False}}
                if text is not None:
                    msg['text'] = text
                if voice is not None:
                    msg['voice'] = voice
                return {'update_id': uid, 'message': msg}
            with patch.object(service, 'safe_send', return_value=True), patch.object(service, 'run_audit') as paid:
                bridge.receive(update(10, 'Boa tarde Codex'))
                self.assertEqual(bridge.current_agent(), 'Codex')
                bridge.receive(update(11, voice={'file_id': 'AwACAgQAAAAAAAABBBBB',
                                                  'duration': 3}))
                queued = __import__('json').loads(
                    (Path(path) / 'pending' / '11.json').read_text())
                self.assertEqual(queued['_routing_agent'], 'Codex')
                bridge.receive(update(12, 'Boa tarde Gemini'))
                self.assertEqual(bridge.current_agent(), 'Gemini')
                bridge.remember_agent('Codex', 11)
                self.assertEqual(bridge.current_agent(), 'Gemini')
                bridge.receive(update(13, 'Verifica a VPS'))
                self.assertEqual(bridge.status('13'), 'rejected')
                paid.assert_not_called()
            bridge.lock.close()
            resumed = service.Listener(Path(path))
            self.assertEqual(resumed.current_agent(), 'Gemini')
            resumed.lock.close()

    def test_failed_greeting_reply_is_not_marked_delivered(self):
        with tempfile.TemporaryDirectory() as path, patch.object(service.gate, 'CHAT_ID', '123456'):
            bridge = service.Listener(Path(path))
            update = {'update_id': 8,
                      'message': {'chat': {'id': 123456, 'type': 'private'},
                                  'from': {'id': 123456, 'is_bot': False},
                                  'text': 'Boa tarde Codex'}}
            with patch.object(service, 'safe_send', return_value=False):
                with self.assertRaisesRegex(RuntimeError, 'Reply delivery failed'):
                    bridge.receive(update)
            self.assertFalse((Path(path) / 'done' / '8.json').exists())
            bridge.lock.close()

    def test_named_multiagent_handoff_fails_closed(self):
        request = ('Oh Codex executa o projeto e quando acabares os tokens '
                   'passa para o Composer acabar')
        for voice in (False, True):
            kind, reply = service.classify(request, voice=voice,
                                           active_agent='Codex')
            self.assertEqual(kind, 'blocked')
            self.assertIn('Composer', reply)
        self.assertEqual(service.classify('Boa tarde Composer'),
                         ('presence', 'Composer'))
        self.assertEqual(service.classify('Oh Codex'), ('presence', 'Codex'))
        self.assertEqual(service.classify('Composer, continua o projeto',
                                          active_agent='Codex')[0], 'blocked')
        self.assertEqual(service.classify('/agentes')[0], 'agents')

    def test_composer_selected_not_alternative_codex(self):
        with tempfile.TemporaryDirectory() as path, patch.object(service.gate, 'CHAT_ID', '123456'):
            bridge = service.Listener(Path(path))
            def update(uid, text):
                return {'update_id': uid,
                        'message': {'chat': {'id': 123456, 'type': 'private'},
                                    'from': {'id': 123456, 'is_bot': False},
                                    'text': text}}
            with patch.object(service, 'safe_send', return_value=True), \
                 patch.object(service, 'run_audit') as run:
                bridge.receive(update(20, 'Boa tarde Composer'))
                self.assertEqual(bridge.current_agent(), 'Composer')
                bridge.receive(update(21, 'Executa o projeto'))
                self.assertEqual(bridge.status('21'), 'rejected')
                bridge.receive(update(22, 'Oh Codex'))
                self.assertEqual(bridge.current_agent(), 'Codex')
                bridge.receive(update(23, '/agentes'))
                self.assertEqual(bridge.status('23'), 'agents')
                run.assert_not_called()
            bridge.lock.close()

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
