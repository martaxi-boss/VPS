#!/usr/bin/env python3
"""Offline safety tests for the Telegram gateway (no bot or GitHub tokens)."""
import importlib.util
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "telegram_gateway.py"
spec = importlib.util.spec_from_file_location("telegram_gateway", SOURCE)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class TelegramGatewayTests(unittest.TestCase):
    def test_parse_audit_commands(self):
        self.assertEqual(gateway.parse_audit("/audit Inspeciona README.md"),
                         "Inspeciona README.md")
        self.assertEqual(gateway.parse_audit("/codex Faz auditoria"),
                         "Faz auditoria")
        self.assertEqual(gateway.parse_audit("Codex, faz uma auditoria"),
                         "faz uma auditoria")
        self.assertIsNone(gateway.parse_audit("Ola, tudo bem?"))

    def test_unauthorized_chat_does_not_trigger_actions(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "github") as gh,
              patch.object(gateway, "telegram") as tg):
            gateway.handle_update({
                "update_id": 10,
                "message": {
                    "chat": {"type": "private", "id": 987654},
                    "from": {"id": 987654, "is_bot": False},
                    "text": "/audit Faz auditoria ao README"
                }
            })
            gh.assert_not_called()
            tg.assert_not_called()

    def test_groups_rejected_even_for_authorized_id(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "github") as gh,
              patch.object(gateway, "telegram") as tg):
            gateway.handle_update({
                "update_id": 11,
                "message": {
                    "chat": {"type": "group", "id": 123456},
                    "from": {"id": 123456, "is_bot": False},
                    "text": "/audit Faz auditoria ao README"
                }
            })
            gh.assert_not_called()
            tg.assert_not_called()

    def test_private_audit_dispatches_exactly_once(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "existing_issue", return_value=None),
              patch.object(gateway, "has_dispatch_marker", return_value=False),
              patch.object(gateway, "github") as gh,
              patch.object(gateway, "say") as send):
            gh.side_effect = [
                {"number": 246}, {},
                {},
            ]
            number = gateway.create_audit(654321, "Ler README em seguranca")
            self.assertEqual(number, 246)
            self.assertEqual(gh.call_count, 3)
            self.assertIn("actions/workflows/codex-chatgpt-bridge.yml/dispatches",
                          gh.call_args_list[1].args[1])
            self.assertEqual(gh.call_args_list[1].args[2]["inputs"]["source"],
                             "telegram")
            send.assert_not_called()

    def test_existing_dispatched_issue_is_not_dispatched_twice(self):
        with (patch.object(gateway, "existing_issue", return_value=999),
              patch.object(gateway, "has_dispatch_marker", return_value=True),
              patch.object(gateway, "github") as gh):
            self.assertEqual(gateway.create_audit(5, "Read-only audit"), 999)
            gh.assert_not_called()

    def test_credential_like_task_rejected(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "create_audit") as create,
              patch.object(gateway, "say") as send):
            gateway.handle_update({
                "update_id": 20,
                "message": {
                    "chat": {"type": "private", "id": 123456},
                    "from": {"id": 123456, "is_bot": False},
                    "text": "/audit Usa password=verysecret123456"
                }
            })
            create.assert_not_called()
            self.assertIn("credenciais", send.call_args[0][0])

    def test_notification_contains_entire_short_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            report.write_text("A auditoria ficou bem.", encoding="utf-8")
            env = {
                "CODEX_JOB_STATUS": "success",
                "CODEX_REPORT_PATH": str(report),
                "CODEX_ISSUE_NUMBER": "17",
                "CODEX_RUN_URL": "https://github.com/example/actions/runs/15"
            }
            with (patch.dict(os.environ, env),
                  patch.object(gateway, "BOT_TOKEN", "test"),
                  patch.object(gateway, "CHAT_ID", "123456"),
                  patch.object(gateway, "say") as send,
                  patch.object(gateway, "telegram") as tg):
                gateway.notify()
                self.assertIn("A auditoria ficou bem.", send.call_args[0][0])
                tg.assert_not_called()

    def test_long_report_sent_as_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            report.write_text("X" * 4200, encoding="utf-8")
            with (patch.dict(os.environ, {"CODEX_REPORT_PATH": str(report)}),
                  patch.object(gateway, "BOT_TOKEN", "test"),
                  patch.object(gateway, "CHAT_ID", "123456"),
                  patch.object(gateway, "say") as send,
                  patch.object(gateway, "telegram") as tg):
                gateway.notify()
                self.assertIn("ficheiro", send.call_args[0][0])
                self.assertEqual(tg.call_args.kwargs["document"][1], b"X" * 4200)


    def test_photo_attachment_with_or_without_caption(self):
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "create_audit", return_value=54) as create,
              patch.object(gateway, "say") as send):
            message = {
                "update_id": 333,
                "message": {
                    "chat": {"type": "private", "id": 123456},
                    "from": {"id": 123456, "is_bot": False},
                    "photo": [
                        {"file_id": "AgACAgQAAAAAAAABBBBB", "file_size": 15424},
                    ],
                },
            }
            gateway.handle_update(message)
            create.assert_called_once()
            self.assertIn("Analisa a captura", create.call_args.args[1])
            self.assertEqual(create.call_args.kwargs["image"]["ext"], "jpg")
            self.assertIn("Imagem enviada", send.call_args.args[0])

    def test_image_document_rejects_nonimage_and_excessive_size(self):
        allowed = {
            "document": {"file_id": "AgACAgQAAAAAAAABBBBB", "mime_type": "image/png",
                         "file_size": 123}
        }
        self.assertEqual(gateway.select_image(allowed)["ext"], "png")
        self.assertIsNone(gateway.select_image({
            "document": {"file_id": "AgACAgQAAAAAAAABBBBB",
                         "mime_type": "application/pdf"}
        }))
        with self.assertRaises(RuntimeError):
            gateway.select_image({
                "photo": [{"file_id": "AgACAgQAAAAAAAABBBBB",
                           "file_size": 12 * 1024 * 1024}]
            })

    def test_photo_task_stores_hash_not_file_id_in_public_issue(self):
        image = {"file_id": "AgACAgQAAAAAAAABBBBB", "ext": "jpg"}
        hashed = hashlib.sha256(image["file_id"].encode("ascii")).hexdigest()
        with (patch.object(gateway, "existing_issue", return_value=None),
              patch.object(gateway, "has_dispatch_marker", return_value=False),
              patch.object(gateway, "github") as gh):
            gh.side_effect = [{"number": 888}, {}, {}]
            self.assertEqual(gateway.create_audit(
                666, "Ler o erro nesta imagem", image=image), 888)
            issue_body = gh.call_args_list[0].args[2]["body"]
            self.assertNotIn(image["file_id"], issue_body)
            self.assertIn(hashed, issue_body)
            payload = gh.call_args_list[1].args[2]["inputs"]
            self.assertEqual(payload["image_file_id"], image["file_id"])
            self.assertEqual(payload["image_ext"], "jpg")

    def test_download_private_png_from_telegram_to_ephemeral_path(self):
        png = b"\x89PNG\r\n\x1a\n" + b"temporary-private-image"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "codex-input.png"
            env = {
                "CODEX_IMAGE_FILE_ID": "AgACAgQAAAAAAAABBBBB",
                "CODEX_IMAGE_EXT": "png",
                "CODEX_IMAGE_OUTPUT": str(path),
            }
            with (patch.dict(os.environ, env),
                  patch.object(gateway, "BOT_TOKEN", "example-bot-token"),
                  patch.object(gateway, "telegram",
                               return_value={"file_path": "photos/photo.png",
                                             "file_size": len(png)}),
                  patch.object(gateway, "urlopen", return_value=io.BytesIO(png))):
                gateway.download_image()
            self.assertEqual(path.read_bytes(), png)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


    def test_private_voice_auto_dispatches_as_read_only_audit(self):
        voice_update = {
            "update_id": 777,
            "message": {
                "chat": {"type": "private", "id": 123456},
                "from": {"id": 123456, "is_bot": False},
                "voice": {
                    "file_id": "AwACAgQAAAAAAAABBBBB",
                    "mime_type": "audio/ogg", "duration": 13, "file_size": 12000
                },
            },
        }
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "transcribe_voice",
                           return_value="Codex, verifica o estado da VPS") as stt,
              patch.object(gateway, "create_audit", return_value=80) as create,
              patch.object(gateway, "say") as send):
            gateway.handle_update(voice_update)
            stt.assert_called_once_with({"file_id": "AwACAgQAAAAAAAABBBBB"})
            create.assert_called_once_with(777, "verifica o estado da VPS")
            self.assertTrue(any("Áudio recebido" in c.args[0]
                                for c in send.call_args_list))
            self.assertTrue(any("Ouvi:" in c.args[0]
                                for c in send.call_args_list))
            self.assertIn("Tarefa #80", send.call_args.args[0])

    def test_voice_without_codex_wake_word_is_audit_only(self):
        update = {
            "update_id": 778,
            "message": {
                "chat": {"type": "private", "id": 123456},
                "from": {"id": 123456, "is_bot": False},
                "voice": {"file_id": "AwACAgQAAAAAAAABBBBB", "duration": 12},
            },
        }
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "transcribe_voice",
                           return_value="Verifica se a VPS está a funcionar corretamente"),
              patch.object(gateway, "create_audit", return_value=81) as create,
              patch.object(gateway, "say")):
            gateway.handle_update(update)
            create.assert_called_once_with(
                778, "Verifica se a VPS está a funcionar corretamente")

    def test_unauthorized_voice_is_never_downloaded_or_transcribed(self):
        update = {
            "update_id": 779,
            "message": {
                "chat": {"type": "private", "id": 888888},
                "from": {"id": 888888, "is_bot": False},
                "voice": {"file_id": "AwACAgQAAAAAAAABBBBB", "duration": 13},
            },
        }
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "transcribe_voice") as stt,
              patch.object(gateway, "say") as send,
              patch.object(gateway, "create_audit") as create):
            gateway.handle_update(update)
            stt.assert_not_called()
            send.assert_not_called()
            create.assert_not_called()

    def test_voice_rejects_oversized_unsupported_and_long_audio(self):
        valid = {"voice": {"file_id": "AwACAgQAAAAAAAABBBBB",
                           "mime_type": "audio/ogg", "duration": 13}}
        self.assertEqual(gateway.select_voice(valid)["file_id"],
                         "AwACAgQAAAAAAAABBBBB")
        for attrs in ({"duration": 91}, {"file_size": 9 * 1024 * 1024},
                      {"mime_type": "audio/mp3"}, {"file_id": "../../bad"}):
            update = {"voice": {**valid["voice"], **attrs}}
            with self.assertRaises(RuntimeError):
                gateway.select_voice(update)

    def test_private_voice_transcript_blocks_secrets_and_edits(self):
        update = {
            "update_id": 780,
            "message": {
                "chat": {"type": "private", "id": 123456},
                "from": {"id": 123456, "is_bot": False},
                "voice": {"file_id": "AwACAgQAAAAAAAABBBBB", "duration": 11},
            },
        }
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "transcribe_voice",
                           return_value="Codex, vê a senha da minha conta"),
              patch.object(gateway, "create_audit") as create,
              patch.object(gateway, "say") as send):
            gateway.handle_update(update)
            create.assert_not_called()
            self.assertIn("não publiquei", send.call_args.args[0].lower())
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "transcribe_voice",
                           return_value="Codex, apaga os ficheiros antigos"),
              patch.object(gateway, "create_audit") as create,
              patch.object(gateway, "say") as send):
            gateway.handle_update(update)
            create.assert_not_called()
            self.assertIn("correções e mudanças", send.call_args.args[0].lower())

    def test_transcription_error_is_explicit_and_no_audit_runs(self):
        update = {
            "update_id": 781,
            "message": {
                "chat": {"type": "private", "id": 123456},
                "from": {"id": 123456, "is_bot": False},
                "voice": {"file_id": "AwACAgQAAAAAAAABBBBB", "duration": 13},
            },
        }
        with (patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "transcribe_voice",
                           side_effect=RuntimeError("Model unavailable")),
              patch.object(gateway, "create_audit") as create,
              patch.object(gateway, "say") as send):
            gateway.handle_update(update)
            create.assert_not_called()
            self.assertIn("Não consegui transcrever", send.call_args.args[0])

    def test_voice_subprocess_env_never_receives_github_or_bot_credentials(self):
        with patch.dict(os.environ, {
            "GH_TOKEN": "never-expose-github-token",
            "TELEGRAM_BOT_TOKEN": "never-expose-telegram-token",
            "VPS_SSH_PASSWORD": "never-expose-ssh-password",
            "GITHUB_TOKEN": "never-expose-token",
        }):
            env = gateway._voice_env(Path("/tmp/voice-test"))
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("TELEGRAM_BOT_TOKEN", env)
            self.assertNotIn("VPS_SSH_PASSWORD", env)
            self.assertEqual(env["HF_HOME"], "/tmp/voice-test/models")

    def test_private_audio_download_and_disposable_transcription(self):
        with tempfile.TemporaryDirectory() as directory:
            commands = []
            def fake_process(args, env, timeout, failure):
                commands.append((args, env))
                if any(x.endswith("telegram_voice_transcribe.py") for x in args):
                    self.assertEqual(
                        Path(args[-1]).read_bytes(), b"OggS" + b"private voice")
                    self.assertEqual(Path(args[-1]).stat().st_mode & 0o777, 0o600)
                    self.assertNotIn("GH_TOKEN", env)
                    return "Codex, faz uma auditoria à VPS"
                return ""
            with (patch.dict(os.environ, {"RUNNER_TEMP": directory}),
                  patch.object(gateway, "BOT_TOKEN", "masked"),
                  patch.object(gateway, "telegram", return_value={
                      "file_path": "voice/file_1.oga", "file_size": 18,
                  }),
                  patch.object(gateway, "urlopen",
                               return_value=io.BytesIO(b"OggS" + b"private voice")),
                  patch.object(gateway, "_voice_run", side_effect=fake_process)):
                self.assertEqual(
                    gateway.transcribe_voice({"file_id": "AwACAgQAAAAAAAABBBBB"}),
                    "Codex, faz uma auditoria à VPS",
                )
            self.assertEqual(len(commands), 3)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_invalid_ogg_is_rejected_before_running_a_model(self):
        with (patch.object(gateway, "BOT_TOKEN", "masked"),
              patch.object(gateway, "telegram", return_value={
                  "file_path": "voice/entry.oga", "file_size": 5,
              }),
              patch.object(gateway, "urlopen", return_value=io.BytesIO(b"plain")),
              patch.object(gateway, "_voice_run") as work):
            with self.assertRaisesRegex(RuntimeError, "not valid OGG"):
                gateway.transcribe_voice({"file_id": "AwACAgQAAAAAAAABBBBB"})
            work.assert_not_called()



if __name__ == "__main__":
    unittest.main()
