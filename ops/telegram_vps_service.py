#!/usr/bin/env python3
"""Private Telegram long-poller on VPS. Audits only, never shell from chat text.

Run as the same unprivileged ubuntu account as the existing, sandboxed Codex
bridge. All Telegram updates, images and reports remain local and private.
"""
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import telegram_gateway as gate

DATA = Path(os.environ.get('TELEGRAM_DATA_DIR', '/home/ubuntu/.local/share/project-leader-telegram'))
JOBS = Path('/home/ubuntu/codex-bridge/jobs')
SOURCE = Path(__file__).resolve().parent
EDIT_WORDS = re.compile(r'\b(?:corrige|corrigir|altera|alterar|apaga|apagar|remove|remover|reinicia|reiniciar|instala|instalar|deploy)\b', re.I)
SECRET_WORDS = re.compile(r'(?i)\b(password|senha|token|api.key|pin|iban|chave privada|c[oó]digo de recupera[cç][aã]o)\b')
SECRET_VALUES = re.compile(r'(?i)(sk-[a-z0-9_-]{12,}|gh[opsru]_[a-z0-9_]{15,}|(?:(?:password|senha|token|api[_-]?key)\s*[:=]\s*\S{8,}))')


def private_message(update):
    message = update.get('message') or {}
    chat = message.get('chat') or {}
    sender = message.get('from') or {}
    return (chat.get('type') == 'private' and
            str(chat.get('id')) == gate.CHAT_ID and
            str(sender.get('id')) == gate.CHAT_ID and
            not sender.get('is_bot'))


def classify(text, voice=False, image=False, active_agent=None):
    """Classify using explicit addressee before persistent conversational context.

    Gemini/other agents are never routed through the Codex-only audit executor.
    Plain speech can use the selected Codex agent, but never guesses a switch.
    """
    text = text.strip()
    addressee, addressed_task = gate.parse_agent_address(text)
    if gate.is_presence_message(text):
        return 'presence', addressee or active_agent
    if re.fullmatch(r'/(?:start|help)(?:@\w+)?', text, re.I):
        return 'help', ''
    if re.fullmatch(r'/status(?:@\w+)?\s+#?(\d+)', text, re.I):
        return 'status', re.search(r'\d+$', text).group()
    if re.match(r'^/(?:fix|cursor|sonnet|composer)(?:\b|@)', text, re.I):
        return 'blocked', 'Os modos de correção e outros agentes não estão ativados.'
    if addressee and addressee != 'Codex':
        return 'blocked', gate.agent_unavailable_reply(addressee)
    if active_agent and active_agent != 'Codex' and not addressee:
        return 'blocked', gate.agent_unavailable_reply(active_agent)
    if voice and (SECRET_WORDS.search(text) or SECRET_VALUES.search(text)):
        return 'blocked', 'Por segurança, não processei um áudio que pode conter informação privada.'
    if EDIT_WORDS.search(text):
        return 'blocked', 'Por segurança, só auditorias de leitura estão ativadas.'
    task = gate.parse_audit(text)
    if task is None and addressee == 'Codex' and addressed_task:
        task = addressed_task
    if task is None and (voice or image or
                         (active_agent == 'Codex' and gate.is_voice_audit_request(text))):
        task = text or (gate.DEFAULT_IMAGE_TASK if image else '')
    if not task:
        return 'blocked', 'Não percebi uma ordem de auditoria. Envia um áudio como «Verifica o estado da VPS».'
    if len(task) < 8 or len(task) > 3800 or SECRET_VALUES.search(task):
        return 'blocked', 'Pedido rejeitado por tamanho ou possível informação sensível.'
    if (voice or addressee == 'Codex' or active_agent == 'Codex') and not image:
        if not gate.is_voice_audit_request(task):
            return 'blocked', 'Não percebi uma auditoria clara; não utilizei o Codex.'
    return 'audit', task

def safe_send(text):
    try:
        gate.say(text)
        return True
    except RuntimeError:
        print('TELEGRAM_SEND=RETRY_LATER', flush=True)
        return False


def atomic_write(path, payload):
    tmp = path.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as dest:
            json.dump(payload, dest, ensure_ascii=False)
            dest.flush()
            os.fsync(dest.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def send_report(uid, success, report):
    headline = ('✅ Auditoria concluída' if success else '⚠️ Auditoria falhou') + f' — pedido {uid}.'
    if len(report) < 3300:
        safe_send(headline + '\n\n' + report)
    else:
        safe_send(headline + '\nO relatório completo segue num ficheiro privado.')
        try:
            gate.telegram('sendDocument', {'chat_id': gate.CHAT_ID,
                                           'caption': f'Relatório privado da auditoria {uid}'},
                          document=(f'auditoria-{uid}.txt', report.encode('utf-8')[:1000000]))
        except RuntimeError:
            safe_send('Não consegui entregar o ficheiro; pede /status ' + str(uid) + '.')


def stage_image(image, job_dir):
    output = job_dir / ('codex-input.' + image['ext'])
    os.environ['CODEX_IMAGE_FILE_ID'] = image['file_id']
    os.environ['CODEX_IMAGE_EXT'] = image['ext']
    os.environ['CODEX_IMAGE_OUTPUT'] = str(output)
    try:
        gate.download_image()
    finally:
        for key in ('CODEX_IMAGE_FILE_ID', 'CODEX_IMAGE_EXT', 'CODEX_IMAGE_OUTPUT'):
            os.environ.pop(key, None)


def run_audit(uid, task, image):
    # Unique audit attempt. Never reuse an existing Codex workspace.
    JOBS.mkdir(parents=True, exist_ok=True, mode=0o700)
    for attempt in range(1, 100):
        job_key = f'{uid}-{attempt}'
        directory = JOBS / job_key
        try:
            directory.mkdir(mode=0o700)
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError('Too many attempts for Telegram update')
    try:
        (directory / 'codex-task.txt').write_text(task + '\n', encoding='utf-8')
        os.chmod(directory / 'codex-task.txt', 0o600)
        for name in ('codex-vps-remote.sh', 'codex-project-leader-bootstrap.py'):
            shutil.copyfile(SOURCE / name, directory / name)
            os.chmod(directory / name, 0o600)
        if image:
            stage_image(image, directory)
        # The local Codex process never receives Telegram credentials.
        env = dict(os.environ)
        for name in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID', 'GH_TOKEN', 'GITHUB_TOKEN',
                     'VPS_SSH_PASSWORD', 'CODEX_GITHUB_TOKEN'):
            env.pop(name, None)
        with (directory / 'daemon-execution.log').open('wb') as log:
            result = subprocess.run(['bash', str(directory / 'codex-vps-remote.sh'), job_key],
                                    cwd=str(directory), env=env, stdout=log, stderr=log,
                                    timeout=40 * 60, check=False)
        report_path = directory / 'report.md'
        report = report_path.read_text(encoding='utf-8', errors='replace') if report_path.is_file() else ''
        if not report:
            report = 'O executor terminou sem relatório. Consulta o serviço na VPS.'
        return result.returncode == 0, report
    finally:
        # Local screenshots and authentication-free output are never uploaded.
        shutil.rmtree(directory, ignore_errors=True)


class Listener:
    def __init__(self, data=DATA):
        self.data = Path(data)
        self.data.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.data, 0o700)
        for sub in ('pending', 'inflight', 'done'):
            (self.data / sub).mkdir(mode=0o700, exist_ok=True)
        self.lock = (self.data / 'process.lock').open('a+')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.offset = self.data / 'offset.json'
        self.session_file = self.data / 'active-agent.json'
        # An interrupted task is NOT retried automatically: avoid paid duplicate Codex calls.
        for path in (self.data / 'inflight').glob('*.json'):
            atomic_write(self.data / 'done' / path.name, {'state': 'interrupted'})
            path.unlink()

    def current_agent(self):
        try:
            info = json.loads(self.session_file.read_text(encoding='utf-8'))
            agent = info.get('agent')
            return agent if agent in ('Codex', 'Gemini', 'Project Leader', 'Cursor', 'Claude') else None
        except (OSError, ValueError, TypeError):
            return None

    def remember_agent(self, agent, update_id):
        """Persist an explicit selection, never let an older voice queue override it."""
        if agent not in ('Codex', 'Gemini', 'Project Leader', 'Cursor', 'Claude'):
            return
        try:
            info = json.loads(self.session_file.read_text(encoding='utf-8'))
            prior = int(info.get('update_id', -1))
        except (OSError, ValueError, TypeError):
            prior = -1
        if int(update_id) > prior:
            atomic_write(self.session_file, {'agent': agent, 'update_id': int(update_id)})

    def receive(self, update):
        uid = int(update['update_id'])
        if not private_message(update):
            return
        message = update['message']
        text = str(message.get('text') or message.get('caption') or '').strip()
        done = self.data / 'done' / f'{uid}.json'
        pending = self.data / 'pending' / f'{uid}.json'
        inflight = self.data / 'inflight' / f'{uid}.json'
        if any(p.exists() for p in (done, pending, inflight)):
            return
        if text and not message.get('voice') and not message.get('photo') and not message.get('document'):
            kind, detail = classify(text, active_agent=self.current_agent())
            if kind == 'presence':
                explicit_agent, _ = gate.parse_agent_address(text)
                if not safe_send(gate.agent_presence_reply(detail)):
                    raise RuntimeError('Reply delivery failed')
                if explicit_agent:
                    self.remember_agent(explicit_agent, uid)
                atomic_write(done, {'state': 'presence'})
                return
            if kind == 'help':
                safe_send('🎙️ Envia um áudio, por exemplo: «Verifica o estado da VPS».\n'
                          'Só estão disponíveis auditorias de leitura. /status <número> consulta um pedido local.')
                atomic_write(done, {'state': 'help'})
                return
            if kind == 'status':
                found = self.status(detail)
                safe_send(f'Pedido {detail}: {found}.')
                atomic_write(done, {'state': 'status'})
                return
            if kind == 'blocked':
                if not safe_send(detail):
                    raise RuntimeError('Reply delivery failed')
                atomic_write(done, {'state': 'rejected'})
                return
        if len(list((self.data / 'pending').glob('*.json'))) >= 10:
            safe_send('Há demasiados pedidos em espera. Tenta mais tarde.')
            atomic_write(done, {'state': 'queue_full'})
            return
        explicit_agent, _ = gate.parse_agent_address(text)
        if explicit_agent == 'Codex':
            self.remember_agent(explicit_agent, uid)
        # Snapshot the selected agent when the update is received. A later
        # greeting must not change the destination of already queued audio.
        update['_routing_agent'] = self.current_agent()
        atomic_write(pending, update)
        safe_send(f'📨 Recebi o pedido {uid}. ' +
                  ('Vou transcrever o áudio e analisar.' if message.get('voice') else
                   'Vou analisar em modo de leitura.') +
                  f' Podes consultar com /status {uid}.')

    def status(self, uid):
        if not re.fullmatch(r'\d{1,20}', str(uid)):
            return 'identificador inválido'
        for sub, label in (('pending', 'em espera'), ('inflight', 'em execução'), ('done', 'concluído')):
            path = self.data / sub / f'{uid}.json'
            if path.exists():
                if sub == 'done':
                    try:
                        return json.loads(path.read_text(encoding='utf-8')).get('state', label)
                    except (ValueError, OSError):
                        return label
                return label
        return 'não encontrado'

    def process_one(self, path):
        uid = path.stem
        inflight = self.data / 'inflight' / path.name
        try:
            path.rename(inflight)
        except FileNotFoundError:
            return
        ok = False
        state = 'falhou'
        try:
            update = json.loads(inflight.read_text(encoding='utf-8'))
            message = update['message']
            image = gate.select_image(message)
            voice = gate.select_voice(message)
            text = str(message.get('text') or message.get('caption') or '').strip()
            if voice:
                text = gate.transcribe_voice(voice)
                safe_send('🎙️ Transcrição recebida: ' + text[:1200])
            kind, detail = classify(text, voice=voice is not None,
                                    image=image is not None,
                                    active_agent=update.get('_routing_agent'))
            if kind == 'presence':
                explicit_agent, _ = gate.parse_agent_address(text)
                safe_send(gate.agent_presence_reply(detail))
                if explicit_agent:
                    self.remember_agent(explicit_agent, int(uid))
                state = 'presença confirmada'
            elif kind != 'audit':
                safe_send(detail if kind == 'blocked' else 'Não identifiquei uma auditoria clara.')
                state = 'rejeitado'
            else:
                explicit_agent, _ = gate.parse_agent_address(text)
                if explicit_agent == 'Codex':
                    self.remember_agent('Codex', int(uid))
                target = ('martaxi-boss/Project-leader' if re.search('project[ -]?leader', detail, re.I)
                          else 'martaxi-boss/VPS')
                task = f'TARGET_REPOSITORY={target}\n' + detail
                ok, report = run_audit(uid, task, image)
                send_report(uid, ok, report)
                state = 'concluído' if ok else 'falhou'
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            safe_send(f'⚠️ O pedido {uid} não foi concluído ({type(exc).__name__}). Não foi feita qualquer alteração à VPS.')
        finally:
            atomic_write(self.data / 'done' / f'{uid}.json', {'state': state})
            inflight.unlink(missing_ok=True)

    def work_forever(self):
        while True:
            for path in sorted((self.data / 'pending').glob('*.json'), key=lambda p: int(p.stem)):
                self.process_one(path)
            time.sleep(1)

    def poll_forever(self):
        # Public Telegram API confirmation before claiming the bridge is live.
        gate.telegram('getMe')
        print('TELEGRAM_VPS_SERVICE=ACTIVE', flush=True)
        while True:
            try:
                next_id = 0
                if self.offset.exists():
                    next_id = int(json.loads(self.offset.read_text())['next_id'])
                updates = gate.telegram('getUpdates', {
                    'offset': next_id, 'timeout': 20, 'limit': 25,
                    'allowed_updates': json.dumps(['message']),
                })
                for update in updates:
                    self.receive(update)
                    next_id = int(update['update_id']) + 1
                    atomic_write(self.offset, {'next_id': next_id})
            except (RuntimeError, ValueError, OSError) as exc:
                # Avoid logging Telegram request URLs (they contain the token).
                print('TELEGRAM_POLL_ERROR=' + type(exc).__name__, flush=True)
                time.sleep(5)


def main():
    if not gate.BOT_TOKEN or not re.fullmatch(r'[1-9]\d{3,17}', gate.CHAT_ID):
        raise SystemExit('TELEGRAM_VPS_SERVICE=NOT_CONFIGURED')
    bridge = Listener()
    worker = threading.Thread(target=bridge.work_forever, daemon=True)
    worker.start()
    bridge.poll_forever()


if __name__ == '__main__':
    main()
