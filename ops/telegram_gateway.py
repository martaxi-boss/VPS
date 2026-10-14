#!/usr/bin/env python3
"""GitHub Actions <-> Telegram Bot API, using the Python standard library.

No Telegram credential is ever checked into GitHub, copied to the VPS,
or included in a ChatGPT message. Only a configured private chat can request audits or read-only Supervisor
status. Nothing in this bridge executes user text as shell.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    from ops.telegram_coordinator_authority import (
        OrderRefused, resolve_target, sign_claim, is_execution_request)
except ModuleNotFoundError:
    from telegram_coordinator_authority import (
        OrderRefused, resolve_target, sign_claim, is_execution_request)

REPO = os.environ.get("GITHUB_REPOSITORY", "martaxi-boss/VPS")
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
GH_TOKEN = os.environ.get("GH_TOKEN", "").strip()

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_VOICE_BYTES = 8 * 1024 * 1024
MAX_VOICE_SECONDS = 90
DEFAULT_IMAGE_TASK = (
    "Analisa a captura de ecra anexa e identifica os erros ou problemas "
    "visiveis, com diagnostico e passos recomendados. Nao alteres ficheiros."
)


def select_image(message):
    """Select exactly one supported Telegram photo or image document."""
    images = message.get("photo") or []
    if images:
        entry = images[-1]  # Telegram photo sizes are ascending.
        ext = "jpg"
    elif message.get("document"):
        entry = message["document"]
        mime = entry.get("mime_type", "").lower()
        ext = {"image/jpeg": "jpg", "image/png": "png",
               "image/webp": "webp"}.get(mime)
        if ext is None:
            return None
    else:
        return None

    file_id = str(entry.get("file_id", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", file_id):
        raise RuntimeError("Unsupported Telegram file identifier")
    if int(entry.get("file_size", 0)) > MAX_IMAGE_BYTES:
        raise RuntimeError("Imagem demasiado grande (limite 10 MB)")
    return {"file_id": file_id, "ext": ext}



def select_voice(message):
    """Only private Telegram voice notes (OGG/Opus), bounded before downloading."""
    entry = message.get("voice")
    if not entry:
        return None
    mime = str(entry.get("mime_type") or "").lower()
    if mime not in ("", "audio/ogg", "audio/opus"):
        raise RuntimeError("Formato de voz Telegram não suportado")
    file_id = str(entry.get("file_id", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", file_id):
        raise RuntimeError("Invalid Telegram voice identifier")
    duration = int(entry.get("duration", 0))
    if duration <= 0 or duration > MAX_VOICE_SECONDS:
        raise RuntimeError("Áudio demasiado longo (limite 90 segundos)")
    if int(entry.get("file_size", 0)) > MAX_VOICE_BYTES:
        raise RuntimeError("Áudio demasiado grande (limite 8 MB)")
    return {"file_id": file_id}


def _voice_env(tmp):
    """Transcription worker and PyPI installer never inherit bot/GitHub secrets."""
    allow = (
        "PATH", "LANG", "LC_ALL", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "no_proxy", "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
    )
    env = {key: os.environ[key] for key in allow if os.environ.get(key)}
    env.update({
        "HOME": str(tmp), "HF_HOME": str(tmp / "models"),
        "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1",
    })
    return env


def _voice_run(command, env, timeout, failure):
    """Never forward dependency/model stdout or stderr into public Actions logs."""
    try:
        result = subprocess.run(
            command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError(failure) from None
    if result.returncode:
        raise RuntimeError(failure)
    return result.stdout.decode("utf-8", errors="replace").strip()


def transcribe_voice(voice):
    """Fetch voice privately and transcribe in an isolated, disposable CPU worker."""
    meta = telegram("getFile", {"file_id": voice["file_id"]})
    if int(meta.get("file_size", 0)) > MAX_VOICE_BYTES:
        raise RuntimeError("Telegram voice exceeds size limit")
    file_path = str(meta.get("file_path", ""))
    if (not re.fullmatch(r"[A-Za-z0-9_./-]{1,512}", file_path) or
            ".." in file_path.split("/")):
        raise RuntimeError("Invalid Telegram voice file path")
    url = "https://api.telegram.org/file/bot" + BOT_TOKEN + "/" + file_path
    try:
        with urlopen(Request(url, method="GET"), timeout=45) as response:
            content = response.read(MAX_VOICE_BYTES + 1)
    except HTTPError as exc:
        raise RuntimeError("Telegram voice HTTP " + str(exc.code)) from None
    except (URLError, TimeoutError):
        raise RuntimeError("Telegram voice download failed") from None
    if not content.startswith(b"OggS") or len(content) > MAX_VOICE_BYTES:
        raise RuntimeError("Telegram voice is not valid OGG audio")
    base_dir = os.environ.get("RUNNER_TEMP")
    if base_dir and not Path(base_dir).is_dir():
        raise RuntimeError("Invalid temporary runner directory")
    with tempfile.TemporaryDirectory(
            prefix="telegram-voice-", dir=base_dir or None) as name:
        tmp = Path(name)
        audio = tmp / "voice.ogg"
        fd = os.open(str(audio), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(content)
        env = _voice_env(tmp)
        venv = tmp / "venv"
        python = str(venv / "bin" / "python")
        _voice_run([sys.executable, "-m", "venv", str(venv)], env, 45,
                   "Não foi possível iniciar o reconhecimento de voz")
        _voice_run(
            [python, "-m", "pip", "install", "--only-binary=:all:", "--quiet",
             "faster-whisper==1.2.1", "av>=11,<19"],
            env, 240, "Motor local de voz indisponível",
        )
        transcript = _voice_run(
            [python, str(Path(__file__).with_name("telegram_voice_transcribe.py")),
             str(audio)],
            env, 240, "Não foi possível transcrever o áudio",
        )
    if len(transcript) < 8 or len(transcript) > 3800:
        raise RuntimeError("A transcrição ficou vazia ou demasiado longa")
    print("TELEGRAM_VOICE=TRANSCRIBED")
    return transcript


def download_image():
    """Retrieve a private Telegram image directly onto an ephemeral Actions runner."""
    if not BOT_TOKEN:
        raise RuntimeError("Telegram bot is not configured")
    file_id = os.environ.get("CODEX_IMAGE_FILE_ID", "")
    ext = os.environ.get("CODEX_IMAGE_EXT", "")
    output = Path(os.environ.get("CODEX_IMAGE_OUTPUT", ""))
    if (not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", file_id) or
            ext not in ("jpg", "png", "webp") or
            not output.is_absolute() or output.suffix != "." + ext):
        raise RuntimeError("Invalid Telegram image input")
    meta = telegram("getFile", {"file_id": file_id})
    size = int(meta.get("file_size", 0))
    if size > MAX_IMAGE_BYTES:
        raise RuntimeError("Telegram image exceeds private transport limit")
    file_path = str(meta.get("file_path", ""))
    if (not re.fullmatch(r"[A-Za-z0-9_./-]{1,512}", file_path) or
            ".." in file_path.split("/")):
        raise RuntimeError("Invalid Telegram file path")

    # No file bytes go through a public GitHub Issue, commit or artifact.
    url = "https://api.telegram.org/file/bot" + BOT_TOKEN + "/" + file_path
    try:
        with urlopen(Request(url, method="GET"), timeout=45) as response:
            content = response.read(MAX_IMAGE_BYTES + 1)
    except HTTPError as exc:
        raise RuntimeError("Telegram image HTTP " + str(exc.code)) from None
    except (URLError, TimeoutError):
        raise RuntimeError("Telegram image network error") from None
    if not content or len(content) > MAX_IMAGE_BYTES:
        raise RuntimeError("Telegram image size is invalid")
    magic_ok = {
        "jpg": content.startswith(b"\xff\xd8\xff"),
        "png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        "webp": content.startswith(b"RIFF") and content[8:12] == b"WEBP",
    }
    if not magic_ok[ext]:
        raise RuntimeError("Telegram image bytes do not match the declared format")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(content)
    print("TELEGRAM_IMAGE_READY=yes; bytes=" + str(len(content)))


def telegram(method, data=None, *, document=None):
    if not BOT_TOKEN:
        raise RuntimeError("Telegram bot is not configured")
    url = "https://api.telegram.org/bot" + BOT_TOKEN + "/" + method
    data = dict(data or {})
    headers = {}
    if document is None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        payload = urlencode(data).encode("utf-8")
    else:
        filename, file_bytes = document
        boundary = "----CodexBridge" + uuid.uuid4().hex
        parts = []
        for key, value in data.items():
            parts.extend([
                ("--" + boundary + "\r\n").encode(),
                ('Content-Disposition: form-data; name="' + key + '"\r\n\r\n').encode(),
                str(value).encode("utf-8"), b"\r\n",
            ])
        parts.extend([
            ("--" + boundary + "\r\n").encode(),
            ('Content-Disposition: form-data; name="document"; filename="' +
             filename + '"\r\n').encode(),
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n",
            file_bytes, b"\r\n",
            ("--" + boundary + "--\r\n").encode(),
        ])
        payload = b"".join(parts)
        headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    try:
        req = Request(url, data=payload, headers=headers, method="POST")
        with urlopen(req, timeout=25) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not result.get("ok"):
            raise RuntimeError("Telegram API rejected request")
        return result["result"]
    except HTTPError as exc:
        # Never print the URL: it contains the Telegram bot token.
        raise RuntimeError("Telegram API HTTP " + str(exc.code)) from None
    except (URLError, TimeoutError):
        raise RuntimeError("Telegram API connection failed") from None


def github(method, path, data=None):
    if not GH_TOKEN:
        raise RuntimeError("GitHub Actions token is missing")
    url = "https://api.github.com/repos/" + REPO + "/" + path.lstrip("/")
    headers = {
        "Authorization": "Bearer " + GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Codex-Telegram-Bridge",
    }
    if data is None:
        payload = None
    else:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        with urlopen(Request(url, data=payload, headers=headers, method=method),
                     timeout=25) as response:
            raw = response.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
    except HTTPError as exc:
        raise RuntimeError("GitHub API HTTP " + str(exc.code) +
                           " at " + path.split("?")[0]) from None
    except (URLError, TimeoutError):
        raise RuntimeError("GitHub API connection failed") from None


def _supervisor_audit():
    """Shared factual auditor; supports both module and script entrypoints."""
    try:
        from ops import supervisor_audit
    except ModuleNotFoundError:
        import supervisor_audit
    return supervisor_audit


def say(message):
    """Every Owner-directed text message crosses the Supervisor egress audit."""
    if not CHAT_ID or not re.fullmatch(r"[1-9][0-9]{3,17}", CHAT_ID):
        raise RuntimeError("Private Supervisor destination is unavailable")
    verified = _supervisor_audit().check_delivery(message)
    telegram("sendMessage", {
        "chat_id": CHAT_ID,
        "text": verified,
        "disable_web_page_preview": True,
    })


def existing_issue(update_id):
    title = "[codex audit] Telegram " + str(update_id)
    issues = github("GET", "issues?state=all&per_page=100&sort=created&direction=desc")
    for issue in issues:
        user = (issue.get("user") or {}).get("login", "")
        if (issue.get("title") == title and user in ("github-actions[bot]", "github-actions")):
            return issue["number"]
    return None


def has_dispatch_marker(number, update_id):
    comments = github("GET", "issues/" + str(number) + "/comments?per_page=100")
    marker = "telegram-dispatched:" + str(update_id)
    return any(marker in (c.get("body") or "") for c in comments)


def create_audit(update_id, task, image=None):
    title = "[codex audit] Telegram " + str(update_id)
    number = existing_issue(update_id)
    if number is None:
        image_marker = ""
        if image is not None:
            image_hash = hashlib.sha256(image["file_id"].encode("ascii")).hexdigest()
            image_marker = ("<!-- telegram-image-sha256:" + image_hash +
                            ":" + image["ext"] + " -->\n\n")
        body = (
            "Origem: Telegram privado autorizado.\n\n"
            "Aviso: este repositório e as Issues são públicos. "
            "Não enviar segredos, dados privados ou credenciais.\n\n"
            "<!-- telegram-update:" + str(update_id) + " -->\n\n" +
            image_marker +
            "## Pedido ao Codex (auditoria, sem alterações)\n\n" + task
        )
        issue = github("POST", "issues", {"title": title, "body": body})
        number = issue["number"]
    if not has_dispatch_marker(number, update_id):
        # Workflow dispatch is permitted for GITHUB_TOKEN triggered events.
        # The recipient workflow checks source=telegram and actor=github-actions[bot].
        inputs = {
            "task": task,
            "mode": "audit",
            "source": "telegram",
            "issue_number": str(number),
        }
        if image is not None:
            inputs["image_file_id"] = image["file_id"]
            inputs["image_ext"] = image["ext"]
        github("POST", "actions/workflows/codex-chatgpt-bridge.yml/dispatches", {
            "ref": "main",
            "inputs": inputs,
        })
        github("POST", "issues/" + str(number) + "/comments", {
            "body": "Tarefa encaminhada para o Codex. <!-- telegram-dispatched:" +
                    str(update_id) + " -->"
        })
    return number


def parse_audit(text):
    text = text.strip()
    match = re.match(r"^/(?:audit|codex)(?:@\w+)?(?:\s+|$)(.*)$", text, re.I | re.S)
    if match:
        return match.group(1).strip()
    match = re.match(r"^codex[,:;\-\s]+(.*)$", text, re.I | re.S)
    if match:
        return match.group(1).strip()
    return None


def is_presence_message(text):
    """Greetings and presence checks must never start paid Codex work."""
    plain = "".join(
        ch for ch in unicodedata.normalize("NFKD", text.lower())
        if not unicodedata.combining(ch)
    )
    plain = " ".join(re.sub(r"[?!.,:;]+", " ", plain).split())
    return bool(re.fullmatch(
        r"(?:(?:codex|project leader)\s+)?"
        r"(?:estas ai|estas por ai|ta ai|tas ai|ola|oi|alo|"
        r"bom dia|boa tarde|boa noite)"
        r"(?:\s+(?:codex|project leader))?",
        plain,
    )) or plain in ("codex", "project leader")


def owner_public_repositories():
    """Fetch a bounded public Owner project list; no Publisher credentials here."""
    names = []
    for page in range(1, 5):
        url = ("https://api.github.com/users/martaxi-boss/repos?"
               "type=owner&sort=updated&per_page=100&page=" + str(page))
        try:
            request = Request(url, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "Project-Leader-Telegram-Project-Discovery"})
            with urlopen(request, timeout=18) as response:
                raw = response.read(500_001)
            if len(raw) > 500_000:
                raise RuntimeError("GitHub project registry response too large")
            data = json.loads(raw.decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            raise RuntimeError("GitHub project discovery unavailable") from None
        if not isinstance(data, list) or len(data) > 100:
            raise RuntimeError("GitHub project list unverified")
        for row in data:
            if (isinstance(row, dict) and
                    row.get("owner", {}).get("login") == "martaxi-boss" and
                    row.get("private") is False and
                    row.get("archived") is False and
                    row.get("default_branch") == "main"):
                names.append(row.get("full_name", ""))
        if len(data) < 100:
            return names
    raise RuntimeError("Owner project list not fully enumerated")


def dispatch_coordinator(update_id, task):
    """Send only signed command data to a separate trusted Owner Issue gateway."""
    if not BOT_TOKEN or not GH_TOKEN:
        raise RuntimeError("Telegram Coordinator configuration unavailable")
    try:
        target = resolve_target(task, owner_public_repositories())
        signed, mac = sign_claim(BOT_TOKEN, int(update_id), target, task)
    except (OrderRefused, ValueError) as exc:
        raise RuntimeError("Coordenador recusou uma ordem sem projeto inequívoco ou segura") from None
    github("POST", "actions/workflows/telegram-coordinator-owner.yml/dispatches", {
        "ref": "main",
        "inputs": {
            "source": "telegram",
            "signed_order_b64": signed,
            "signature": mac,
        },
    })
    return target


def is_voice_audit_request(task):
    """Recognizable read-only intent required; reject noisy ASR strings."""
    return bool(re.search(
        r"\b(?:audit(?:a|ar|oria)|auditoria|verific(?:a|ar|acao|ação)|"
        r"analis(?:a|ar|e)|inspecion(?:a|ar|e)|diagnostic(?:a|ar|o)|"
        r"investig(?:a|ar|ue)|examin(?:a|ar|e)|consult(?:a|ar|e)|"
        r"relat[oó]rio|erros?|problemas?|estado|confirma|confirmar|"
        r"testa|testar|rev[êe]|rever|v[êe]|olha|procura|procurar)\b",
        task, re.I,
    ))


def issue_status(text):
    match = re.fullmatch(r"/status(?:@\w+)?\s+#?(\d+)\s*", text, re.I)
    if not match:
        return None
    number = int(match.group(1))
    issue = github("GET", "issues/" + str(number))
    comments = github("GET", "issues/" + str(number) + "/comments?per_page=100")
    results = [str(c.get("body") or "") for c in comments
               if (c.get("user") or {}).get("login") in
                  ("github-actions[bot]", "github-actions")
               and str(c.get("body") or "").startswith("**Codex VPS:")]
    if results:
        return ("Tarefa #" + str(number) + "\n\n" +
                results[-1][:3300] + "\n\n" + issue["html_url"])
    return ("Tarefa #" + str(number) + ": sem relatório final por enquanto.\n" +
            issue["html_url"])


def handle_update(update):
    message = update.get("message") or {}
    chat = message.get("chat") or {}
    sender = message.get("from") or {}
    # Private chat ID and sender ID must match our explicit allowlist.
    if (chat.get("type") != "private" or
        str(chat.get("id")) != CHAT_ID or
        str(sender.get("id")) != CHAT_ID or
        sender.get("is_bot")):
        return

    image = select_image(message)
    try:
        voice = select_voice(message)
    except (RuntimeError, ValueError, TypeError):
        say("🎙️ Aceito áudios Telegram em OGG com até 90 segundos e 8 MB.")
        return
    text = str(message.get("text") or message.get("caption") or "").strip()
    if voice is not None:
        say("🎙️ Áudio recebido. Estou a transcrever localmente; pode demorar alguns minutos.")
        try:
            text = transcribe_voice(voice)
        except RuntimeError:
            say("⚠️ Não consegui transcrever este áudio. Tenta reenviá-lo mais tarde.")
            return
    if not text and image is None:
        if message.get("document"):
            say("Aceito fotografias e imagens PNG, JPG ou WEBP até 10 MB. "
                "Envia a imagem como foto ou ficheiro de imagem.")
        return
    if is_presence_message(text):
        say("🤖 Estou aqui! Envia um áudio com uma ordem de auditoria, "
            "por exemplo: 'Verifica o estado da VPS'. "
            "Não precisas de escrever nem dizer Codex.")
        return
    if re.match(r"^/(?:start|help)(?:@\w+)?$", text, re.I):
        say("🤖 Ponte Codex ligada ao GitHub.\n\n"
            "Para auditorias de leitura: /audit <pedido>.\n"
            "Para correções, descreve por texto ou voz o que pretendes "
            "corrigir e identifica o projeto (por exemplo, PINK IPTV).\n"
            "Recebo mensagens de voz até 90 segundos.\n"
            "Consulta resultados de auditoria com /status 123.\n"
            "Pergunta ao Supervisor com /supervisor.\n\n"
            "A execução de correções exige verificação independente "
            "e permissões do proprietário no GitHub.\n"
            "Não envies credenciais nem dados privados em ordens.")
        return
    # Supervisor is a separate read-only path: never create public Issues,
    # dispatch Codex, or reinterpret Project Leader Human Gates.
    try:
        from ops import supervisor_live as supervisor
    except ModuleNotFoundError:
        import supervisor_live as supervisor
    supervision = supervisor.parse_request(text)
    if supervision is not None:
        try:
            answer = (supervisor.overview(github) if supervision == 0
                      else supervisor.task_status(github, supervision))
        except RuntimeError:
            say("👁️ Supervisor: não consegui consultar agora o estado fiável "
                "do GitHub. Não iniciei trabalhadores. Tenta consultar novamente.")
            return
        say(_supervisor_audit().observation(answer, source="owner_query"))
        return
    if supervisor.is_addressed_to_supervisor(text):
        say("👁️ Supervisor: só consulto e comunico estados da produção. "
            "Não executo ordens, não autorizo nem encaminho trabalhadores.")
        return

    # Natural text and offline-transcribed voice share the same authenticated
    # Owner Coordinator path. A screenshot is private; do not silently publish
    # or omit its evidence from a write order.
    if (is_execution_request(text) and
            not re.match(r"^/(?:audit|codex)(?:@\w+)?(?:\s|$)", text, re.I)):
        if image is not None:
            say("As imagens não são enviadas para tarefas de correção pela ponte "
                "Telegram. Descreve o problema por texto ou voz.")
            return
        try:
            target = dispatch_coordinator(update["update_id"], text)
        except RuntimeError:
            say("Não consegui encaminhar a ordem com segurança. "
                "Confirma o nome de um único projeto teu e tenta novamente.")
            return
        say("📨 Ordem recebida para " + target + ". "
            "A autorização e execução pelo Coordenador ainda serão verificadas "
            "no GitHub; esta mensagem não confirma que os trabalhadores arrancaram.")
        return

    if text.lower().startswith(("/fix", "/cursor", "/sonnet", "/composer")):
        say("Este agente ainda não está ativado. "
            "Para já posso enviar auditorias de leitura ao Codex: /audit <pedido>.")
        return
    status = issue_status(text)
    if status is not None:
        say(_supervisor_audit().observation(status, source="owner_query"))
        return
    task = parse_audit(text)
    if image is not None:
        # A plain-language photo caption is a task; no caption is also valid.
        if task is None:
            task = text or DEFAULT_IMAGE_TASK
        elif not task:
            task = DEFAULT_IMAGE_TASK
    elif voice is not None and task is None:
        # Voice commands do not require speaking a wake word; still audit-only.
        task = text
    elif task is None:
        say("Não reconheci essa ordem. Usa /audit <pedido>, "
            "'Codex, <pedido>', /status <número> ou /help.")
        return
    if voice is not None and re.search(
            r"\b(corrige|corrigir|altera|alterar|apaga|apagar|remove|remover|"
            r"reinicia|reiniciar|instala|instalar|deploy)\b", text, re.I):
        say("Por segurança, correções e mudanças na VPS ainda não estão ativas por voz. "
            "Pede apenas uma auditoria ou uma análise.")
        return
    if len(task) < 8 or len(task) > 3800:
        say("A tarefa tem de ter entre 8 e 3800 caracteres.")
        return
    # A voice transcript is also a public GitHub Issue: be extra conservative.
    if voice is not None and re.search(
            r"(?i)\b(password|senha|token|api.key|pin|iban|chave privada|"
            r"código de recuperação)\b", text):
        say("⚠️ Não publiquei esta ordem: pode conter dados privados. "
            "O repositório GitHub é público.")
        return
    # Prevent accidental publishing of obvious access credentials in a public Issue.
    if re.search(r"(?i)(sk-[a-z0-9_-]{12,}|gh[opsru]_[a-z0-9_]{15,}|"
                 r"(?:(?:password|senha|token|api[_-]?key)\s*[:=]\s*\S{8,}))", task):
        say("Não vou publicar uma ordem que parece conter credenciais. "
            "Retira passwords/tokens e volta a enviar.")
        return
    if voice is not None and not is_voice_audit_request(task):
        say("🎙️ Ouvi o áudio, mas não percebi uma ordem de auditoria clara. "
            "Tenta dizer, por exemplo: 'Verifica se a VPS tem erros'. "
            "Não foi enviada nenhuma tarefa ao Codex.")
        return
    number = (create_audit(update["update_id"], task, image=image) if image
              else create_audit(update["update_id"], task))
    if voice is not None:
        say("🎙️ Ouvi: " + text[:1700])
    say(("📸 Imagem enviada ao Codex.\n" if image
         else "📨 Auditoria enviada ao Codex.\n") +
        "Tarefa #" + str(number) + "\n"
        "O relatório completo vai chegar aqui quando terminar.\n"
        "https://github.com/" + REPO + "/issues/" + str(number))


def poll():
    if not BOT_TOKEN or not CHAT_ID or not GH_TOKEN:
        print("TELEGRAM_BRIDGE=NOT_CONFIGURED")
        return
    if not re.fullmatch(r"[1-9]\d{3,17}", CHAT_ID):
        raise RuntimeError("TELEGRAM_CHAT_ID must be a positive private chat ID")
    print("TELEGRAM_BRIDGE=ACTIVE")
    # Never discard the next incoming photo while acknowledging the previous one.
    offset = None
    for _ in range(8):
        args = {"limit": 25, "timeout": 0,
                "allowed_updates": json.dumps(["message"])}
        if offset is not None:
            args["offset"] = offset
        updates = telegram("getUpdates", args)
        if not updates:
            break
        for update in updates:
            try:
                handle_update(update)
            except RuntimeError as exc:
                # Retry this same update during the next polling run.
                print("TELEGRAM_COMMAND=RETRY_REQUIRED " + str(exc))
                return
            offset = int(update["update_id"]) + 1
    # Acknowledge successfully handled messages. Any fresh message returned
    # by this final call stays pending; it is processed next time.
    if offset is not None:
        telegram("getUpdates", {"offset": offset, "limit": 1, "timeout": 0,
                                "allowed_updates": json.dumps(["message"])})
    print("TELEGRAM_POLL=COMPLETE")


def private_report_status(status):
    """Distinguish staged PRs and unverified results from completed work."""
    if status in ("success", "MERGED", "NO_CHANGE"):
        return "✅ Execução concluída (verificar o resultado)"
    if status == "PR_STAGED":
        return "📝 PR pronta para revisão; alterações NÃO integradas"
    if status == "WORKER_REPORT_RECEIVED":
        return "📩 Relatório do trabalhador recebido; validação final pendente"
    if status == "PAUSED_QUOTA":
        return "⏸️ QUOTA REAL DO CHATGPT/CODEX ATINGIDA — aguarda decisão do Owner"
    if status == "QUOTA_UNVERIFIED":
        return "⏸️ Cota real não verificável — trabalho protegido, sem Codex"
    if status in ("NOT_STARTED", "NOT_COMPLETED", "FAILED"):
        return "⚠️ Execução interrompida ou não certificada"
    if status in ("NO_CHANGE_UNVERIFIED", "PR_NEEDS_ATTENTION"):
        return "⚠️ Revisão necessária; objetivo NÃO certificado"
    return "⚠️ Não concluído ou não verificado"


def notify():
    """Supervisor audits factual origin/outcomes, then privately forwards them.

    The report content is never used as a command, Human Gate classifier or
    public GitHub Issue; only the Project Leader worker owns those decisions.
    """
    if not BOT_TOKEN or not CHAT_ID:
        print("TELEGRAM_NOTIFY=NOT_CONFIGURED")
        return
    audit = _supervisor_audit()
    status = os.environ.get("CODEX_JOB_STATUS", "unknown")
    issue = os.environ.get("CODEX_ISSUE_NUMBER", "")
    run_url = os.environ.get("CODEX_RUN_URL", "")
    worker = os.environ.get("CODEX_INSTANCE_ID", "")
    if not re.fullmatch(r"(?:[12]|p[2-8]-[12])?", worker):
        raise RuntimeError("Invalid trusted Codex worker identity")
    label = (f" fase {worker[1]} trabalhador {worker[-1]}"
             if worker.startswith("p") else (f" {worker}" if worker else ""))
    outcome = private_report_status(status)
    # The Supervisor must not repeat a success badge when trusted CI disagrees.
    if (os.environ.get("CODEX_REPORT_MODE", "worker") == "status"
            and status in ("MERGED", "NO_CHANGE")
            and any(os.environ.get(key) in ("failure", "cancelled") for key in
                    ("PREFLIGHT_OUTCOME", "STAGE_OUTCOME", "CODEX_OUTCOME",
                     "COLLECT_OUTCOME", "ARTIFACTS_OUTCOME", "PUBLISH_OUTCOME"))):
        outcome = "⚠️ INCONSISTÊNCIA: conclusão NÃO CERTIFICADA"
    top = "🤖 Codex" + label + " — " + outcome + "\n"
    if issue:
        top += "Tarefa #" + issue + "\n"
    top += "Repositório: " + REPO + "\n"
    if issue:
        top += "https://github.com/" + REPO + "/issues/" + issue + "\n"
    if run_url:
        top += run_url + "\n"

    mode = os.environ.get("CODEX_REPORT_MODE", "worker")
    if mode == "status":
        stages = (("PREFLIGHT_OUTCOME", "Pré-validação"),
                  ("STAGE_OUTCOME", "VPS"),
                  ("CODEX_OUTCOME", "Codex"),
                  ("COLLECT_OUTCOME", "Recolha"),
                  ("ARTIFACTS_OUTCOME", "Artefactos"),
                  ("PUBLISH_OUTCOME", "Publicação/CI"))
        allowed = {"success", "failure", "skipped", "cancelled"}
        facts = {key: os.environ[key] for key, _ in stages
                 if os.environ.get(key) in allowed}
        details = [name + ": " + facts[key]
                   for key, name in stages if key in facts]
        if status == "PAUSED_QUOTA":
            proof = os.environ.get("QUOTA_HOLD_OUTCOME", "unknown")
            if proof == "success":
                details.append("Checkpoint da tarefa: registado para decisão do Owner. "
                               "Se houver trabalho parcial, o espaço privado da VPS é preservado.")
            else:
                details.append("ATENÇÃO: checkpoint GitHub ainda NÃO certificado. "
                               "Não reiniciar; verificar primeiro o espaço privado na VPS.")
            details.append("Retoma: apenas após nova ordem autenticada do Owner.")
        suffix = ("\n" + "\n".join(details)) if details else ""
        audit_report = audit.pipeline(issue=issue, run_url=run_url,
                                      worker=worker, status=status, steps=facts)
        # Never include the private worker report in this second notification.
        say(audit_report + top + "\nEstado final do pipeline." + suffix +
            "\nConsulta a tarefa no GitHub.")
        print("TELEGRAM_NOTIFY=SENT")
        return
    if mode != "worker":
        raise RuntimeError("Invalid passive Supervisor message mode")

    report_path = Path(os.environ.get("CODEX_REPORT_PATH", "/nonexistent"))
    if not report_path.is_file() or report_path.is_symlink():
        raise RuntimeError("Supervisor refused an absent or symlink worker report")
    raw_report = report_path.read_bytes()
    if not 1 <= len(raw_report) <= 65536:
        raise RuntimeError("Supervisor refused an invalid-size report")
    report = raw_report.decode("utf-8", errors="replace")
    audit_report = audit.worker_report(
        issue=issue, run_url=run_url, worker=worker, status=status, report=raw_report)
    prefix = audit_report + top
    if len(prefix) + len(report) + 20 <= 4000:
        say(prefix + "\nRELATÓRIO ORIGINAL:\n" + report)
    else:
        say(prefix + "\nEXCERTO DO RELATÓRIO:\n" + report[:1300] +
            "\n\nO relatório completo segue como ficheiro privado, "
            "sem cortes nem alterações.")
        name = "codex-relatorio-" + (issue or "execucao") + (
            "-worker-" + worker if worker else ""
        ) + ".txt"
        # Audited above, and the original *bytes* are attached unchanged.
        telegram("sendDocument", {
            "chat_id": CHAT_ID,
            "caption": "Relatório original integral, conferido pelo Supervisor",
        }, document=(name, raw_report))
    print("TELEGRAM_NOTIFY=SENT")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "poll":
            poll()
        elif len(sys.argv) == 2 and sys.argv[1] == "notify":
            notify()
        elif len(sys.argv) == 2 and sys.argv[1] == "download":
            download_image()
        else:
            raise RuntimeError("Usage: telegram_gateway.py poll|notify|download")
    except RuntimeError as exc:
        print("TELEGRAM_BRIDGE_ERROR=" + str(exc), file=sys.stderr)
        sys.exit(1)
