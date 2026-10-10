#!/usr/bin/env python3
"""GitHub Actions <-> Telegram Bot API, using the Python standard library.

No Telegram credential is ever checked into GitHub, copied to the VPS,
or included in a ChatGPT message. Only a configured private chat can
issue audit tasks. Nothing in this bridge executes user text as shell.
"""
import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

REPO = os.environ.get("GITHUB_REPOSITORY", "martaxi-boss/VPS")
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
GH_TOKEN = os.environ.get("GH_TOKEN", "").strip()

MAX_IMAGE_BYTES = 10 * 1024 * 1024
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
        "jpg": content.startswith(b"\\xff\\xd8\\xff"),
        "png": content.startswith(b"\\x89PNG\\r\\n\\x1a\\n"),
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


def say(message):
    if not CHAT_ID:
        return
    telegram("sendMessage", {
        "chat_id": CHAT_ID,
        "text": message[:4000],
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


def issue_status(text):
    match = re.fullmatch(r"/status(?:@\w+)?\s+#?(\d+)\s*", text, re.I)
    if not match:
        return None
    number = int(match.group(1))
    issue = github("GET", "issues/" + str(number))
    comments = github("GET", "issues/" + str(number) + "/comments?per_page=100")
    results = [str(c.get("body") or "") for c in comments
               if str(c.get("body") or "").startswith("**Codex VPS:")]
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

    text = str(message.get("text") or "").strip()
    if not text:
        return
    if re.match(r"^/(?:start|help)(?:@\w+)?$", text, re.I):
        say("🤖 Ponte Codex ligada ao GitHub.\n\n"
            "Envia /audit seguido do pedido, ou 'Codex, faz uma auditoria...'.\n"
            "Consulta o resultado com /status 123.\n\n"
            "Por segurança, só auditorias de leitura estão ativas. "
            "As correções e Cursor ainda não estão ativados.\n"
            "⚠️ Este repositório GitHub é público: nunca incluas passwords, "
            "tokens ou dados privados nas ordens.")
        return
    if text.lower().startswith(("/fix", "/cursor", "/sonnet", "/composer")):
        say("Este agente ainda não está ativado. "
            "Para já posso enviar auditorias de leitura ao Codex: /audit <pedido>.")
        return
    status = issue_status(text)
    if status is not None:
        say(status)
        return
    task = parse_audit(text)
    if task is None:
        say("Não reconheci essa ordem. Usa /audit <pedido>, "
            "'Codex, <pedido>', /status <número> ou /help.")
        return
    if len(task) < 8 or len(task) > 3800:
        say("A tarefa tem de ter entre 8 e 3800 caracteres.")
        return
    # Prevent accidental publishing of obvious access credentials in a public Issue.
    if re.search(r"(?i)(sk-[a-z0-9_-]{12,}|gh[opsru]_[a-z0-9_]{15,}|"
                 r"(?:(?:password|senha|token|api[_-]?key)\s*[:=]\s*\S{8,}))", task):
        say("Não vou publicar uma ordem que parece conter credenciais. "
            "Retira passwords/tokens e volta a enviar.")
        return
    number = create_audit(update["update_id"], task)
    say("📨 Auditoria enviada ao Codex.\n"
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
    # Telegram confirms updates only after the next getUpdates call with offset.
    # Confirm each successfully handled update to avoid silently losing commands.
    for _ in range(8):
        updates = telegram("getUpdates", {
            "limit": 25, "timeout": 0,
            "allowed_updates": json.dumps(["message"]),
        })
        if not updates:
            break
        for update in updates:
            try:
                handle_update(update)
            except RuntimeError as exc:
                # Leave the update unacknowledged so it can be retried.
                print("TELEGRAM_COMMAND=RETRY_REQUIRED " + str(exc))
                return
            telegram("getUpdates", {
                "offset": int(update["update_id"]) + 1,
                "limit": 1, "timeout": 0,
                "allowed_updates": json.dumps(["message"]),
            })
    print("TELEGRAM_POLL=COMPLETE")


def notify():
    if not BOT_TOKEN or not CHAT_ID:
        print("TELEGRAM_NOTIFY=NOT_CONFIGURED")
        return
    status = os.environ.get("CODEX_JOB_STATUS", "unknown")
    issue = os.environ.get("CODEX_ISSUE_NUMBER", "")
    run_url = os.environ.get("CODEX_RUN_URL", "")
    report_path = Path(os.environ.get("CODEX_REPORT_PATH", "/nonexistent"))
    report = (report_path.read_text(encoding="utf-8", errors="replace")
              if report_path.is_file() else "Sem relatório disponível; consultar o GitHub.")
    outcome = "✅ Concluído" if status == "success" else "⚠️ Falhou"
    top = "🤖 Codex — " + outcome + "\n"
    if issue:
        top += "Tarefa #" + issue + "\n"
    top += "Repositório: " + REPO + "\n"
    if issue:
        top += "https://github.com/" + REPO + "/issues/" + issue + "\n"
    elif run_url:
        top += run_url + "\n"
    if len(top) + len(report) < 3800:
        say(top + "\nRELATÓRIO:\n" + report)
    else:
        say(top + "\nRESUMO:\n" + report[:1700] +
            "\n\nO relatório completo segue como ficheiro.")
        name = "codex-relatorio-" + (issue or "execucao") + ".txt"
        telegram("sendDocument", {
            "chat_id": CHAT_ID,
            "caption": "Relatório completo do Codex",
        }, document=(name, report.encode("utf-8")))
    print("TELEGRAM_NOTIFY=SENT")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "poll":
            poll()
        elif len(sys.argv) == 2 and sys.argv[1] == "notify":
            notify()
        else:
            raise RuntimeError("Usage: telegram_gateway.py poll|notify")
    except RuntimeError as exc:
        print("TELEGRAM_BRIDGE_ERROR=" + str(exc), file=sys.stderr)
        sys.exit(1)
