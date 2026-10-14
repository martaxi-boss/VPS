#!/usr/bin/env python3
"""Loopback-only, API-key protected MCP ingress for Owner-selected ChatGPT files.

Intended for a privately configured Secure MCP Tunnel, NOT an internet listener.
Does not execute a Coordinator, submit Issues, choose models, or create workers.
Never persist or log pre-signed download URLs. Transfers run asynchronously so a
large original does not exceed the caller's MCP request deadline.
"""
from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any

try:
    from ops import chatgpt_attachment_ingress as ingress
except ModuleNotFoundError:
    import chatgpt_attachment_ingress as ingress

OWNER = "martaxi-boss"
JOB_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
MAX_JSON_REQUEST = 256 * 1024
MAX_STAGED_JOBS = 2  # In addition to the one actively streaming, keep VPS disk bounded.
PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOLS = {"2025-03-26", "2025-06-18", "2025-11-25"}


class MCPRefused(ValueError):
    """Return static error codes only, never URLs, tokens, or raw exceptions."""


def _secret_from_file(path: Path) -> bytes:
    path = Path(path)
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or path.is_symlink() or info.st_size > 1024):
            raise MCPRefused("OWNER_KEY_NOT_PROVISIONED")
        key = path.read_bytes().strip()
    except OSError:
        raise MCPRefused("OWNER_KEY_NOT_PROVISIONED") from None
    if not 32 <= len(key) <= 256 or any(c < 33 or c > 126 for c in key):
        raise MCPRefused("OWNER_KEY_NOT_PROVISIONED")
    return key


def _private_jobs(inbox: Path) -> Path:
    base = ingress._private_dir(inbox)
    jobs = base / ".mcp-jobs"
    if not jobs.exists() and not jobs.is_symlink():
        jobs.mkdir(mode=0o700)
    return ingress._private_dir(jobs)


def _record(jobs: Path, job: str, value: dict[str, Any]) -> None:
    if JOB_ID.fullmatch(job) is None:
        raise MCPRefused("INVALID_JOB_ID")
    final = jobs / (job + ".json")
    temporary = jobs / ("." + job + ".tmp")
    blob = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")
    if len(blob) > 4096 or temporary.exists() or temporary.is_symlink():
        raise MCPRefused("INVALID_JOB_RECORD")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(blob)
        os.replace(temporary, final)
    finally:
        temporary.unlink(missing_ok=True)


def _read_record(jobs: Path, job: str) -> dict:
    if type(job) is not str or JOB_ID.fullmatch(job) is None:
        raise MCPRefused("INVALID_JOB_ID")
    path = jobs / (job + ".json")
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096
                or info.st_nlink != 1 or path.is_symlink()):
            raise MCPRefused("JOB_NOT_AVAILABLE")
        return json.loads(path.read_text(encoding="ascii"))
    except (OSError, ValueError, UnicodeError):
        raise MCPRefused("JOB_NOT_AVAILABLE") from None


class MediaTool:
    def __init__(self, *, inbox: Path, key_file: Path, descriptor: Path):
        self.inbox = ingress._private_dir(inbox)
        self.jobs = _private_jobs(self.inbox)
        self.secret = _secret_from_file(key_file)
        self.descriptor = json.loads(Path(descriptor).read_text(encoding="utf-8"))
        if (self.descriptor.get("name") != "stage_selected_owner_files" or
                self.descriptor.get("_meta", {}).get("openai/fileParams") != ["files"]):
            raise MCPRefused("FILE_PARAMS_DESCRIPTOR_INVALID")
        self.mutex = threading.Lock()
        self.running: set[str] = set()
        self.lock = threading.Lock()

    def authorize(self, header: str | None) -> bool:
        # Caller identity is bound to a uniquely Owner-provisioned plugin API key.
        # The model never sees this value. No unauthenticated action is accepted.
        if type(header) is not str or not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].encode("utf-8", "replace"), self.secret)

    def descriptors(self):
        stage = dict(self.descriptor)
        return [stage, {
            "name": "status_selected_owner_files",
            "title": "Verificar chegada privada dos anexos",
            "description": "Read the status of a previously authorized selected-file transfer. Does not send orders or trigger workers.",
            "inputSchema": {
                "type": "object", "properties": {
                    "job_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"}},
                "required": ["job_id"], "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "openWorldHint": False,
                            "destructiveHint": False},
        }]

    def start(self, files: Any) -> dict:
        if type(files) is not list or not 1 <= len(files) <= ingress.MAX_FILES:
            raise MCPRefused("INVALID_SELECTION")
        # No network or side effects before strict selected-file validation.
        try:
            checked = [ingress._check_file(item, ingress.DEFAULT_ALLOWED_HOSTS)
                       for item in files]
        except ingress.IngressRefused:
            raise MCPRefused("INVALID_SELECTION") from None
        if len({f[0] for f in checked}) != len(checked):
            raise MCPRefused("DUPLICATE_SELECTION")
        if not self.mutex.acquire(blocking=False):
            raise MCPRefused("TRANSFER_IN_PROGRESS")
        try:
            pending = [p for p in self.inbox.iterdir()
                       if p.is_dir() and JOB_ID.fullmatch(p.name)]
            if len(pending) >= MAX_STAGED_JOBS:
                raise MCPRefused("PRIVATE_INBOX_CAPACITY_REACHED")
            job = secrets.token_hex(16)
            _record(self.jobs, job, {"status": "TRANSFERRING", "created": int(time.time())})
            with self.lock:
                self.running.add(job)
            try:
                thread = threading.Thread(target=self._worker, args=(job, list(files)), daemon=True)
                thread.start()
            except RuntimeError:
                self.running.discard(job)
                _record(self.jobs, job, {"status": "FAILED"})
                raise MCPRefused("TRANSFER_NOT_STARTED") from None
            return {"status": "TRANSFERRING", "job_id": job}
        except Exception:
            self.mutex.release()
            raise

    def _worker(self, job: str, files: list[dict]):
        try:
            receipt = ingress.stage(files, self.inbox, verified_owner=OWNER)
            verified = {"status": "READY", "bundle_id": receipt.bundle_id,
                        "file_count": receipt.file_count,
                        "originals": [dict(name=x.name, size=x.size, sha256=x.sha256)
                                      for x in receipt.originals]}
            _record(self.jobs, job, verified)
        except Exception:
            # No exception string: could contain presigned URL or file contents.
            _record(self.jobs, job, {"status": "FAILED"})
        finally:
            with self.lock:
                self.running.discard(job)
            self.mutex.release()

    def status(self, job: Any) -> dict:
        record = _read_record(self.jobs, job)
        if record.get("status") == "TRANSFERRING":
            with self.lock:
                alive = job in self.running
            if not alive:
                return {"status": "FAILED"}
        if record.get("status") not in ("READY", "FAILED", "TRANSFERRING"):
            raise MCPRefused("JOB_NOT_AVAILABLE")
        return record


class Handler(BaseHTTPRequestHandler):
    # A client that stalls before sending its headers/body must not occupy
    # unbounded authenticated tunnel threads or VPS sockets.
    def setup(self):
        # The request socket exists before StreamRequestHandler defines connection.
        self.request.settimeout(60)
        super().setup()

    # Disable all access logging to avoid presigned URLs or auth headers in logs.
    def log_message(self, format, *args):
        return

    def _send(self, code: int, data: dict | None):
        body = b"" if data is None else json.dumps(data, ensure_ascii=True,
                                                      separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._send(405, {"error": "METHOD_NOT_ALLOWED"})

    def do_POST(self):
        tool: MediaTool = self.server.media_tool
        if self.path != "/mcp":
            return self._send(404, {"error": "NOT_FOUND"})
        if not tool.authorize(self.headers.get("Authorization")):
            return self._send(401, {"error": "UNAUTHORIZED"})
        length = self.headers.get("Content-Length")
        if (length is None or not length.isascii() or not length.isdecimal()
                or not 1 <= int(length) <= MAX_JSON_REQUEST):
            return self._send(413, {"error": "REQUEST_TOO_LARGE"})
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            return self._send(415, {"error": "UNSUPPORTED_MEDIA_TYPE"})
        obj = None
        try:
            obj = json.loads(self.rfile.read(int(length)))
            if (type(obj) is not dict or obj.get("jsonrpc") != "2.0" or
                    type(obj.get("method")) is not str):
                raise MCPRefused("INVALID_JSON_RPC")
            method, ident = obj["method"], obj.get("id")
            if "id" not in obj:  # MCP notifications do not receive replies.
                return self._send(202, None)
            if type(ident) not in (int, str):
                raise MCPRefused("INVALID_JSON_RPC_ID")
            args = obj.get("params") or {}
            if type(args) is not dict:
                raise MCPRefused("INVALID_ARGUMENTS")
            if method == "initialize":
                pv = args.get("protocolVersion")
                result = {"protocolVersion": pv if pv in SUPPORTED_PROTOCOLS else PROTOCOL_VERSION,
                          "serverInfo": {"name": "project-leader-selected-media", "version": "1.0.0"},
                          "capabilities": {"tools": {"listChanged": False}}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": tool.descriptors()}
            elif method == "tools/call":
                name = args.get("name")
                data = args.get("arguments")
                if type(data) is not dict:
                    raise MCPRefused("INVALID_ARGUMENTS")
                if name == "stage_selected_owner_files" and set(data) == {"files"}:
                    response = tool.start(data["files"])
                elif name == "status_selected_owner_files" and set(data) == {"job_id"}:
                    response = tool.status(data["job_id"])
                else:
                    raise MCPRefused("TOOL_NOT_ALLOWED")
                result = {"content": [{"type": "text",
                                       "text": json.dumps(response, sort_keys=True)}],
                          "isError": False}
            else:
                raise MCPRefused("UNKNOWN_METHOD")
            return self._send(200, {"jsonrpc": "2.0", "id": ident, "result": result})
        except (ValueError, UnicodeError, TypeError, MCPRefused) as exc:
            reason = str(exc) if isinstance(exc, MCPRefused) else "MALFORMED_REQUEST"
            return self._send(200, {"jsonrpc": "2.0", "id": obj.get("id") if isinstance(obj, dict) else None,
                                    "error": {"code": -32602, "message": reason}})


def make_server(tool: MediaTool, *, port: int = 8765):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise MCPRefused("INVALID_LISTEN_PORT")
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.media_tool = tool
    return server


def main():
    # Explicit opt-in to local server. Never opens public ports on VPS.
    keyfile = os.environ.get("PROJECT_LEADER_MCP_OWNER_KEY_FILE")
    if not keyfile:
        raise SystemExit("PRIVATE_MCP_KEY_NOT_CONFIGURED")
    script = Path(__file__).resolve()
    inbox = Path.home() / "codex-bridge" / ".coordinator-inbox"
    port = int(os.environ.get("PROJECT_LEADER_MCP_LOCAL_PORT", "8765"))
    try:
        tool = MediaTool(inbox=inbox, key_file=Path(keyfile),
                         descriptor=script.with_name("chatgpt_coordinator_file_tool.json"))
        srv = make_server(tool, port=port)
    except (MCPRefused, OSError, ValueError):
        raise SystemExit("PRIVATE_MCP_STARTUP_REFUSED") from None
    srv.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()