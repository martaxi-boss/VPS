#!/usr/bin/env python3
"""Stage Owner-selected ChatGPT files into the EXISTING Coordinator's private inbox.

A ChatGPT MCP app tool must receive files via `_meta['openai/fileParams']`,
perform OAuth Owner validation, then call stage() with the verified identity.
This module deliberately does not serve a public HTTP endpoint, send orders,
create a Coordinator, or bypass existing Owner/worker gates.

Never log file download URLs. They are short-lived credentials.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import secrets
from typing import Callable, Mapping, Sequence
from urllib import error, parse, request

try:
    from ops import coordinator_media
except ModuleNotFoundError:
    import coordinator_media

OWNER = "martaxi-boss"
MAX_FILES = coordinator_media.MAX_FILES
MAX_FILE_BYTES = coordinator_media.MAX_FILE_BYTES
MAX_TOTAL_BYTES = coordinator_media.MAX_TOTAL_BYTES
FILE_ID = re.compile(r"file[-_][A-Za-z0-9_-]{8,180}\Z", re.ASCII)
MIME = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+\Z", re.ASCII)
BUNDLE_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)

# Configuration supplied by the trusted MCP backend, NEVER an LLM/user field.
# Adapt this allowlist ONLY after seeing the real, certified ChatGPT file host.
DEFAULT_ALLOWED_HOSTS = frozenset({"files.oaiusercontent.com", "chatgpt.com"})


class IngressRefused(ValueError):
    """No original files are considered delivered after any ingress failure."""


@dataclass(frozen=True)
class FileReceipt:
    file_id: str
    name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class Receipt:
    bundle_id: str
    file_count: int
    originals: tuple[FileReceipt, ...]


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A presigned URL redirect could leave the trusted CDN host (SSRF).
        return None


def _private_dir(path: Path) -> Path:
    path = Path(path)
    if path.is_symlink():
        raise IngressRefused("Private upload inbox is a symlink")
    try:
        info = path.lstat()
    except OSError as exc:
        raise IngressRefused("Private upload inbox is unavailable") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077):
        raise IngressRefused("Private upload inbox is not owner-only")
    return path.resolve(strict=True)


def _check_file(value: Mapping[str, str], approved_hosts: frozenset[str]) -> tuple[str, str, str]:
    if not isinstance(value, dict):
        raise IngressRefused("Invalid ChatGPT file parameter")
    if not {"download_url", "file_id"} <= set(value):
        raise IngressRefused("Incomplete ChatGPT file parameter")
    if set(value) - {"download_url", "file_id", "file_name", "mime_type"}:
        raise IngressRefused("Unexpected ChatGPT file parameter")
    file_id = value["file_id"]
    if type(file_id) is not str or not FILE_ID.fullmatch(file_id):
        raise IngressRefused("Invalid ChatGPT file identity")
    original_name = value.get("file_name") or (file_id + ".bin")
    try:
        original_name = coordinator_media._check_original_name(original_name)
    except coordinator_media.MediaRefused as exc:
        raise IngressRefused("Unsafe ChatGPT original filename") from exc
    mime = value.get("mime_type")
    if mime is not None and (type(mime) is not str or not MIME.fullmatch(mime)):
        raise IngressRefused("Invalid ChatGPT media type")
    raw_url = value["download_url"]
    if type(raw_url) is not str or not 1 <= len(raw_url) <= 8192:
        raise IngressRefused("Invalid private file transfer URL")
    try:
        parsed = parse.urlsplit(raw_url)
        # No arbitrary URLs, localhost, custom ports, redirectors or credentials.
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise IngressRefused("Invalid private file transfer URL") from exc
    if (parsed.scheme != "https" or parsed.username is not None or
            parsed.password is not None or port not in (None, 443) or
            parsed.fragment or not hostname or hostname not in approved_hosts or
            any(ord(ch) > 127 for ch in hostname) or
            not parsed.path.startswith("/") or parsed.path.startswith("//")):
        raise IngressRefused("Unapproved private file download host")
    return file_id, original_name, raw_url


def _secure_download(url: str, target: Path, maximum: int) -> int:
    """Fetch one HTTPS file with redirects and proxying disabled, bounded bytes."""
    opener = request.build_opener(
        request.ProxyHandler({}), request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect())
    req = request.Request(url, headers={"Accept-Encoding": "identity",
                                        "User-Agent": "ProjectLeader-ChatGPT-PrivateIngress/1"})
    total = 0
    try:
        with opener.open(req, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise IngressRefused("Invalid private file response")
            advertised = response.headers.get("Content-Length")
            if advertised is not None:
                if not advertised.isdecimal() or int(advertised) > maximum:
                    raise IngressRefused("Private file size exceeds limit")
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                while data := response.read(1024 * 1024):
                    total += len(data)
                    if total > maximum:
                        raise IngressRefused("Private file size exceeds limit")
                    output.write(data)
            if advertised is not None and total != int(advertised):
                raise IngressRefused("Truncated private file transfer")
    except (error.URLError, error.HTTPError, OSError, TimeoutError,
            http.client.HTTPException) as exc:
        # Signed download URL and any response details must never reach logs.
        raise IngressRefused("Private file download could not be completed") from None
    if total < 1:
        raise IngressRefused("Empty private file transfer")
    return total


def stage(
    files: Sequence[Mapping[str, str]], inbox: Path, *,
    verified_owner: str,
    approved_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS,
    downloader: Callable[[str, Path, int], int] = _secure_download,
) -> Receipt:
    """Stage only explicitly selected originals, atomically and once.

    verified_owner MUST come from the MCP server's validated OAuth principal,
    never from model/tool parameters. Staging does not send a work order.
    """
    if verified_owner != OWNER:
        raise IngressRefused("Owner authorization not verified")
    if type(files) not in (list, tuple) or not 1 <= len(files) <= MAX_FILES:
        raise IngressRefused("Invalid number of selected attachments")
    if (type(approved_hosts) is not frozenset or not approved_hosts or
            any(type(h) is not str or not h or h.lower() != h or
                "/" in h or ":" in h for h in approved_hosts)):
        raise IngressRefused("Trusted download host configuration is missing")
    root = _private_dir(Path(inbox))
    validated = tuple(_check_file(x, approved_hosts) for x in files)
    ids = [x[0] for x in validated]
    if len(set(ids)) != len(ids):
        raise IngressRefused("Duplicate selected ChatGPT file")
    bundle_id = secrets.token_hex(16)
    if not BUNDLE_ID.fullmatch(bundle_id):
        raise IngressRefused("Invalid transfer identifier")
    temporary = root / (".receiving-" + bundle_id)
    destination = root / bundle_id
    if destination.exists() or destination.is_symlink():
        raise IngressRefused("Existing transfer identifier must not be reused")
    temporary.mkdir(mode=0o700)
    total = 0
    try:
        sources = []
        for index, (_, name, url) in enumerate(validated, 1):
            # Per-file folders preserve identical original filenames.
            part = temporary / f"part-{index:03d}"
            part.mkdir(mode=0o700)
            original = part / name
            size = downloader(url, original, MAX_FILE_BYTES)
            info = original.lstat()
            if (type(size) is not int or size < 1 or size > MAX_FILE_BYTES or
                    not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.getuid() or info.st_mode & 0o077 or
                    info.st_size != size):
                raise IngressRefused("Selected file transfer failed integrity checks")
            total += size
            if total > MAX_TOTAL_BYTES:
                raise IngressRefused("Selected files exceed maximum transfer size")
            sources.append(original)
        staged = coordinator_media.pack(sources, temporary / "bundle")
        checked = coordinator_media.verify(staged)
        if len(checked) != len(validated):
            raise IngressRefused("Incomplete selected-file bundle")
        # Move a COMPLETE private bundle into the existing Coordinator inbox.
        staged.rename(destination)
        checked = coordinator_media.verify(destination)
        receipts = tuple(FileReceipt(file_id=validated[i][0], name=item.name,
                                     sha256=item.sha256, size=item.size)
                         for i, item in enumerate(checked))
        return Receipt(bundle_id, len(receipts), receipts)
    except (OSError, coordinator_media.MediaRefused) as exc:
        raise IngressRefused("Selected private attachments could not be staged") from None
    finally:
        shutil.rmtree(temporary, ignore_errors=True)