#!/usr/bin/env python3
"""Single-use encrypted original-file relay into the existing Coordinator inbox.

This is NOT a Coordinator, a public uploader, or a work-order trigger.
Only a pinned-SSH GitHub Actions workflow, authenticated as Owner, may run
`request` or `stage` on the VPS. The private X25519 key never leaves that VPS.

The Python cryptography library is required; fail closed if unavailable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tempfile
import time
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SESSION_RE = re.compile(r"[0-9a-f]{32}\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
STORED = re.compile(r"file-(0[0-9]{2}|[0-9]{3})\.(jpg|jpeg|png|webp|gif|mp4|mov|webm|pdf|txt|md|csv|json|zip|docx|xlsx|pptx|xml|log|bin)\Z")
MAGIC = b"PLMEDIA1"
BUF = 1024 * 1024
TOTAL_LIMIT = 1024 * 1024 * 1024
RELAY_OVERHEAD = 16 * 1024 * 1024
MAX_FILES = 16


class RelayRefused(ValueError):
    """Static refusal; never include document content or signed download URLs."""


def _session(s):
    if type(s) is not str or SESSION_RE.fullmatch(s) is None:
        raise RelayRefused("Invalid private media session")
    return s


def _private_dir(path, create=False):
    path = Path(path)
    if create and not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    try:
        info = path.lstat()
    except OSError as exc:
        raise RelayRefused("Missing private directory") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or path.is_symlink()):
        raise RelayRefused("Unsafe private directory")
    return path


def _private_file(path):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise RelayRefused("Missing private file") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        raise RelayRefused("Unsafe private file")
    return path


def _inbox(home):
    bridge = Path(home) / "codex-bridge"
    if bridge.is_symlink() or not bridge.is_dir():
        raise RelayRefused("Coordinator bridge missing")
    if bridge.stat().st_uid != os.getuid():
        raise RelayRefused("Coordinator bridge owner mismatch")
    return _private_dir(bridge / ".coordinator-inbox", create=True)


def _keys(inbox):
    return _private_dir(inbox / ".relay-keys", create=True)


def request_key(inbox: Path, session: str) -> str:
    """Generate one recipient key on VPS; return PUBLIC material only."""
    _session(session)
    _private_dir(inbox)
    root = _keys(inbox)
    keydir = root / session
    if keydir.exists() or keydir.is_symlink():
        raise RelayRefused("Private session already exists")
    keydir.mkdir(mode=0o700)
    try:
        priv = x25519.X25519PrivateKey.generate()
        private = priv.private_bytes(serialization.Encoding.Raw,
                                     serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption())
        keypath = keydir / "private.key"
        fd = os.open(keypath, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(private)
        public = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
        return base64.b64encode(public).decode("ascii")
    except Exception:
        shutil.rmtree(keydir, ignore_errors=True)
        raise


def _hkdf(shared, nonce, session):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce,
                info=b"ProjectLeader-private-media-v1-" + bytes.fromhex(session)).derive(shared)


def seal(bundle: Path, session: str, recipient_pub_b64: str, output: Path) -> tuple[str, int]:
    """Encrypt bytes in bounded memory; never upload the original ZIP to GitHub."""
    _session(session)
    try:
        public = x25519.X25519PublicKey.from_public_bytes(
            base64.b64decode(recipient_pub_b64, validate=True))
    except (ValueError, TypeError) as exc:
        raise RelayRefused("Untrusted media recipient key") from exc
    bundle = Path(bundle)
    if not bundle.is_file() or bundle.stat().st_size <= 0 or bundle.stat().st_size > TOTAL_LIMIT + RELAY_OVERHEAD:
        raise RelayRefused("Original bundle outside size limit")
    epriv = x25519.X25519PrivateKey.generate()
    ep = epriv.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    nonce = os.urandom(12)
    header = json.dumps({"version": 1, "session": session,
                         "ephemeral": base64.b64encode(ep).decode("ascii"),
                         "nonce": base64.b64encode(nonce).decode("ascii")},
                        separators=(",", ":"), sort_keys=True).encode("ascii")
    key = _hkdf(epriv.exchange(public), nonce, session)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    prefix = MAGIC + struct.pack(">H", len(header)) + header
    cipher.authenticate_additional_data(prefix)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise RelayRefused("Sealed output already exists")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as out, bundle.open("rb") as source:
            out.write(prefix)
            digest.update(prefix)
            size += len(prefix)
            while chunk := source.read(BUF):
                data = cipher.update(chunk)
                out.write(data)
                digest.update(data)
                size += len(data)
            tail = cipher.finalize() + cipher.tag
            out.write(tail)
            digest.update(tail)
            size += len(tail)
        return digest.hexdigest(), size
    except Exception:
        output.unlink(missing_ok=True)
        raise


def _decrypt(infile, outfile, keyfile, session):
    """Read protected ciphertext, emit private ZIP and verify GCM before use."""
    original = _private_file(infile)
    original_size = original.stat().st_size
    if not 50 <= original_size <= TOTAL_LIMIT + RELAY_OVERHEAD:
        raise RelayRefused("Ciphertext size outside limit")
    with original.open("rb") as f:
        prefix = f.read(len(MAGIC) + 2)
        if len(prefix) != len(MAGIC) + 2 or not prefix.startswith(MAGIC):
            raise RelayRefused("Invalid sealed payload")
        hsize = struct.unpack(">H", prefix[len(MAGIC):])[0]
        if not 50 <= hsize <= 512:
            raise RelayRefused("Invalid sealed header length")
        header = f.read(hsize)
        try:
            info = json.loads(header.decode("ascii"))
            if (type(info) is not dict or set(info) != {"version", "session", "ephemeral", "nonce"}
                    or info["version"] != 1 or info["session"] != session):
                raise ValueError()
            ephemeral = base64.b64decode(info["ephemeral"], validate=True)
            nonce = base64.b64decode(info["nonce"], validate=True)
            if len(ephemeral) != 32 or len(nonce) != 12:
                raise ValueError()
            public = x25519.X25519PublicKey.from_public_bytes(ephemeral)
        except (ValueError, KeyError, TypeError) as exc:
            raise RelayRefused("Invalid sealed header") from exc
        payload_offset = len(prefix) + len(header)
        if original_size - payload_offset < 17:
            raise RelayRefused("Truncated sealed payload")
        f.seek(original_size - 16)
        tag = f.read(16)
        key = x25519.X25519PrivateKey.from_private_bytes(
            _private_file(keyfile).read_bytes())
        decryptor = Cipher(algorithms.AES(_hkdf(key.exchange(public), nonce, session)),
                           modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(prefix + header)
        fd = os.open(outfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as target:
                f.seek(payload_offset)
                remaining = original_size - payload_offset - 16
                while remaining:
                    chunk = f.read(min(BUF, remaining))
                    if not chunk:
                        raise RelayRefused("Truncated sealed payload")
                    target.write(decryptor.update(chunk))
                    remaining -= len(chunk)
                try:
                    target.write(decryptor.finalize())
                except InvalidTag as exc:
                    raise RelayRefused("Private payload integrity failure") from exc
        except Exception:
            outfile.unlink(missing_ok=True)
            raise


def _unpack_verified(zip_path: Path, destination: Path) -> int:
    """Extract exactly the allowlisted originals and verify their sha256/size."""
    if destination.exists() or destination.is_symlink():
        raise RelayRefused("Destination already exists")
    with zipfile.ZipFile(zip_path) as archive:
        entries = archive.infolist()
        if not 2 <= len(entries) <= MAX_FILES + 1:
            raise RelayRefused("Invalid original-file selection")
        names = [e.filename for e in entries]
        if len(set(names)) != len(names) or "manifest.json" not in names:
            raise RelayRefused("Invalid original-file listing")
        for entry in entries:
            if (entry.is_dir() or entry.compress_type != zipfile.ZIP_STORED
                    or entry.filename != "manifest.json" and not STORED.fullmatch(entry.filename)
                    or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.file_size < 1 or entry.file_size > TOTAL_LIMIT):
                raise RelayRefused("Unsafe original ZIP entry")
        if sum(e.file_size for e in entries if e.filename != "manifest.json") > TOTAL_LIMIT:
            raise RelayRefused("Selected files exceed one-GiB limit")
        if archive.getinfo("manifest.json").file_size > 8192:
            raise RelayRefused("Oversized original-file manifest")
        metadata = archive.read("manifest.json")
        try:
            manifest = json.loads(metadata)
            if (set(manifest) != {"version", "selection", "files"}
                    or manifest["version"] != 1 or manifest["selection"] != "owner_explicit"
                    or type(manifest["files"]) is not list
                    or not 1 <= len(manifest["files"]) <= MAX_FILES):
                raise ValueError()
        except (ValueError, TypeError) as exc:
            raise RelayRefused("Invalid original-file manifest") from exc
        expected = set()
        destination.mkdir(mode=0o700)
        try:
            for index, item in enumerate(manifest["files"], 1):
                if (type(item) is not dict or set(item) != {"id", "name", "stored", "sha256", "size", "mime"}
                        or item["id"] != f"file-{index:03d}"
                        or type(item["stored"]) is not str or not STORED.fullmatch(item["stored"])
                        or not item["stored"].startswith(f"file-{index:03d}.")
                        or type(item["sha256"]) is not str or not HEX_SHA256.fullmatch(item["sha256"])
                        or type(item["size"]) is not int or not 1 <= item["size"] <= TOTAL_LIMIT
                        or type(item["name"]) is not str or not item["name"] or "/" in item["name"] or "\\" in item["name"]
                        or type(item["mime"]) is not str or not item["mime"]):
                    raise RelayRefused("Invalid selected-file description")
                member = item["stored"]
                expected.add(member)
                if archive.getinfo(member).file_size != item["size"]:
                    raise RelayRefused("Declared original size mismatch")
                digest = hashlib.sha256()
                total = 0
                fd = os.open(destination / member,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as out, archive.open(member) as source:
                    while chunk := source.read(BUF):
                        total += len(chunk)
                        if total > item["size"]:
                            raise RelayRefused("Original exceeds declared size")
                        digest.update(chunk)
                        out.write(chunk)
                if total != item["size"] or digest.hexdigest() != item["sha256"]:
                    raise RelayRefused("Original file integrity mismatch")
            if set(names) != expected | {"manifest.json"}:
                raise RelayRefused("Unselected original-file entries")
            fd = os.open(destination / "manifest.json",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(metadata)
            return len(expected)
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise


def stage(inbox: Path, session: str, expected_cipher_sha: str) -> int:
    """Consume one ciphertext and recipient key; publish only complete private originals."""
    _session(session)
    if type(expected_cipher_sha) is not str or not HEX_SHA256.fullmatch(expected_cipher_sha):
        raise RelayRefused("Invalid ciphertext checksum")
    inbox = _private_dir(inbox)
    keys = _keys(inbox)
    keydir = _private_dir(keys / session)
    age = time.time() - keydir.stat().st_mtime
    if age < -120 or age > 86400:
        raise RelayRefused("Expired private media session")
    cipherpath = _private_file(inbox / (".relay-cipher-" + session))
    if cipherpath.stat().st_size > TOTAL_LIMIT + RELAY_OVERHEAD:
        raise RelayRefused("Ciphertext exceeds one-GiB limit")
    digest = hashlib.sha256()
    with cipherpath.open("rb") as f:
        while chunk := f.read(BUF):
            digest.update(chunk)
    if digest.hexdigest() != expected_cipher_sha:
        raise RelayRefused("Ciphertext checksum mismatch")
    fd, name = tempfile.mkstemp(prefix=".relay-decrypted-", suffix=".zip", dir=inbox)
    os.close(fd)
    plaintext = Path(name)
    plaintext.unlink()
    destination = inbox / session
    try:
        _decrypt(cipherpath, plaintext, keydir / "private.key", session)
        count = _unpack_verified(plaintext, destination)
        return count
    finally:
        plaintext.unlink(missing_ok=True)
        cipherpath.unlink(missing_ok=True)
        shutil.rmtree(keydir, ignore_errors=True)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        return 2
    command, session = argv[:2]
    try:
        _session(session)
        inbox = _inbox(Path.home())
        if command == "request" and len(argv) == 2:
            print("MEDIA_PUBLIC_KEY_V1=" + request_key(inbox, session))
            return 0
        if command == "stage" and len(argv) == 3:
            count = stage(inbox, session, argv[2])
            print("MEDIA_PRIVATE_STAGED_V1=" + session + ";count=" + str(count))
            return 0
    except (RelayRefused, OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        print("MEDIA_PRIVATE_STAGE_REFUSED", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())