#!/usr/bin/env python3
"""Private, explicitly selected original-file evidence for the existing Coordinator.

This is a transport-neutral data contract, NOT a network endpoint, uploader,
second Coordinator or worker.  The caller must deliver the complete private
bundle to the existing Coordinator before invoking its model. No partial bundle
is valid. All files are kept byte-for-byte; derived visual previews are additive.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

MAX_FILES = 16
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
SUFFIX = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".mp4", ".mov", ".webm", ".pdf", ".txt", ".md", ".csv", ".json", ".zip", ".docx", ".xlsx", ".pptx", ".xml", ".log"}
SHA = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"file-[0-9]{3}\Z")


class MediaRefused(ValueError):
    """A selected attachment could not be transferred or verified exactly."""


@dataclass(frozen=True)
class SelectedMedia:
    item_id: str
    name: str
    mime: str
    original: Path
    size: int
    sha256: str


@dataclass(frozen=True)
class VerifiedBundle:
    directory: Path
    originals: tuple[SelectedMedia, ...]
    images: tuple[Path, ...]
    notes: tuple[str, ...]


def _sha256(path: Path, maximum: int = MAX_FILE_BYTES) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > maximum:
                raise MediaRefused("Attachment exceeds size limit")
            digest.update(chunk)
    return digest.hexdigest(), count


def _private_directory(path: Path) -> Path:
    if path.is_symlink():
        raise MediaRefused("Attachment directory is symlinked")
    try:
        info = path.lstat()
    except OSError as exc:
        raise MediaRefused("Attachment directory is missing") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077):
        raise MediaRefused("Attachment directory is not owner-only")
    return path.resolve(strict=True)


def _regular_private(path: Path, parent: Path) -> None:
    if path.parent != parent:
        raise MediaRefused("Attachment escapes private directory")
    try:
        info = path.lstat()
    except OSError as exc:
        raise MediaRefused("Selected attachment is missing") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077 or info.st_nlink != 1 or
            info.st_size < 1 or info.st_size > MAX_FILE_BYTES):
        raise MediaRefused("Selected attachment has unsafe metadata")


def _check_original_name(name: object) -> str:
    if (type(name) is not str or not 1 <= len(name) <= 180 or
            any(ord(c) < 32 or ord(c) == 127 for c in name) or
            "/" in name or "\\" in name or name in (".", "..")):
        raise MediaRefused("Invalid original attachment name")
    return name


def pack(paths: list[Path], destination: Path) -> Path:
    """Prepare an exact local bundle; transport it only when the Owner opts in."""
    if not 1 <= len(paths) <= MAX_FILES:
        raise MediaRefused("Invalid number of selected attachments")
    if destination.exists() or destination.is_symlink():
        raise MediaRefused("Private destination must not already exist")
    destination.mkdir(mode=0o700, parents=False)
    root = _private_directory(destination)
    files = []
    total = 0
    try:
        for i, source in enumerate(paths, 1):
            source = Path(source)
            name = _check_original_name(source.name)
            original_info = source.lstat()
            if not stat.S_ISREG(original_info.st_mode) or original_info.st_size < 1:
                raise MediaRefused("Selected original is not a regular file")
            ext = source.suffix.lower()
            entry_name = f"file-{i:03d}{ext if ext in SUFFIX else '.bin'}"
            dest = root / entry_name
            with source.open("rb") as inp:
                with dest.open("xb") as out:
                    os.chmod(dest, 0o600)
                    digest = hashlib.sha256()
                    count = 0
                    while chunk := inp.read(1024 * 1024):
                        count += len(chunk)
                        total += len(chunk)
                        if count > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                            raise MediaRefused("Selected attachments exceed size limit")
                        out.write(chunk)
                        digest.update(chunk)
            mime = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".gif": "image/gif", ".mp4": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm", ".pdf": "application/pdf"}.get(ext, "application/octet-stream")
            files.append({"id": f"file-{i:03d}", "name": name,
                          "stored": entry_name, "sha256": digest.hexdigest(),
                          "size": count, "mime": mime})
        manifest = root / "manifest.json"
        fd = os.open(manifest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"version": 1, "selection": "owner_explicit", "files": files},
                      stream, separators=(",", ":"), ensure_ascii=True)
            stream.write("\n")
        verify(root)
        return root
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def verify(directory: Path) -> tuple[SelectedMedia, ...]:
    """Fail closed if even one declared original is missing, changed or extra."""
    root = _private_directory(Path(directory))
    manifest = root / "manifest.json"
    _regular_private(manifest, root)
    if manifest.stat().st_size > 8192:
        raise MediaRefused("Attachment manifest is too large")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise MediaRefused("Invalid attachment manifest") from exc
    if (type(data) is not dict or set(data) != {"version", "selection", "files"} or
            data["version"] != 1 or data["selection"] != "owner_explicit" or
            type(data["files"]) is not list or not 1 <= len(data["files"]) <= MAX_FILES):
        raise MediaRefused("Invalid explicit selection contract")
    result = []
    seen = set()
    total = 0
    for i, raw in enumerate(data["files"], 1):
        if type(raw) is not dict or set(raw) != {"id", "name", "stored", "sha256", "size", "mime"}:
            raise MediaRefused("Malformed selected attachment metadata")
        ident, stored = raw["id"], raw["stored"]
        if (type(ident) is not str or not ID.fullmatch(ident) or
                ident != f"file-{i:03d}" or type(stored) is not str or
                not stored.startswith(ident) or not stored.endswith(tuple(SUFFIX | {'.bin'})) or
                stored.count(".") != 1 or "/" in stored or "\\" in stored or stored in seen):
            raise MediaRefused("Unsafe attachment file name")
        seen.add(stored)
        _check_original_name(raw["name"])
        if (type(raw["mime"]) is not str or not 1 <= len(raw["mime"]) <= 100 or
                any(ord(c) < 33 or ord(c) > 126 for c in raw["mime"])):
            raise MediaRefused("Invalid attachment media type")
        if (type(raw["sha256"]) is not str or not SHA.fullmatch(raw["sha256"]) or
                type(raw["size"]) is not int or not 1 <= raw["size"] <= MAX_FILE_BYTES):
            raise MediaRefused("Invalid attachment digest or size")
        path = root / stored
        _regular_private(path, root)
        digest, size = _sha256(path)
        if size != raw["size"] or digest != raw["sha256"]:
            raise MediaRefused("Selected attachment digest differs from the original")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise MediaRefused("Attachment bundle size limit exceeded")
        result.append(SelectedMedia(ident, raw["name"], raw["mime"], path, size, digest))
    # Unknown extra files cannot be silently slipped into the selected set.
    if set(x.name for x in root.iterdir()) != seen | {"manifest.json"}:
        raise MediaRefused("Unexpected file in selected attachment bundle")
    return tuple(result)


def prepare(directory: Path, previews: Path, *, video_frames: int = 3) -> VerifiedBundle:
    """Make additional visual inputs without replacing the originals."""
    originals = verify(directory)
    preview_dir = Path(previews)
    if preview_dir.exists() or preview_dir.is_symlink():
        raise MediaRefused("Preview directory must not already exist")
    preview_dir.mkdir(mode=0o700, parents=False)
    _private_directory(preview_dir)
    images: list[Path] = []
    notes: list[str] = []
    try:
        for item in originals:
            if item.mime in {"image/jpeg", "image/png", "image/webp"}:
                images.append(item.original)
                notes.append(item.item_id + ": original image attached to the Codex model")
            elif item.mime.startswith("video/"):
                if shutil.which("ffmpeg") is None:
                    raise MediaRefused("Video preview generator is unavailable")
                for frame in range(video_frames):
                    output = preview_dir / f"{item.item_id}-frame-{frame+1}.png"
                    command = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                               "-y", "-ss", str(frame), "-i", str(item.original),
                               "-frames:v", "1", "-vf", "scale='min(1280,iw)':-2", str(output)]
                    try:
                        completed = subprocess.run(command, check=False,
                                                   stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL, timeout=30)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        raise MediaRefused("Video preview failed") from exc
                    if completed.returncode != 0 or not output.is_file() or output.stat().st_size < 1:
                        raise MediaRefused("Video visual preview is incomplete")
                    output.chmod(0o600)
                    images.append(output)
                notes.append(item.item_id + ": original video retained, " + str(video_frames) +
                             " visual frames attached; AUDIO NOT ANALYSED")
            else:
                notes.append(item.item_id + ": original file available read-only; "
                             "format-specific interpretation NOT VERIFIED")
        return VerifiedBundle(Path(directory).resolve(), originals, tuple(images), tuple(notes))
    except Exception:
        shutil.rmtree(preview_dir, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Private Coordinator selected-media contract")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("pack")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("files", nargs="+", type=Path)
    q = sub.add_parser("verify")
    q.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "pack":
            bundle = pack(args.files, args.output)
            files = verify(bundle)
        else:
            files = verify(args.bundle)
    except (MediaRefused, OSError, ValueError) as exc:
        parser.exit(2, "COORDINATOR_ATTACHMENTS_REFUSED: " + str(exc) + "\n")
    print("COORDINATOR_ATTACHMENTS_VERIFIED=" + str(len(files)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())