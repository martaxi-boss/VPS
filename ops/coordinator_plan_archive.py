"""Private append-only archive of the EXISTING Coordinator's verified Owner DAG.

The archive is host-side evidence, not a new Coordinator, dispatch gateway,
Supervisor, or approval. It never certifies PRs or launches a model.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from ops.coordinator_phase_continuation import _audited

JOB = re.compile(r"[1-9][0-9]{7,14}-[1-9][0-9]{0,3}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SCHEMA = "ORIGINAL_OWNER_DAG_PRIVATE_ARCHIVE_V1"


class PrivatePlanError(ValueError):
    """Unsafe, missing or changed original Owner planning evidence."""


def _record(original_b64: str, job: str, target: str, audited_sha: str) -> dict:
    if (type(job) is not str or not JOB.fullmatch(job)
            or type(target) is not str or not target.startswith("martaxi-boss/")
            or type(audited_sha) is not str or not SHA.fullmatch(audited_sha)):
        raise PrivatePlanError("Invalid original Owner run provenance")
    try:
        original, phases = _audited(original_b64)
        raw = base64.b64decode(original_b64.encode("ascii"), validate=True)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise PrivatePlanError("Unverified original Coordinator DAG") from exc
    if (not 0 < len(raw) <= 24_000
            or base64.b64encode(raw).decode("ascii") != original_b64
            or phases["target_repository"] != target
            or phases["audited_revision"] != audited_sha
            or original["target_repository"] != target):
        raise PrivatePlanError("Original target or audited revision mismatch")
    return {
        "schema": SCHEMA,
        "job": job,
        "target_repository": target,
        "audited_sha": audited_sha,
        "phase_count": phases["phase_count"],
        "audit_sha256": hashlib.sha256(raw).hexdigest(),
        "original_plan_b64": original_b64,
    }


def _owner_only(directory: Path, *, create: bool) -> Path:
    directory = Path(directory)
    if directory.is_symlink():
        raise PrivatePlanError("Archive directory symlink refused")
    try:
        if create:
            directory.mkdir(mode=0o700, exist_ok=True)
        mode = directory.lstat()
        if (not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid()
                or stat.S_IMODE(mode.st_mode) != 0o700):
            raise PrivatePlanError("Archive directory requires mode 0700 and owner UID")
    except OSError as exc:
        raise PrivatePlanError("Private Owner archive directory unavailable") from exc
    return directory


def archive_verified_plan(original_b64: str, directory: Path, *,
                          job: str, target: str, audited_sha: str) -> dict:
    """Atomically retain only an independently validated original plan.

    The caller authenticates the Owner Issue and validates all audited git
    paths BEFORE calling. Refuse duplicate writes, including ambiguous retries.
    No original media, credentials, audit bytes or worker text are logged.
    """
    record = _record(original_b64, job, target, audited_sha)
    root = _owner_only(directory, create=True)
    destination = root / (job + ".json")
    if destination.exists() or destination.is_symlink():
        raise PrivatePlanError("Owner DAG already archived; no blind replay")
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    fd, temporary = tempfile.mkstemp(prefix=".owner-dag-", suffix=".tmp", dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic no-overwrite publication: even a competing writer cannot
        # replace a previous certified run's original Owner audit.
        os.link(temporary, destination, follow_symlinks=False)
        parent_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise PrivatePlanError("Private archive publication failed") from exc
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {k: record[k] for k in (
        "job", "target_repository", "audited_sha", "phase_count", "audit_sha256"
    )}


def load_original_plan(directory: Path, *, job: str, target: str,
                       audited_sha: str) -> str:
    """Restore verified bytes only. A separate external certifier MUST check
    Owner Issue, exact target CI, accepted merges and current main SHA before
    any next phase. Existence of this file grants NO dispatch authority.
    """
    if type(job) is not str or not JOB.fullmatch(job):
        raise PrivatePlanError("Invalid archived Owner job")
    root = _owner_only(directory, create=False)
    path = root / (job + ".json")
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 36_000):
            raise PrivatePlanError("Original archive is not an owner-only regular file")
        record = json.loads(path.read_bytes().decode("ascii", "strict"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PrivatePlanError("Original archived Owner plan missing or invalid") from exc
    if not isinstance(record, dict) or set(record) != {
        "schema", "job", "target_repository", "audited_sha", "phase_count",
        "audit_sha256", "original_plan_b64"
    } or record["schema"] != SCHEMA:
        raise PrivatePlanError("Original archive schema is invalid")
    if _record(record["original_plan_b64"], job, target, audited_sha) != record:
        raise PrivatePlanError("Original Owner plan integrity or scope mismatch")
    return record["original_plan_b64"]
