#!/usr/bin/env python3
"""P311: sign ONE scoped REA task with the EXISTING owner's Android Ed25519 key.

Runs on the owner's trusted device, offline; never sends private key anywhere.
This is a preparation path, NOT a ChatGPT yes/no approval service. In the live
system the signing CLI is unnecessary only after a genuinely authenticated
owner-approval channel is available and security-tested.
"""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys

PURPOSE = "REA_OWNER_SCOPED_TASK_V1"
ORIGIN = "martaxi-boss/VPS:rea/one-skill-bridge-20261023"
MAX_SECONDS = 7 * 24 * 3600
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
HEX = re.compile(r"[a-f0-9]{32}\Z")
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,119}\Z")
JOB_ROOT = Path("/opt/rea-reversa/rea/.rea-private/jobs")
EXPECTED = {
    "purpose", "grant_id", "project", "task_id", "origin", "not_before",
    "expires_at", "allowed_tools", "permitted_effects", "artifact_root",
}
SAFE_EFFECTS = frozenset({"mutatesSession", "writesFilesystem", "launchesProcess"})
DENIED_TOOL_NAMES = frozenset({
    "close_binary", "import_evidence_bundle", "export_evidence_bundle",
    "record_unknown", "update_unknown", "install_adb_package",
    "uninstall_adb_package", "push_adb_file", "start_frida_session",
    "load_frida_script", "execute_rizin_command", "gdb_console",
    "cutter_command", "rizin_debug_command",
})


class ApprovalError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalError("Duplicate grant field")
        result[key] = value
    return result


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ApprovalError("Invalid UTC timestamp")
    try:
        return datetime.strptime(value, TIME_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ApprovalError("Invalid calendar timestamp") from exc


def validate_grant(grant, now=None):
    """Validate exact server-compatible grant shape before owner confirmation."""
    if not isinstance(grant, dict) or set(grant) != EXPECTED:
        raise ApprovalError("Invalid scoped task fields")
    if grant["purpose"] != PURPOSE or grant["origin"] != ORIGIN:
        raise ApprovalError("Unexpected project bridge or signature purpose")
    if not isinstance(grant["grant_id"], str) or not HEX.fullmatch(grant["grant_id"]):
        raise ApprovalError("Invalid grant identifier")
    for key in ("project", "task_id", "artifact_root"):
        value = grant[key]
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ApprovalError("Missing or excessively large grant scope")
    start, end = _timestamp(grant["not_before"]), _timestamp(grant["expires_at"])
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or not start <= now < end:
        raise ApprovalError("Grant is not currently valid")
    if not 0 < (end - start).total_seconds() <= MAX_SECONDS:
        raise ApprovalError("Grant duration exceeds seven days")
    root = Path(grant["artifact_root"])
    if (not root.is_absolute() or str(root) != str(root.resolve()) or
            JOB_ROOT not in root.parents or root == JOB_ROOT):
        raise ApprovalError("Only an isolated task artifact root may be signed")
    names = grant["allowed_tools"]
    if (not isinstance(names, list) or not 1 <= len(names) <= 229 or
            any(not isinstance(n, str) or not NAME.fullmatch(n) for n in names) or
            names != sorted(set(names)) or DENIED_TOOL_NAMES.intersection(names)):
        raise ApprovalError("Tool allowlist is invalid or contains forbidden tools")
    effects = grant["permitted_effects"]
    if (not isinstance(effects, list) or effects != sorted(set(effects)) or
            any(not isinstance(e, str) or e not in SAFE_EFFECTS for e in effects)):
        raise ApprovalError("Grant contains a forbidden effect permission")
    return grant


def _private_key(path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ApprovalError("Private signing key not found on trusted device")
    meta = path.stat()
    if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o600:
        raise ApprovalError("Owner key must be owned by current user, mode 0600")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ApprovalError("Existing owner key is not Ed25519")
    return key


def sign_task(grant, private_key_file, *, approved=False, now=None):
    if approved is not True:
        raise ApprovalError("Explicit owner consent is required")
    validate_grant(grant, now=now)
    owner = _private_key(private_key_file)
    signature = base64.b64encode(owner.sign(_canonical(grant))).decode("ascii")
    return {
        "grant": grant, "owner_signature": signature,
        "project": grant["project"], "task_id": grant["task_id"],
        "origin": grant["origin"], "artifact_root": grant["artifact_root"],
    }


def _load_manifest(path):
    source = Path(path)
    if not source.is_file() or source.is_symlink() or source.stat().st_size > 128000:
        raise ApprovalError("Invalid unsigned grant file")
    return json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _save_new_private(path, data):
    dest = Path(path)
    if not dest.parent.is_dir() or dest.parent.is_symlink():
        raise ApprovalError("Private output directory must already exist")
    mode = stat.S_IMODE(dest.parent.stat().st_mode)
    if mode & 0o077:
        raise ApprovalError("Output directory must not permit group/world access")
    fd = os.open(dest, os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(_canonical(data) + b"\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sign one REA task with existing owner key (offline)")
    parser.add_argument("--grant", required=True, help="Unsigned scoped task JSON")
    parser.add_argument("--private-key", required=True,
                        help="Existing local rea-owner-private.pem; NEVER upload it")
    parser.add_argument("--output", required=True, help="New signed JSON output in private directory")
    args = parser.parse_args(argv)
    grant = validate_grant(_load_manifest(args.grant))
    print("REA owner authorization (ONE project/task, no terminal code to memorize)")
    print("Project:", grant["project"])
    print("Task:", grant["task_id"])
    print("Artifact root:", grant["artifact_root"])
    print("Expires:", grant["expires_at"])
    print("Tool count:", len(grant["allowed_tools"]))
    print("Permitted effects:", ", ".join(grant["permitted_effects"]))
    try:
        answer = input("Autorizar este trabalho? [sim/nao]: ").strip().casefold()
    except EOFError as exc:
        raise ApprovalError("Owner response required") from exc
    if answer not in ("sim", "s"):
        print("RECUSADO; no grant was signed.")
        return 1
    result = sign_task(grant, args.private_key, approved=True)
    _save_new_private(args.output, result)
    print("Grant de trabalho assinado com a chave existente. Guardado apenas no destino privado.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ApprovalError, ValueError, OSError) as exc:
        print("REA_OWNER_TASK_GRANT=FAIL " + type(exc).__name__, file=sys.stderr)
        sys.exit(2)

