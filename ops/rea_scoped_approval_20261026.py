"""Experimental owner-signed, scoped REA task grant. NOT enabled in the live bridge.

The owner signs one explicit bounded permission document on their trusted device.
The VPS only holds/uses the already-enrolled Ed25519 public verifier. A grant
never signs on behalf of the owner and never permits destructive tool effects.
"""
import base64
import binascii
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PURPOSE = "REA_OWNER_SCOPED_TASK_V1"
ORIGIN = "martaxi-boss/VPS:rea/one-skill-bridge-20261023"
MAX_SECONDS = 7 * 24 * 3600
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,119}$")
HEX = re.compile(r"^[0-9a-f]{32}$")
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ALLOWED_EFFECTS = frozenset({"mutatesSession", "writesFilesystem", "launchesProcess"})
FORBIDDEN_EFFECTS = frozenset({
    "mutatesTarget", "mayDiscardData", "changesUiState", "executesForeignCode",
    "mutatesDevice", "accessesNetwork",
})
# These have a special data-retention / service-safety contract, regardless
# of their coarse ToolEffects annotations. No standing-grant admission.
NEVER_STANDING_TOOLS = frozenset({
    "close_binary", "import_evidence_bundle", "export_evidence_bundle",
    "record_unknown", "update_unknown", "install_adb_package",
    "uninstall_adb_package", "push_adb_file", "start_frida_session",
    "load_frida_script", "execute_rizin_command", "gdb_console",
    "cutter_command", "rizin_debug_command",
})
# Standing task grants may only touch a dedicated, project-specific job folder.
# Broader paths remain behind the original per-operation authorization.
JOBS_BASE = Path("/opt/rea-reversa/rea/.rea-private/jobs")
PATH_ARG_KEYS = frozenset({
    "path", "file", "filename", "input_path", "output_path", "target_path",
    "source_path", "destination_path", "artifact_path", "binary_path",
    "directory", "root", "out_dir", "output_dir", "archive", "bundle",
})
# A grant is not a general-purpose command interpreter, browser or device token.
BLOCKED_ARGUMENT_KEYS = frozenset({
    "command", "shell", "script", "javascript", "code", "exec", "expression",
    "device", "device_id", "host", "hostname", "endpoint", "url", "uri",
    "target_url", "source_url", "remote_url", "process_id", "pid",
})
FIELDS = frozenset({
    "purpose", "grant_id", "project", "task_id", "origin", "not_before",
    "expires_at", "allowed_tools", "permitted_effects", "artifact_root",
})


class ScopedApprovalError(ValueError):
    """The grant is missing, forged, expired or outside the signed scope."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _time(value):
    if not isinstance(value, str) or not TIME.fullmatch(value):
        raise ScopedApprovalError("Invalid UTC grant timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError as exc:
        raise ScopedApprovalError("Invalid UTC grant timestamp") from exc


def _validate_job_paths(artifact_root, arguments):
    """Deny cross-project targets, path traversal and unbound sessions.

    The signed root must be a dedicated child of the preapproved jobs tree.
    The request must name at least one target inside that signed root; session
    calls without a path need additional future session binding and are denied.
    """
    if not isinstance(arguments, dict):
        raise ScopedApprovalError("Invalid arguments for scoped execution")
    root = Path(artifact_root)
    if (not root.is_absolute() or str(root) != str(root.resolve()) or
            root == JOBS_BASE or JOBS_BASE not in root.parents):
        raise ScopedApprovalError("Signed job root is not a confined job folder")
    count = 0

    def walk(obj):
        nonlocal count
        if isinstance(obj, dict):
            for key, value in obj.items():
                if not isinstance(key, str):
                    raise ScopedApprovalError("Invalid scoped argument key")
                if (key.lower() in BLOCKED_ARGUMENT_KEYS or
                        key.lower().endswith(("_url", "_uri", "_command", "_script"))):
                    raise ScopedApprovalError("External or command argument forbidden by grant")
                is_path = key in PATH_ARG_KEYS or key.endswith(("_path", "_file", "_dir"))
                is_paths = key.endswith(("_paths", "_files", "_dirs"))
                if is_path:
                    if not isinstance(value, str) or not value.startswith("/"):
                        raise ScopedApprovalError("Scoped target must be an absolute path")
                    target = Path(value).resolve()
                    if target != root and root not in target.parents:
                        raise ScopedApprovalError("Target outside signed task folder")
                    count += 1
                elif is_paths:
                    if not isinstance(value, list):
                        raise ScopedApprovalError("Invalid scoped paths collection")
                    for item in value:
                        walk({"path": item})
                else:
                    walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)
        elif isinstance(obj, str):
            # Even unrecognised string fields cannot hide an outside absolute
            # pathname or a remote/file URL alongside a valid job-root path.
            if "://" in obj or obj.startswith("/"):
                if "://" in obj:
                    raise ScopedApprovalError("URI not allowed in standing task")
                target = Path(obj).resolve()
                if target != root and root not in target.parents:
                    raise ScopedApprovalError("Hidden path outside signed task folder")

    walk(arguments)
    if count == 0:
        raise ScopedApprovalError("Scoped execution requires a bound job artifact")



def verify_not_revoked(grant_id, revocation_dir):
    """Fail closed for an explicitly revoked grant ID in owner's private store.

    Reading an absent directory is compatible with existing installations.
    Removing/replacing revocation markers is never performed by this verifier.
    """
    if not isinstance(grant_id, str) or not HEX.fullmatch(grant_id):
        raise ScopedApprovalError("Invalid grant identifier")
    directory = Path(revocation_dir)
    if directory.is_symlink():
        raise ScopedApprovalError("Untrusted revocation directory")
    if not directory.exists():
        return True
    info = directory.stat()
    if (not directory.is_dir() or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise ScopedApprovalError("Unsafe revocation directory")
    marker = directory / (grant_id + ".revoked")
    if marker.is_symlink():
        raise ScopedApprovalError("Unsafe revocation marker")
    if marker.exists():
        info = marker.stat()
        if (not marker.is_file() or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise ScopedApprovalError("Unsafe revocation marker")
        raise ScopedApprovalError("Owner has revoked this task grant")
    return True


def propose_task_tools(registry, audited_effects, schema_pins, *,
                       schema_digest, classify_tool):
    """Derive a conservative, reviewable tool list from the ACTUAL live MCP.

    This is a proposal for the owner to sign, NOT an authorization. The user
    describes the work; they do not need to name any tools. Schema drift,
    missing audits, unknown effects and dangerous operations fail closed.
    """
    if not isinstance(registry, dict):
        raise ScopedApprovalError("Missing live tool catalog")
    selection = []
    for name, descriptor in registry.items():
        if (not isinstance(name, str) or not NAME.fullmatch(name) or
                not isinstance(descriptor, dict) or name in NEVER_STANDING_TOOLS):
            continue
        flags = audited_effects.get(name)
        expected_hash = schema_pins.get(name)
        if (not isinstance(flags, frozenset) or
                not flags or not flags.issubset(ALLOWED_EFFECTS) or
                flags.intersection(FORBIDDEN_EFFECTS) or
                not isinstance(expected_hash, str) or len(expected_hash) != 64):
            continue
        try:
            if schema_digest(descriptor.get("inputSchema")) != expected_hash:
                continue
            hints = descriptor.get("annotations") or {}
            if not isinstance(hints, dict) or any(
                hints.get(key) is not expected for key, expected in {
                    "readOnlyHint": not bool(flags),
                    "destructiveHint": bool(flags.intersection({
                        "mayDiscardData", "executesForeignCode", "mutatesDevice"})),
                    "openWorldHint": bool(flags.intersection({
                        "launchesProcess", "accessesNetwork"})),
                }.items()
            ):
                continue
            risk = classify_tool(name, descriptor)
            if risk not in ("workspace", "sensitive"):
                continue
        except (ValueError, TypeError, KeyError):
            continue
        selection.append(name)
    return sorted(selection)


def verify_task_grant(grant, owner_signature_b64, owner_public_pem, *,
                      project, task_id, origin, artifact_root,
                      tool, audited_effects, current_risk, arguments, now=None,
                      revocation_dir=None):
    """Check one sensitive/workspace tool against an independently owner-signed grant.

    This helper DOES NOT change secure.validate_inner or authorize live calls.
    Integration must also preserve the original argument schemas, bounded paths,
    nonce/replay checks and per-step Ed25519 fallback for excluded operations.
    """
    if not isinstance(grant, dict) or set(grant) != FIELDS:
        raise ScopedApprovalError("Invalid standing grant schema")
    if grant["purpose"] != PURPOSE or grant["origin"] != ORIGIN:
        raise ScopedApprovalError("Wrong grant purpose or origin")
    if not isinstance(grant["grant_id"], str) or not HEX.fullmatch(grant["grant_id"]):
        raise ScopedApprovalError("Invalid grant ID")
    for k in ("project", "task_id", "artifact_root"):
        if not isinstance(grant[k], str) or not grant[k] or len(grant[k]) > 256:
            raise ScopedApprovalError("Invalid grant scope")
    if (grant["project"] != project or grant["task_id"] != task_id or
            grant["origin"] != origin or grant["artifact_root"] != artifact_root):
        raise ScopedApprovalError("Task, origin or artifact root outside signed scope")
    start, end = _time(grant["not_before"]), _time(grant["expires_at"])
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ScopedApprovalError("Naive current time")
    if not start <= now < end or not 0 < (end - start).total_seconds() <= MAX_SECONDS:
        raise ScopedApprovalError("Grant expired, not active or overly broad")
    names = grant["allowed_tools"]
    if (not isinstance(names, list) or not 1 <= len(names) <= 229 or
            any(not isinstance(n, str) or not NAME.fullmatch(n) for n in names) or
            sorted(set(names)) != names):
        raise ScopedApprovalError("Tool allowlist must be sorted and unique")
    effects = grant["permitted_effects"]
    if (not isinstance(effects, list) or
            sorted(set(effects)) != effects or
            any(not isinstance(e, str) or e not in ALLOWED_EFFECTS for e in effects)):
        raise ScopedApprovalError("Unsupported effect permissions")
    if not isinstance(owner_signature_b64, str) or len(owner_signature_b64) > 128:
        raise ScopedApprovalError("Invalid signature encoding")
    try:
        signature = base64.b64decode(owner_signature_b64, validate=True)
        public = serialization.load_pem_public_key(owner_public_pem)
        if not isinstance(public, Ed25519PublicKey) or len(signature) != 64:
            raise ValueError("Wrong signature or verifier type")
        public.verify(signature, canonical_bytes(grant))
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise ScopedApprovalError("Owner signature does not verify") from exc
    if (current_risk not in ("workspace", "sensitive") or
            tool not in names or tool in NEVER_STANDING_TOOLS):
        raise ScopedApprovalError("Operation not approved for autonomous execution")
    if (not isinstance(audited_effects, (set, frozenset)) or
            not audited_effects.issubset(ALLOWED_EFFECTS) or
            not audited_effects.issubset(set(effects)) or
            audited_effects.intersection(FORBIDDEN_EFFECTS)):
        raise ScopedApprovalError("Operation has unapproved or dangerous effects")
    _validate_job_paths(grant["artifact_root"], arguments)
    if revocation_dir is not None:
        verify_not_revoked(grant["grant_id"], revocation_dir)
    return True

