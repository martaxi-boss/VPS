"""Experimental owner-signed, scoped REA task grant. NOT enabled in the live bridge.

The owner signs one explicit bounded permission document on their trusted device.
The VPS only holds/uses the already-enrolled Ed25519 public verifier. A grant
never signs on behalf of the owner and never permits destructive tool effects.
"""
import base64
import binascii
from datetime import datetime, timezone
import json
import re

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


def verify_task_grant(grant, owner_signature_b64, owner_public_pem, *,
                      project, task_id, origin, artifact_root,
                      tool, audited_effects, current_risk, now=None):
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
    return True

