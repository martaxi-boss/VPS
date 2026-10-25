#!/usr/bin/env python3
"""OFFLINE owner approval for risky REA actions (no SSH, plugin or MCP).

Never upload the owner private key. The verifier public key must be provisioned
through a separately approved owner-controlled step on the existing VPS. A
self-declared confirmed_by_owner field in a GitHub request is NOT an approval.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def write_exclusive(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def generate_owner_keypair(directory):
    """Explicit opt-in only. Creates no key on the REA VPS."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_path = Path(directory) / "rea-owner-private.pem"
    public_path = Path(directory) / "rea-owner-public.pem"
    # Never overwrite an existing signer, including after partial failure.
    if private_path.exists() or public_path.exists():
        raise ValueError("Owner approval keys already exist; refusing overwrite")
    write_exclusive(private_path, private)
    write_exclusive(public_path, public)
    return {"private_key": str(private_path),
            "public_key": str(public_path),
            "notice": "Keep private_key OFF GitHub, ChatGPT and the VPS."}


def sign_sensitive_step(body, index, private_pem):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if not isinstance(body, dict) or body.get("protocol") != 1:
        raise ValueError("Invalid protocol")
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(body["steps"]):
        raise ValueError("Invalid step index")
    if not isinstance(body.get("nonce"), str) or len(body["nonce"]) != 32:
        raise ValueError("Missing unique request nonce")
    if not isinstance(body.get("expires_at"), str):
        raise ValueError("Missing request expiry")
    step = body["steps"][index]
    auth = step.get("authorization")
    if not isinstance(auth, dict) or auth.get("scope") != "sensitive":
        raise ValueError("This command signs only explicitly sensitive operations")
    if not isinstance(step.get("arguments"), dict):
        raise ValueError("Invalid step arguments")
    if auth.get("tool") != step.get("tool") or (
        auth.get("arguments_sha256") != hashlib.sha256(canonical(step["arguments"])).hexdigest()
    ) or auth.get("acknowledgement") != "AUTORIZO_OPERACAO_SENSIVEL":
        raise ValueError("Authorization does not bind tool/arguments/sensitive scope")
    if auth.get("confirmed_by_owner") is not True:
        raise ValueError("Missing explicit owner confirmation")
    if not isinstance(auth.get("reason"), str) or not 12 <= len(auth["reason"].strip()) <= 400:
        raise ValueError("A specific approval reason is required")
    key = serialization.load_pem_private_key(Path(private_pem).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Owner signer key must be Ed25519")
    payload = {
        "purpose": "REA_OWNER_APPROVAL_V1",
        "nonce": body["nonce"], "expires_at": body["expires_at"],
        "step_index": index, "tool": step["tool"],
        "arguments_sha256": hashlib.sha256(canonical(step["arguments"])).hexdigest(),
        "scope": "sensitive",
        "reason": auth["reason"],
        "acknowledgement": auth["acknowledgement"],
    }
    auth["owner_signature"] = base64.b64encode(key.sign(canonical(payload))).decode("ascii")
    return body



# P269: One offline review/confirmation can sign many *distinct*, exact
# one-use requests, but cannot grant a blanket signature or override MCP policy.
# The original verifier still checks each Ed25519 signature independently.
_BATCH_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,90}\.json$")
_BATCH_SHA = re.compile(r"^[0-9a-f]{64}$")
_BATCH_NONCE = re.compile(r"^[0-9a-f]{32}$")
_BATCH_TOOL = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,119}$")


def _load_p269_request(manifest_dir, entry, now):
    """Validate a complete fixed, unsigned request before any owner-key read."""
    if not isinstance(entry, dict) or set(entry) != {"file", "unsigned_sha256"}:
        raise ValueError("Manifest entries require file and unsigned_sha256")
    name = entry["file"]
    if not isinstance(name, str) or not _BATCH_NAME.fullmatch(name):
        raise ValueError("Request must be one relative JSON basename, without traversal")
    if not isinstance(entry["unsigned_sha256"], str) or not _BATCH_SHA.fullmatch(entry["unsigned_sha256"]):
        raise ValueError("Missing exact unsigned request SHA-256")
    path = manifest_dir / name
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 512000:
        raise ValueError("Unsigned request missing, symlinked or oversized")
    body = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(body, dict) or set(body) != {"protocol", "nonce", "expires_at", "steps"}:
        raise ValueError("Invalid original REA request fields")
    if hashlib.sha256(canonical(body)).hexdigest() != entry["unsigned_sha256"]:
        raise ValueError("Unsigned request does not match manifest SHA-256")
    if body["protocol"] != 1 or not isinstance(body["nonce"], str) or not _BATCH_NONCE.fullmatch(body["nonce"]):
        raise ValueError("Invalid original protocol/nonce")
    expiry_raw = body["expires_at"]
    if not isinstance(expiry_raw, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", expiry_raw):
        raise ValueError("Invalid expiry format")
    expiry = datetime.strptime(expiry_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if not 0 < (expiry - now).total_seconds() <= 86400:
        raise ValueError("Expired or over-24h batch request")
    steps = body["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 12:
        raise ValueError("Original MCP allows 1 to 12 steps per request")
    sensitive = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) not in (
            {"tool", "arguments"}, {"tool", "arguments", "authorization"}
        ):
            raise ValueError("Invalid exact MCP step fields")
        tool, args = step["tool"], step["arguments"]
        if not isinstance(tool, str) or not _BATCH_TOOL.fullmatch(tool):
            raise ValueError("Invalid MCP tool name")
        if not isinstance(args, dict) or len(canonical(args)) > 400000:
            raise ValueError("Invalid MCP arguments")
        auth = step.get("authorization")
        if auth is None:
            continue  # Server rejects any incorrectly unsigned workspace/sensitive step.
        if not isinstance(auth, dict):
            raise ValueError("Invalid per-step authorization")
        scope = auth.get("scope")
        expected_keys = {
            "tool", "arguments_sha256", "scope", "reason",
            "confirmed_by_owner", "acknowledgement"
        }
        if scope == "sensitive":
            if set(auth) != expected_keys or not isinstance(auth.get("reason"), str):
                raise ValueError("Sensitive step must be unsigned pending owner review")
        elif scope == "workspace":
            if set(auth) != expected_keys or not isinstance(auth.get("reason"), str):
                raise ValueError("Workspace approval has unexpected fields")
        else:
            raise ValueError("Unknown risk class; no blanket authorization")
        if (auth["tool"] != tool or
                auth["arguments_sha256"] != hashlib.sha256(canonical(args)).hexdigest() or
                auth["confirmed_by_owner"] is not True or
                not 12 <= len(auth["reason"].strip()) <= 400 or
                auth["acknowledgement"] != (
                    "AUTORIZO_OPERACAO_SENSIVEL" if scope == "sensitive"
                    else "AUTORIZO_ANALISE_LOCAL")):
            raise ValueError("Per-operation authorization mismatch")
        if scope == "sensitive":
            sensitive.append((index, step))
    return body, sensitive


def sign_batch_requests(manifest_path, private_pem, output_dir, confirm_callback=input, now=None):
    """Offline batch approval: one visible review, one prompt, N independent signatures.

    No network, SSH, GitHub, VPS, daemon or change to installed REA. An approved
    batch is immutable, nonce-bound, expires within 24 h and is executed later
    only under the existing original MCP server verifier.
    """
    now = now or datetime.now(timezone.utc)
    manifest_path = Path(manifest_path)
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 80000:
        raise ValueError("Batch manifest absent, symlinked or oversized")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"protocol", "requests"} or manifest["protocol"] != "REA_OWNER_BATCH_V1":
        raise ValueError("Invalid explicit batch manifest")
    requests = manifest["requests"]
    if not isinstance(requests, list) or not 1 <= len(requests) <= 16:
        raise ValueError("Batch manifest must contain 1 to 16 exact requests")
    parsed, names, nonces, previews = [], set(), set(), []
    sensitive_total = 0
    manifest_dir = manifest_path.parent.resolve()
    for entry in requests:
        body, sensitive = _load_p269_request(manifest_dir, entry, now)
        name = entry["file"]
        if name in names or body["nonce"] in nonces:
            raise ValueError("Duplicate source filename/one-use nonce")
        names.add(name)
        nonces.add(body["nonce"])
        parsed.append((name, body, sensitive))
        sensitive_total += len(sensitive)
        # Review *every* step, including workspace approvals and reads.
        # A batch cannot hide a side-effecting workspace call behind one
        # visible sensitive signature.
        for index, step in enumerate(body["steps"]):
            args_json = canonical(step["arguments"]).decode("utf-8")
            if len(args_json) > 4096:
                raise ValueError("Bulk review refuses to hide large arguments")
            auth = step.get("authorization")
            scope = auth["scope"] if auth is not None else "read_claim_server_checks"
            digest = hashlib.sha256(canonical(step["arguments"])).hexdigest()
            reason = auth["reason"] if auth is not None else "Read-only step; original MCP validates risk"
            previews.append((
                name, index, step["tool"], scope, args_json, digest, reason
            ))
    if not 1 <= sensitive_total <= 83:
        raise ValueError("No sensitive steps to approve or excessive signature count")
    output_dir = Path(output_dir).resolve()
    if not output_dir.is_dir():
        raise ValueError("Output folder must exist; no hidden directory creation")
    outputs = [output_dir / ("signed-" + name) for name, _, _ in parsed]
    if len(set(outputs)) != len(outputs) or any(path.exists() or path.is_symlink() for path in outputs):
        raise ValueError("One or more signed output files already exist; never overwrite")
    if any(path.resolve() == manifest_path.resolve() for path in outputs):
        raise ValueError("Refusing to overwrite manifest")
    plan_hash = hashlib.sha256(canonical(manifest)).hexdigest()
    print("REA_OWNER_BATCH_V1: review ALL steps below, including workspace and read calls.")
    print("No automatic execution. The same private key remains on this device.")
    print("Batch SHA-256:", plan_hash)
    print("Requests:", len(parsed), "total steps:", len(previews),
          "sensitive signatures:", sensitive_total)
    for name, index, tool, scope, args, digest, reason in previews:
        print("REQUEST:", name, "STEP:", index, "TOOL:", tool, "SCOPE:", scope)
        print("ARGUMENTS:", args)
        print("ARGUMENTS_SHA256:", digest)
        print("PURPOSE:", reason)
    acknowledgement = "AUTORIZO_LOTE_" + str(sensitive_total) + "_" + plan_hash[:12]
    if confirm_callback("Type " + acknowledgement + " to sign only these displayed operations: ").strip() != acknowledgement:
        raise ValueError("Owner declined batch; no files signed")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key_path = Path(private_pem)
    if key_path.is_symlink() or not key_path.is_file() or key_path.stat().st_mode & 0o077:
        raise ValueError("Owner private key missing, symlinked or accessible to other users")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected existing Ed25519 owner key")
    prepared = []
    for name, body, sensitive in parsed:
        for index, step in sensitive:
            auth = step["authorization"]
            payload = {
                "purpose": "REA_OWNER_APPROVAL_V1",
                "nonce": body["nonce"],
                "expires_at": body["expires_at"],
                "step_index": index,
                "tool": step["tool"],
                "arguments_sha256": auth["arguments_sha256"],
                "scope": "sensitive",
                "reason": auth["reason"],
                "acknowledgement": auth["acknowledgement"]
            }
            auth["owner_signature"] = base64.b64encode(key.sign(canonical(payload))).decode("ascii")
        prepared.append(canonical(body) + b"\n")
    created = []
    try:
        for out, payload in zip(outputs, prepared):
            write_exclusive(out, payload)
            created.append(out)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return {
        "status": "SIGNED_EXACT_BATCH_OFFLINE",
        "approved_manifest_sha256": plan_hash,
        "signed_requests": len(outputs),
        "individually_signed_sensitive_steps": sensitive_total,
        "output_files": [str(p) for p in outputs],
        "private_key_exported": False
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    generate = actions.add_parser("owner-keygen")
    generate.add_argument("--dir", required=True)
    sign = actions.add_parser("sign-step")
    sign.add_argument("--request", required=True)
    sign.add_argument("--step-index", type=int, required=True)
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--output", required=True)
    sign.add_argument("--approve-sensitive", action="store_true")
    batch = actions.add_parser("sign-batches", help="Sign fixed reviewed REA requests offline with one confirmation")
    batch.add_argument("--manifest", required=True)
    batch.add_argument("--private-key", required=True)
    batch.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    if args.action == "owner-keygen":
        print(json.dumps(generate_owner_keypair(Path(args.dir))))
    elif args.action == "sign-step":
        if not args.approve_sensitive:
            raise ValueError("Explicit --approve-sensitive flag is required")
        body = json.loads(Path(args.request).read_text(encoding="utf-8"))
        signed = sign_sensitive_step(body, args.step_index, args.private_key)
        write_exclusive(Path(args.output), canonical(signed) + b"\n")
        print(json.dumps({"status": "signed_single_sensitive_operation",
                          "step_index": args.step_index,
                          "private_key_stays_local": True,
                          "output_path": args.output}))
    elif args.action == "sign-batches":
        print(json.dumps(sign_batch_requests(
            args.manifest, args.private_key, args.output_dir
        ), ensure_ascii=True))


if __name__ == "__main__":
    main()
