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


if __name__ == "__main__":
    main()
