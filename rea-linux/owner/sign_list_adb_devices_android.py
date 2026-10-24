#!/usr/bin/env python3
"""Sign exactly one REA list_adb_devices call on the owner's Android.

No internet, GitHub, SSH, ADB execution, or key export. The authorized remote operation may start the VPS-local ADB server. The private
Ed25519 PEM stays in Termux. The output is a one-hour, single-use,
owner-signed REA protocol request, not a reusable blanket authorization.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import tempfile

EXPECTED_OWNER_PUBKEY_SHA256_DER = (
    "99580a4806703661ca38f75a3cb95e47d46e32228cf89d5aa7ab55e95a4e25b4"
)
APPROVAL = "AUTORIZO_OPERACAO_SENSIVEL"
TOOL = "list_adb_devices"
ARGUMENTS = {}
REASON = "Owner-controlled REA test of ADB device enumeration on the VPS. The call may start the local ADB server but does not control connected devices."


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def local_key_files():
    directory = Path.home() / ".rea-owner"
    private = directory / "rea-owner-private.pem"
    public = directory / "rea-owner-public.pem"
    for path in (directory, private, public):
        if path.is_symlink() or not path.exists():
            raise RuntimeError("Owner key directory or PEM missing, or unsafe symlink")
    for key in (private, public):
        info = key.stat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError("Owner PEM file must not be accessible by other users")
    result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"],
        capture_output=True, check=True)
    digest = hashlib.sha256(result.stdout).hexdigest()
    if digest != EXPECTED_OWNER_PUBKEY_SHA256_DER:
        raise RuntimeError("Owner public fingerprint does not match the enrolled VPS key")
    return directory, private, public


def main():
    os.umask(0o077)
    directory, private, public = local_key_files()
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=45)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_hex(16)
    auth = {
        "tool": TOOL,
        "arguments_sha256": hashlib.sha256(canonical(ARGUMENTS)).hexdigest(),
        "scope": "sensitive",
        "reason": REASON,
        "confirmed_by_owner": True,
        "acknowledgement": APPROVAL,
    }
    payload = {
        "purpose": "REA_OWNER_APPROVAL_V1",
        "nonce": nonce,
        "expires_at": expiry,
        "step_index": 0,
        "tool": TOOL,
        "arguments_sha256": auth["arguments_sha256"],
        "scope": auth["scope"],
        "reason": auth["reason"],
        "acknowledgement": auth["acknowledgement"],
    }
    print("Operacao: list_adb_devices; argumentos: {}")
    print("Enumera dispositivos ADB; pode iniciar o servidor ADB local na VPS, sem os controlar.")
    print("Autorizacao individual expira em 45 minutos: " + expiry)
    answer = input("Para assinar escreve AUTORIZO_OPERACAO_SENSIVEL: ").strip()
    if answer != APPROVAL:
        raise RuntimeError("Authorization not granted; nothing signed")
    with tempfile.TemporaryDirectory(prefix="rea-owner-sign-", dir=directory) as td:
        msg = Path(td) / "approval.json"
        sig = Path(td) / "approval.sig"
        msg.write_bytes(canonical(payload))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin",
                        "-inkey", str(private), "-in", str(msg),
                        "-out", str(sig)], check=True, capture_output=True)
        check = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin",
                                "-pubin", "-inkey", str(public),
                                "-in", str(msg), "-sigfile", str(sig)],
                               check=False, capture_output=True)
        if check.returncode != 0:
            raise RuntimeError("Signature did not verify; request not emitted")
        raw_signature = sig.read_bytes()
        if len(raw_signature) != 64:
            raise RuntimeError("Invalid Ed25519 signature length")
    auth["owner_signature"] = base64.b64encode(raw_signature).decode("ascii")
    body = {
        "protocol": 1,
        "nonce": nonce,
        "expires_at": expiry,
        "steps": [{"tool": TOOL, "arguments": ARGUMENTS, "authorization": auth}],
    }
    print("REA_OWNER_SIGNED_EXACT_ADB_DEVICES=PASS")
    print("BEGIN_REA_SIGNED_REQUEST_JSON")
    print(canonical(body).decode("ascii"))
    print("END_REA_SIGNED_REQUEST_JSON")
    print("Copiar apenas a linha JSON entre os marcadores; NUNCA a chave privada.")


if __name__ == "__main__":
    main()
