#!/usr/bin/env python3
"""Owner-only offline Ed25519 signer for exact Frida local process and invalid-device tests.

Private signer key remains on Android Termux. No GitHub, SSH, ADB, Frida,
or Cutter operations are performed by this script; those run on the VPS only
if the owner sends the exact signed request to the trusted bridge.
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

EXPECTED_PUBKEY_SHA256_DER = "99580a4806703661ca38f75a3cb95e47d46e32228cf89d5aa7ab55e95a4e25b4"
ACK = "AUTORIZO_OPERACAO_SENSIVEL"
OPERATIONS = (
    (
        "list_frida_processes", {"device_id": "local"},
        "Owner-approved discovery of process metadata (names and PIDs) on the VPS local Frida device only. No remote connection, injection or process attachment.",
        "Ler nomes e PIDs dos processos locais da VPS pelo Frida; nao instrumenta processos nem usa servidores remotos.",
    ),
    (
        "list_frida_processes", {"device_id": "rea-p205-nonexistent-device"},
        "Owner-approved negative error test on an explicitly nonexistent Frida device identifier. The source-owned test makes no remote connection and must not attach to any process.",
        "Teste negativo: pedir processos de um identificador Frida inexistente; espera-se rejeicao sem tocar em dispositivos ou processos.",
    ),
)


def canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def signer_files():
    directory = Path.home() / ".rea-owner"
    private = directory / "rea-owner-private.pem"
    public = directory / "rea-owner-public.pem"
    for path in (directory, private, public):
        if path.is_symlink() or not path.exists():
            raise RuntimeError("Owner key missing or unsafe symlink")
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise RuntimeError("Owner key directory is not mode 0700")
    for key in (private, public):
        if not key.is_file() or stat.S_IMODE(key.stat().st_mode) & 0o077:
            raise RuntimeError("Owner key file permissions unsafe")
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"],
        check=True, capture_output=True).stdout
    if hashlib.sha256(der).hexdigest() != EXPECTED_PUBKEY_SHA256_DER:
        raise RuntimeError("Owner public key does not match enrolled VPS key")
    return directory, private, public


def sign_and_verify(private, public, directory, payload):
    with tempfile.TemporaryDirectory(prefix="rea-discovery-sign-", dir=directory) as tmp:
        message = Path(tmp) / "payload.json"
        signature = Path(tmp) / "signature.bin"
        message.write_bytes(canonical(payload))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin",
                        "-inkey", str(private), "-in", str(message),
                        "-out", str(signature)], check=True, capture_output=True)
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin",
                                 "-pubin", "-inkey", str(public),
                                 "-in", str(message), "-sigfile", str(signature)],
                                check=False, capture_output=True)
        raw = signature.read_bytes()
        if result.returncode != 0 or len(raw) != 64:
            raise RuntimeError("Owner Ed25519 signature verification failed")
        return base64.b64encode(raw).decode("ascii")


def main():
    os.umask(0o077)
    directory, private, public = signer_files()
    nonce = secrets.token_hex(16)
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
    steps = []
    for index, (name, args, reason, notice) in enumerate(OPERATIONS):
        print("\nOPERACAO", index + 1, "de", len(OPERATIONS), ":", name)
        print(notice)
        print("Argumentos exatos:", canonical(args).decode("ascii"), ". Expira em UTC:", expiry)
        confirmation = input("Para autorizar ESTA operacao escreve " + ACK + ": ").strip()
        if confirmation != ACK:
            raise RuntimeError("Autorizacao recusada; nao foi produzido pedido completo")
        hashed_args = hashlib.sha256(canonical(args)).hexdigest()
        authorization = {
            "tool": name, "arguments_sha256": hashed_args,
            "scope": "sensitive", "reason": reason,
            "confirmed_by_owner": True, "acknowledgement": ACK,
        }
        message = {
            "purpose": "REA_OWNER_APPROVAL_V1", "nonce": nonce,
            "expires_at": expiry, "step_index": index,
            "tool": name, "arguments_sha256": hashed_args,
            "scope": "sensitive", "reason": reason,
            "acknowledgement": ACK,
        }
        authorization["owner_signature"] = sign_and_verify(private, public, directory, message)
        steps.append({"tool": name, "arguments": args, "authorization": authorization})
    request = {"protocol": 1, "nonce": nonce, "expires_at": expiry, "steps": steps}
    print("\nREA_OWNER_FRIDA_PROCESS_TESTS_SIGNED=PASS")
    print("BEGIN_REA_SIGNED_REQUEST_JSON")
    print(canonical(request).decode("ascii"))
    print("END_REA_SIGNED_REQUEST_JSON")
    print("\nRESUMO_CURTO_PARA_CAPTURA")
    print("NONCE=" + nonce)
    print("EXPIRY=" + expiry)
    for index, step in enumerate(steps):
        sig = step["authorization"]["owner_signature"]
        for part in range(0, len(sig), 24):
            print("SIG" + str(index) + "_" + str(part // 24 + 1) + "=" + sig[part:part+24])
    print("Nunca enviar as chaves privadas PEM. Estas assinaturas aprovam apenas as duas operacoes acima.")

if __name__ == "__main__":
    main()
