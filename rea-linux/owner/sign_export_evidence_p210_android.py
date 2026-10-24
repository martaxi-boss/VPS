#!/usr/bin/env python3
"""Autorizacao offline para certificacao P210 do REA original.

So prepara duas assinaturas Ed25519 de uso unico no Android Termux.
NUNCA cria chaves, nem contacta GitHub/VPS/MCP, nem executa operacoes REA.
A chave privada permanece exclusivamente no Android.
O destino e uma copia de preservacao das evidencias no diretorio do motor;
nao e um novo servidor, plugin, MCP ou motor.
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

OWNER_FINGERPRINT_SHA256_DER = "99580a4806703661ca38f75a3cb95e47d46e32228cf89d5aa7ab55e95a4e25b4"
ACK = "AUTORIZO_OPERACAO_SENSIVEL"
ROOT = "/opt/rea-reversa/rea"


def canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def signer_files():
    directory = Path.home() / ".rea-owner"
    private = directory / "rea-owner-private.pem"
    public = directory / "rea-owner-public.pem"
    for path in (directory, private, public):
        if path.is_symlink() or not path.exists():
            raise RuntimeError("Chave de proprietario ausente ou link inseguro")
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise RuntimeError("Diretorio .rea-owner deve ser 0700")
    for key in (private, public):
        if not key.is_file() or stat.S_IMODE(key.stat().st_mode) & 0o077:
            raise RuntimeError("Permissoes inseguras para chave PEM")
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    if hashlib.sha256(der).hexdigest() != OWNER_FINGERPRINT_SHA256_DER:
        raise RuntimeError("A chave publica nao corresponde ao verificador da VPS")
    return directory, private, public


def sign_and_verify(private, public, directory, payload):
    with tempfile.TemporaryDirectory(prefix="rea-p210-sign-", dir=directory) as tmp:
        message = Path(tmp) / "payload.json"
        signature = Path(tmp) / "signature.bin"
        message.write_bytes(canonical(payload))
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private),
             "-in", str(message), "-out", str(signature)],
            check=True, capture_output=True,
        )
        verified = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
             "-inkey", str(public), "-in", str(message),
             "-sigfile", str(signature)],
            capture_output=True, check=False,
        )
        raw = signature.read_bytes()
        if verified.returncode != 0 or len(raw) != 64:
            raise RuntimeError("Assinatura Ed25519 falhou a verificacao local")
        return base64.b64encode(raw).decode("ascii")


def controlled_operations(nonce):
    # Cada pedido escolhe um nome de destino unico e nunca autoriza overwrite.
    path = ROOT + "/rea-p210-evidence-backup-" + nonce + ".json"
    arguments = {"path": path, "overwrite": False}
    return (
        (
            "export_evidence_bundle", arguments,
            "Criar copia canonica das seis evidencias historicas do MCP REA no ficheiro novo, sem sobrescrever nem fechar sessao.",
            "Owner explicitly authorizes one Evidence bundle backup to the unique new path under the existing REA engine directory, with overwrite=false. No session close and no code changes.",
        ),
        (
            "export_evidence_bundle", arguments,
            "Repetir exportacao exatamente ao mesmo destino protegido. Deve rejeitar ficheiro existente com isError=true, sem alterar a copia ou as evidencias.",
            "Owner explicitly authorizes the duplicate-destination negative test against the identical already-created backup, with overwrite=false. The existing data must not be replaced.",
        ),
    )


def main():
    os.umask(0o077)
    directory, private, public = signer_files()
    nonce = secrets.token_hex(16)
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
    steps = []
    for index, (tool, args, notice, reason) in enumerate(controlled_operations(nonce)):
        print("\nOPERACAO", index + 1, "de 2:", tool)
        print(notice)
        print("ARGUMENTOS EXATOS:", canonical(args).decode("ascii"))
        print("EXPIRA UTC:", expiry)
        if input("Se autorizares ESTA operacao escreve " + ACK + ": ").strip() != ACK:
            raise RuntimeError("Autorizacao recusada; nenhum pedido completo e produzido")
        args_digest = hashlib.sha256(canonical(args)).hexdigest()
        authorization = {
            "tool": tool, "arguments_sha256": args_digest, "scope": "sensitive",
            "reason": reason, "confirmed_by_owner": True,
            "acknowledgement": ACK,
        }
        payload = {
            "purpose": "REA_OWNER_APPROVAL_V1", "nonce": nonce,
            "expires_at": expiry, "step_index": index,
            "tool": tool, "arguments_sha256": args_digest,
            "scope": "sensitive", "reason": reason, "acknowledgement": ACK,
        }
        authorization["owner_signature"] = sign_and_verify(
            private, public, directory, payload
        )
        steps.append({"tool": tool, "arguments": args,
                      "authorization": authorization})
    request = {"protocol": 1, "nonce": nonce, "expires_at": expiry,
               "steps": steps}
    print("\nREA_OWNER_EXPORT_P210_SIGNED=PASS")
    print("BEGIN_REA_SIGNED_REQUEST_JSON")
    print(canonical(request).decode("ascii"))
    print("END_REA_SIGNED_REQUEST_JSON")
    print("APENAS esta copia e o teste de nao-sobrescrita estao autorizados.")
    print("Nao enviar chaves PEM. Envia apenas o JSON assinado no prazo.")
    print("Nenhuma ferramenta MCP foi executada neste Android.")


if __name__ == "__main__":
    main()
