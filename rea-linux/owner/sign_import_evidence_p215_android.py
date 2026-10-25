#!/usr/bin/env python3
"""Autorizacao offline para ensaio P215 import_evidence_bundle no REA original.

Prepara duas assinaturas Ed25519 independentes no Android Termux.
NUNCA cria chaves, nem contacta GitHub/VPS/MCP, nem executa operacoes REA.
A chave privada permanece exclusivamente no Android.
O alvo e a copia P214 na pasta persistente do servico REA (systemd StateDirectory);
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
ROOT = "/var/lib/rea-reversa"


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
    with tempfile.TemporaryDirectory(prefix="rea-p214-sign-", dir=directory) as tmp:
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
    """Exactly one idempotent merge of the retained P214 archive and one missing-path refusal.

    No new evidence or changes are expected from the first import because the
    source is the six-record backup of the unchanged permanent MCP state.
    Still, import_evidence_bundle is STATE-MUTATING in principle and requires
    independent per-operation Ed25519 owner approvals.
    """
    preserved = (ROOT + "/rea-p214-evidence-backup-"
                 + "7c5e1ad42fe74b121f3e2c4fe830c6c7.json")
    missing = ROOT + "/rea-p215-missing-" + nonce + ".json"
    return (
        (
            "import_evidence_bundle", {"path": preserved},
            "Importar uma vez a copia P214 original no proprio REA. Espera-se importacao idempotente (0 registos novos, 6 totais), sem limpar ou fechar sessao. Esta operacao PODE modificar metadados se o arquivo diferir; autoriza apenas se aceitares este efeito.",
            "Owner authorizes one import_evidence_bundle of the previously verified P214 six-record backup from the existing REA service StateDirectory. Expected idempotent merge of zero new records/unknowns. Do not close any session, change other service paths or import any third-party data.",
        ),
        (
            "import_evidence_bundle", {"path": missing},
            "Verificar recusas ao pedir importacao de ficheiro comprovadamente inexistente na mesma pasta. Espera-se MCP isError=true; nao criar nem apagar arquivos.",
            "Owner authorizes one negative import_evidence_bundle of a fresh nonce-named nonexistent StateDirectory path, expecting MCP isError=true and no state changes. No directory edits and no other files or targets.",
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
    encoded = canonical(request) + b"\n"
    private_out = Path.home() / ("rea-p215-pedido-" + nonce + ".json")
    fd = os.open(private_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
    print("FICHEIRO_TERMUX=", str(private_out))
    external = Path("/sdcard/Download")
    if external.is_dir() and os.access(external, os.W_OK):
        shared_out = external / private_out.name
        try:
            fd = os.open(shared_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
            print("FICHEIRO_DOWNLOADS=", str(shared_out))
        except OSError:
            print("FICHEIRO_DOWNLOADS=UNAVAILABLE")
    else:
        print("FICHEIRO_DOWNLOADS=UNAVAILABLE")
    print("\nREA_OWNER_IMPORT_P215_SIGNED=PASS")
    print("BEGIN_REA_SIGNED_REQUEST_JSON")
    print(canonical(request).decode("ascii"))
    print("END_REA_SIGNED_REQUEST_JSON")
    print("APENAS importacao idempotente da copia P214 e leitura negativa de ficheiro ausente estao autorizadas.")
    print("Nao enviar chaves PEM. Envia apenas o JSON assinado no prazo.")
    print("Nenhuma ferramenta MCP foi executada neste Android.")


if __name__ == "__main__":
    main()
