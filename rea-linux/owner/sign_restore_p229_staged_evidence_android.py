#!/usr/bin/env python3
"""Autorizacao offline P229 de restauracao em pasta previamente permitida pelo REA.

Prepara UMA assinatura Ed25519 especifica no Android Termux.
NUNCA cria chaves, nem contacta GitHub/VPS/MCP, nem executa operacoes REA.
A chave privada permanece exclusivamente no Android.
O alvo e a copia P214 REVERIFICADA na raiz de analise REA (6 Evidence; 0 Unknowns);
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
    with tempfile.TemporaryDirectory(prefix="rea-p229-sign-", dir=directory) as tmp:
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
    """One owner-authorized import from an exact staged P214 backup.

    Before signing, an owner-controlled administrator must stage the verified
    P214 archive at the exact path below. The original security policy then
    allows the path; this signer never changes any server policy.
    """
    staged = ROOT + "/.rea-p229-restore-p214-7c5e1ad42fe74b121f3e2c4fe830c6c7.json"
    return ((
        "import_evidence_bundle",
        {"path": staged},
        "P229: Autorizar uma unica importacao sensivel da COPIA TEMPORARIA P214, "
        "na pasta aprovada do motor REA. Confirmar primeiro SHA256="
        "daa7bcc15a6cb1adf4fb46563100b2d67ff8b6694b191ef762d3cd2d8e61f3c4 "
        "e permissoes 0600 da copia na VPS. Esta operacao pode adicionar "
        "6 Evidence antigas; nao recria P217/P218 e nao fecha sessoes.",
        "Owner approves exactly one import_evidence_bundle into original REA from "
        "the isolated source-owned P214 six-record checksum-matched staged copy "
        "inside the preapproved REA analysis root. No import from any other file, "
        "no binary session opening or closing, no source modifications, and "
        "no restoration of P217/P218 unknowns."
    ),)

def main():
    os.umask(0o077)
    directory, private, public = signer_files()
    nonce = secrets.token_hex(16)
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
    steps = []
    for index, (tool, args, notice, reason) in enumerate(controlled_operations(nonce)):
        print("\nOPERACAO", index + 1, "de 1:", tool)
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
    private_out = Path.home() / ("rea-p229-restauro-" + nonce + ".json")
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
    print("\nREA_OWNER_RECOVERY_P229_SIGNED=PASS")
    print("PEDIDO_JSON_SHA256=", hashlib.sha256(encoded).hexdigest())
    print("Foi autorizada APENAS uma importacao de recuperacao do arquivo P214 (6 Evidence).")
    print("P217/P218 permanecem historicas e NAO sao recriadas.")
    print("Nao enviar chaves PEM. Envia apenas o ficheiro JSON assinado, dentro da validade.")
    print("Nenhuma ferramenta MCP foi executada neste Android.")


if __name__ == "__main__":
    main()
