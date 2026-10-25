#!/usr/bin/env python3
"""Autorizacao offline para ensaio P218 update_unknown no REA original.

Prepara duas assinaturas Ed25519 independentes no Android Termux.
NUNCA cria chaves, nem contacta GitHub/VPS/MCP, nem executa operacoes REA.
A chave privada permanece exclusivamente no Android.
A operacao avanca para investigating uma questao existente P217; gera uma revisao e uma nova Evidence;
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
    """Two exact owner-approved P218 updates; second intentionally stale.

    The original P217 unknown currently has revision 1 and status open.
    A successful first call creates revision 2, status investigating, and one
    new mutation Evidence while preserving the prior six historical Evidence
    and the P217 creation Evidence. A second attempt with expected_revision=1
    is an intentionally stale optimistic-concurrency negative test.
    This program does not connect to VPS/GitHub or touch the owner's keys.
    """
    unknown_id = "unk_83470d409b1de94724284543af4f1db77f71da800bd2b6ee259b22e9a67c3952"
    args = {
        "unknown_id": unknown_id,
        "expected_revision": 1,
        "status": "investigating",
        "severity": "low",
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "required_authority": "controlled-replay",
        "required_confidence": "observed",
        "required_environment": None,
        "recommended_probes": [],
        "relationships": [],
        "resolution": None,
    }
    return (
        (
            "update_unknown", args,
            "ATUALIZACAO REAL P218: alterar a questao CDP autorizada da P217 de open/revisao 1 para investigating/revisao 2. Isto cria UMA nova Evidence permanente. Nao afirma que o endpoint CDP existe; nao elimina nem altera outras questoes.",
            "Owner explicitly authorizes exactly one revision-guarded status update of the source-owned P217 unknown from open revision 1 to investigating revision 2 in the original REA MCP, with one new mutation Evidence. No CDP attachment or resolution claim, no session close or changes to other projects.",
        ),
        (
            "update_unknown", args,
            "TESTE NEGATIVO P218: repetir a mesma atualizacao, intencionalmente com expected_revision=1 ja ultrapassada. Espera-se isError=true/revision-conflict, sem outra revisao nem Evidence.",
            "Owner explicitly authorizes exactly one identical stale-revision update_unknown negative test against the same P217 unknown, expecting MCP isError=true revision-conflict and zero additional changes. No other operations allowed.",
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
    private_out = Path.home() / ("rea-p218-pedido-" + nonce + ".json")
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
    print("\nREA_OWNER_UPDATE_P218_SIGNED=PASS")
    print("BEGIN_REA_SIGNED_REQUEST_JSON")
    print(canonical(request).decode("ascii"))
    print("END_REA_SIGNED_REQUEST_JSON")
    print("APENAS transicao open -> investigating de uma questao P217 e rejeicao de revisao obsoleta estao autorizadas.")
    print("Nao enviar chaves PEM. Envia apenas o JSON assinado no prazo.")
    print("Nenhuma ferramenta MCP foi executada neste Android.")


if __name__ == "__main__":
    main()
