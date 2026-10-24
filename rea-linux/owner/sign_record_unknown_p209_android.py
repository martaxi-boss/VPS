#!/usr/bin/env python3
"""Offline owner approval for a P209 REA residual-unknown MCP test.

This script only signs an exact, short-lived three-step request on the
owner's Android/Termux. It NEVER connects to VPS, SSH, GitHub or MCP.
Private Ed25519 key NEVER leaves Termux. No key is created or replaced.
Execution requires separate safe preflight of the REA Linux session and
transport via the EXISTING encrypted GitHub Actions -> SSH bridge.
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
WORKSPACE_ACK = "AUTORIZO_ANALISE_LOCAL"

def controlled_operations(nonce):
    unknown_args = {
        "question": "Does this isolated REA ELF test have independent observed evidence for its unresolved behavior?",
        "severity": "low",
        "domain": "rea-linux-p209-owned-fixture-" + nonce,
        "required_authority": "controlled-replay",
        "required_confidence": "observed",
        "required_environment": None,
        "recommended_probes": [],
        "relationships": [],
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
    }
    return (
        (
            "open_binary", {"path": "/usr/bin/true", "provider_id": "ghidra"}, "workspace",
            "Owner approves only a bounded analysis session for the known Linux system ELF /usr/bin/true with existing Ghidra provider, without executing the ELF.",
            "Abrir somente o ficheiro ELF conhecido /usr/bin/true, com o Ghidra existente; sem executar o programa. A sessão será encerrada pela ponte após o teste.",
        ),
        (
            "record_unknown", unknown_args, "sensitive",
            "Owner authorizes recording one low-severity unresolved question tied to a unique owned-test nonce in the temporary binary analysis context; no truth claim.",
            "Criar uma única questão não resolvida e evidência de mutação no contexto de teste /usr/bin/true; sem afetar outro projeto.",
        ),
        (
            "record_unknown", unknown_args, "sensitive",
            "Owner authorizes one duplicate-identity negative test against the just-created controlled unknown, expecting MCP isError true and no extra record.",
            "Repetir exatamente a mesma questão no contexto de teste para verificar rejeição de duplicados: espera-se isError=true.",
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
    operations = controlled_operations(nonce)
    steps = []
    for index, (name, args, scope, reason, notice) in enumerate(operations):
        print("\nOPERACAO", index + 1, "de", len(operations), ":", name)
        print(notice)
        print("Ambito:", scope, "| Argumentos exatos:", canonical(args).decode("ascii"))
        print("Validade limite UTC:", expiry)
        confirmation_required = ACK if scope == "sensitive" else WORKSPACE_ACK
        confirmation = input("Para autorizar ESTA operacao escreve " + confirmation_required + ": ").strip()
        if confirmation != confirmation_required:
            raise RuntimeError("Autorizacao recusada; nenhum pedido completo e produzido")
        hashed_args = hashlib.sha256(canonical(args)).hexdigest()
        authorization = {
            "tool": name,
            "arguments_sha256": hashed_args,
            "scope": scope,
            "reason": reason,
            "confirmed_by_owner": True,
            "acknowledgement": confirmation_required,
        }
        if scope == "sensitive":
            signed_payload = {
                "purpose": "REA_OWNER_APPROVAL_V1",
                "nonce": nonce,
                "expires_at": expiry,
                "step_index": index,
                "tool": name,
                "arguments_sha256": hashed_args,
                "scope": scope,
                "reason": reason,
                "acknowledgement": confirmation_required,
            }
            authorization["owner_signature"] = sign_and_verify(
                private, public, directory, signed_payload
            )
        steps.append({"tool": name, "arguments": args, "authorization": authorization})
    request = {"protocol": 1, "nonce": nonce, "expires_at": expiry, "steps": steps}
    print("\nREA_OWNER_RECORD_UNKNOWN_P209_SIGNED=PASS")
    print("BEGIN_REA_SIGNED_REQUEST_JSON")
    print(canonical(request).decode("ascii"))
    print("END_REA_SIGNED_REQUEST_JSON")
    print("Apenas as 2 operacoes sensitive foram assinadas; a operacao workspace tem aprovacao separada.")
    print("Envie somente o JSON assinado para o operador. NUNCA envie ficheiros PEM nem a chave privada.")
    print("O pedido nao foi executado: depende de preflight seguro da sessao e cifragem pela ponte existente.")

if __name__ == "__main__":
    main()
