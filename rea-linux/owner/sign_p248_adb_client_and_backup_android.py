#!/usr/bin/env python3
"""Sign exact REA ADB client inspection + retained Evidence backup on Android.

No internet, GitHub, SSH, device connection, or key export. The private
Ed25519 PEM stays in Termux. The 45-minute two-step signed request covers
only inert local ADB metadata and new no-overwrite durable Evidence export.
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
TOOL = "inspect_adb_client"
ARGUMENTS = {}
REASON = "Owner controlled REA certification of ADB client metadata without any device communication."


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
    """Two owner-approved steps; ADB metadata first, durable Evidence export second."""
    os.umask(0o077)
    directory, private, public = local_key_files()
    nonce = secrets.token_hex(16)
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=45)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    # The second step is strictly the existing REA systemd StateDirectory.
    # The GitHub bridge's original path policy must NOT be permanently widened.
    # Operator must install a temporary SHA/expiry-exact path exception only
    # AFTER receiving owner-signed exact arguments, as in approved P214.
    backup_path = "/var/lib/rea-reversa/rea-p248-adb-client-" + nonce + ".json"
    operations = (
        (
            "inspect_adb_client",
            {},
            "O REA vai ler apenas a versao e o caminho do executavel ADB local "
            "na VPS, sem iniciar servidor ADB ou contactar dispositivos.",
            "Owner authorizes one ADB client version and binary-path inspection on "
            "the existing original REA VPS without starting adb server, accessing "
            "a device or performing binary session lifecycle operations.",
        ),
        (
            "export_evidence_bundle",
            {"path": backup_path, "overwrite": False},
            "Se a inspecao anterior passar, guardar TODAS as Evidence e Unknowns "
            "retidas num ficheiro NOVO privado da pasta persistente REA. "
            "Nao sobrescrever nada nem fechar sessao.",
            "Owner authorizes a new complete REA Evidence/Unknown backup to "
            "this exact nonce-bound filename in the original existing systemd "
            "StateDirectory, overwrite=false. No session close, daemon restart, "
            "cross-project writes or changes to any other destination.",
        ),
    )
    steps = []
    for index, (tool, args, notice, reason) in enumerate(operations):
        print("\nREA - AUTORIZACAO", index + 1, "de", len(operations))
        print("Ferramenta:", tool)
        print("Argumentos:", canonical(args).decode("ascii"))
        print(notice)
        print("Expira (UTC):", expiry)
        approval = input("Escreve AUTORIZO_OPERACAO_SENSIVEL para ESTE passo: ").strip()
        if approval != APPROVAL:
            raise RuntimeError("Autorizacao recusada. Nenhum pedido completo foi criado.")
        digest = hashlib.sha256(canonical(args)).hexdigest()
        authorization = {
            "tool": tool,
            "arguments_sha256": digest,
            "scope": "sensitive",
            "reason": reason,
            "confirmed_by_owner": True,
            "acknowledgement": APPROVAL,
        }
        signed_fields = {
            "purpose": "REA_OWNER_APPROVAL_V1",
            "nonce": nonce,
            "expires_at": expiry,
            "step_index": index,
            "tool": tool,
            "arguments_sha256": digest,
            "scope": authorization["scope"],
            "reason": reason,
            "acknowledgement": APPROVAL,
        }
        with tempfile.TemporaryDirectory(prefix="rea-p248-sign-", dir=directory) as root:
            msg = Path(root) / "step.json"
            signature = Path(root) / "step.sig"
            msg.write_bytes(canonical(signed_fields))
            subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-rawin",
                 "-inkey", str(private), "-in", str(msg),
                 "-out", str(signature)],
                check=True, capture_output=True,
            )
            proof = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                 "-inkey", str(public), "-in", str(msg),
                 "-sigfile", str(signature)],
                capture_output=True, check=False,
            )
            raw = signature.read_bytes()
            if proof.returncode != 0 or len(raw) != 64:
                raise RuntimeError("Assinatura Ed25519 nao passou na verificacao local.")
        authorization["owner_signature"] = base64.b64encode(raw).decode("ascii")
        steps.append({"tool": tool, "arguments": args, "authorization": authorization})

    body = {"protocol": 1, "nonce": nonce, "expires_at": expiry, "steps": steps}
    encoded = canonical(body) + b"\n"
    home_output = Path.home() / ("rea-p248-adb-backup-" + nonce + ".json")
    fd = os.open(home_output, os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600)
    with os.fdopen(fd, "wb") as writer:
        writer.write(encoded)
    print("FICHEIRO_TERMUX=", home_output)
    download = Path("/sdcard/Download")
    if download.is_dir() and os.access(download, os.W_OK):
        shared = download / home_output.name
        try:
            fd = os.open(shared, os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600)
            with os.fdopen(fd, "wb") as writer:
                writer.write(encoded)
            print("FICHEIRO_DOWNLOADS=", shared)
        except OSError:
            print("FICHEIRO_DOWNLOADS=UNAVAILABLE")
    else:
        print("FICHEIRO_DOWNLOADS=UNAVAILABLE")

    print("\nREA_P248_TWO_EXACT_OWNER_SIGNATURES=PASS")
    print("FICHEIRO_ASSINADO_EXPIRA_UTC=", expiry)
    print("BEGIN_REA_SIGNED_REQUEST_JSON")
    print(canonical(body).decode("ascii"))
    print("END_REA_SIGNED_REQUEST_JSON")
    print("Envia apenas o ficheiro JSON assinado, nunca as chaves PEM.")
    print("Nenhuma ferramenta REA foi executada neste Android.")


if __name__ == "__main__":
    main()
