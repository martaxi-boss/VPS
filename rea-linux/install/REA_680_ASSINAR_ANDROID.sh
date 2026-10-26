#!/data/data/com.termux/files/usr/bin/bash
# REA 6.8.0: signed owner consent for the ORIGINAL import_evidence_bundle MCP tool.
# It DOES NOT connect to VPS, replace REA, install anything or transfer keys.
set -eu
python3 - <<'PY'
import base64, hashlib, json, os, secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def canon(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")

private=Path.home()/".rea-owner"/"rea-owner-private.pem"
if not private.is_file() or private.is_symlink():
    raise SystemExit("REA_680=ERRO chave existente do proprietario indisponivel; nao criar outra.")
key=load_pem_private_key(private.read_bytes(),password=None)
if not isinstance(key,Ed25519PrivateKey):
    raise SystemExit("REA_680=ERRO chave proprietaria nao e Ed25519.")
args={"path":"/opt/rea-reversa/rea/.rea-migration/evidence-restore.json"}
args_sha=hashlib.sha256(canon(args)).hexdigest()
assert args_sha=="8f169f38227b98c0b0cb1f7231ccfdfaab221a71044f2dc67edf73048f23a515"
nonce=secrets.token_hex(16)
expiry=(datetime.now(timezone.utc)+timedelta(hours=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
reason=("Autorizo a troca controlada do REA oficial 6.7.0 por 6.8.0 e a "
        "importacao do backup privado de 16 Evidence e 1 Unknown; "
        "numa falha, autorizo o restauro do REA anterior e desse mesmo bundle.")
auth={"tool":"import_evidence_bundle",
      "arguments_sha256":args_sha,"scope":"sensitive",
      "reason":reason,"confirmed_by_owner":True,
      "acknowledgement":"AUTORIZO_OPERACAO_SENSIVEL"}
body={"protocol":1,"nonce":nonce,"expires_at":expiry,
      "steps":[{"tool":"import_evidence_bundle",
                "arguments":args,"authorization":auth}]}
message={"purpose":"REA_OWNER_APPROVAL_V1","nonce":nonce,
         "expires_at":expiry,"step_index":0,"tool":"import_evidence_bundle",
         "arguments_sha256":args_sha,"scope":"sensitive",
         "reason":reason,"acknowledgement":"AUTORIZO_OPERACAO_SENSIVEL"}
sig=key.sign(canon(message))
key.public_key().verify(sig,canon(message))
body["steps"][0]["authorization"]["owner_signature"]=base64.b64encode(sig).decode("ascii")
outdir=Path.home()/"storage"/"downloads"
if not outdir.is_dir():
    outdir=Path.home()
dest=outdir/("REA_680_IMPORT_ASSINADO_"+nonce[:12]+".json")
fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"wb") as out:
    out.write(canon(body)+b"\n")
print("REA_680_ASSINATURA=PASS_LOCAL_ONLY")
print("REA_680_CHAVE_PRIVADA=CONTINUA_NO_TERMUX")
print("REA_680_ASSINOU=IMPORTAR_16_EVIDENCE_1_UNKNOWN_APOS_UPDATE")
print("REA_680_EXPIRA_UTC="+expiry)
print("REA_680_FICHEIRO="+str(dest))
print("Anexa apenas este ficheiro JSON no ChatGPT; NUNCA envies o PEM.")
PY
