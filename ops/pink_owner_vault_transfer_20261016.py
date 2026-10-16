"""One-time encrypted transfer of the *existing* PINK APK signer into Owner's original VPS vault.
Only root on the pinned VPS may decrypt, own, or verify secrets.
No new signing identity is generated and no plaintext is ever emitted to GitHub logs.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile

ROOT = Path("/root/project-secrets")
OWNER = ROOT / "OWNER-SIGNING"
VAULT = OWNER / "PINK-IPTV-FINAL-20261016"
EXCHANGE_PRIV = VAULT / ".one-time-import-rsa.pem"
EXCHANGE_CERT = VAULT / ".one-time-import-cert.pem"
KEY_NAME = "PINK-IPTV-CHAVE-DE-ASSINATURA-20261016.p12"
PASS_NAME = "PINK-IPTV-KEYSTORE-PASSWORD.txt"
RECOVERY_NAME = "PINK-IPTV-SENHA-DE-RECUPERACAO-20261016.txt"
META_NAME = "signing-identity.json"
EXPECTED_KEY_SHA = "95e2fe6da5834312a202c0eab74bfcbe36d9600d5f501ba485d011507b3d50ef"
EXPECTED_RECOVERY_SHA = "53efa6cd65e843c4fb815096fec4b4e7fb7d6d46aed8d1a5b4bb1aa27f94c3a8"
EXPECTED_CERT_SHA = "e65fb31a1ad7f4380a71b8503cd8d5627a92fc5b0fb56d82abfedf7ceab3ca8f"
EXPECTED_SIGNED_APK_SHA = "779ca54dbbc3170f746a2f57bb9216f16fbf3c1f60f38aadbe1adee21d30e3ca"
EXPECTED_OWNER_SOURCE = "d48126cb8b95da3ea76646fbb8bf3de033216167"
INBOX = Path("/home/ubuntu/.pink-owner-signing-inbox-20261016")
ENCRYPTED = INBOX / "pink-owner-signing-transfer-20261016.cms.b64"
BACKUP_ROOT = Path("/var/backups/pink-iptv")
BACKUP_PARENT = BACKUP_ROOT / "release-signing"
BACKUP = BACKUP_PARENT / "PINK-IPTV-FINAL-20261016"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def command(argv, *, data=None, timeout=90):
    try:
        p = subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        if p.returncode:
            raise RuntimeError("Protected crypto check failed")
        return p.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Protected crypto tool unavailable") from exc

def protected_dir(path, *, create=False):
    if path.is_symlink():
        raise RuntimeError("Refuse symlink in vault path")
    if create and not path.exists():
        path.mkdir(mode=0o700)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError("Vault directory not root/0700")
    return path

def root_preflight():
    if os.geteuid()!=0:
        raise RuntimeError("Root-only vault operation")
    os.umask(0o077)
    protected_dir(ROOT)

def assure_vault():
    root_preflight()
    protected_dir(OWNER,create=True)
    protected_dir(VAULT,create=True)

def backup_root_existing():
    if BACKUP_ROOT.is_symlink() or not BACKUP_ROOT.is_dir():
        raise RuntimeError("PINK backup root absent or symlinked")
    st=BACKUP_ROOT.lstat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise RuntimeError("Unsafe PINK backup root")
    return BACKUP_ROOT

def guarded(path):
    if path.is_symlink():
        raise RuntimeError("Symlinked vault material")
    if not path.exists():
        return False
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o600:
        raise RuntimeError("Vault material ownership or permissions changed")
    return True

def write_new(path,content):
    flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os,"O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd=os.open(str(path),flags,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())

def prepare():
    assure_vault()
    if any(guarded(VAULT / n) for n in [KEY_NAME,PASS_NAME,RECOVERY_NAME]):
        raise RuntimeError("Signer already present; no new transport needed")
    if EXCHANGE_PRIV.exists() != EXCHANGE_CERT.exists():
        raise RuntimeError("Incomplete exchange certificate pair")
    if not EXCHANGE_PRIV.exists():
        command(["openssl","req","-x509","-newkey","rsa:4096","-nodes","-sha256",
                 "-days","2","-subj","/CN=PINK IPTV One Time VPS Transfer 20261016",
                 "-keyout",str(EXCHANGE_PRIV),"-out",str(EXCHANGE_CERT)], timeout=120)
        EXCHANGE_PRIV.chmod(0o600)
        EXCHANGE_CERT.chmod(0o600)
    if not guarded(EXCHANGE_PRIV) or not guarded(EXCHANGE_CERT):
        raise RuntimeError("Transport material not root protected")
    cert=EXCHANGE_CERT.read_bytes()
    if len(cert)<500 or len(cert)>4000: raise RuntimeError("Transport certificate invalid")
    print("PINK_ONE_TIME_TRANSFER_PUBLIC_CERT_B64="+base64.b64encode(cert).decode("ascii"))
    print("PINK_TRANSFER_CERT_SHA256="+digest(cert))
    print("PINK_OWNER_VAULT_PREPARED=PASS")

def verify_cert_bytes(p12,password):
    if len(password)!=64 or not password.isascii():
        raise RuntimeError("Recovery password shape invalid")
    with tempfile.TemporaryDirectory(prefix=".signer-verify-",dir=VAULT) as temp:
        t=Path(temp); a=t/"check.p12"; b=t/"check.pw"
        write_new(a,p12)
        write_new(b,password+b"\n")
        pem=command(["openssl","pkcs12","-in",str(a),"-passin","file:"+str(b),
                     "-nokeys","-clcerts"])
        der=command(["openssl","x509","-inform","PEM","-outform","DER"],data=pem)
        return digest(der)

def verify_files():
    assure_vault()
    backup_root_existing()
    protected_dir(BACKUP_PARENT)
    protected_dir(BACKUP)
    for name,expected in [(KEY_NAME,EXPECTED_KEY_SHA),(RECOVERY_NAME,EXPECTED_RECOVERY_SHA)]:
        main=VAULT/name; backup=BACKUP/name
        if not guarded(main) or not guarded(backup): raise RuntimeError("Signer or protected backup incomplete")
        if digest(main.read_bytes())!=expected or main.read_bytes()!=backup.read_bytes():
            raise RuntimeError("Protected signer backup has wrong identity")
    passwd=VAULT/PASS_NAME; backup_pass=BACKUP/PASS_NAME
    if not guarded(passwd) or not guarded(backup_pass) or passwd.read_bytes()!=backup_pass.read_bytes():
        raise RuntimeError("Protected signing password not consistently backed up")
    pw=passwd.read_bytes().strip()
    if not pw or verify_cert_bytes((VAULT/KEY_NAME).read_bytes(),pw)!=EXPECTED_CERT_SHA:
        raise RuntimeError("Signer certificate does not match the released APK")
    if pw not in (VAULT/RECOVERY_NAME).read_bytes():
        raise RuntimeError("Signer password does not match encrypted recovery record")
    meta=VAULT/META_NAME
    if not guarded(meta): raise RuntimeError("Signer metadata missing")
    j=json.loads(meta.read_text())
    if j.get("signer_cert_sha256")!=EXPECTED_CERT_SHA or j.get("approved_apk_sha256")!=EXPECTED_SIGNED_APK_SHA:
        raise RuntimeError("Signer metadata disagrees with released APK")
    print("PINK_VPS_OWNER_SIGNER_VERIFIED="+json.dumps({
        "status":"PASS","vault":str(VAULT),"backup":str(BACKUP),
        "p12_sha256":EXPECTED_KEY_SHA,"signer_certificate_sha256":EXPECTED_CERT_SHA,
        "approved_apk_sha256":EXPECTED_SIGNED_APK_SHA,
        "permissions":"root:0700/0600","signing_password_private":True,
        "backup_integrity":"PASS","owner_vpn_or_services_modified":False,
        "secrets_ever_printed":False},sort_keys=True))

def import_existing():
    assure_vault()
    if not guarded(EXCHANGE_PRIV) or not guarded(EXCHANGE_CERT):
        if (VAULT/KEY_NAME).exists():
            verify_files()
            return
        raise RuntimeError("One-time private exchange key absent")
    st=ENCRYPTED.lstat()
    ubuntu=pwd.getpwnam("ubuntu").pw_uid
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=ubuntu or stat.S_IMODE(st.st_mode)!=0o600 or not (1000<st.st_size<30000):
        raise RuntimeError("Encrypted source ownership, permissions or size invalid")
    enc=base64.b64decode(ENCRYPTED.read_bytes().strip(),validate=True)
    if len(enc)<1000 or len(enc)>30000:
        raise RuntimeError("Encrypted envelope size invalid")
    output=command(["openssl","cms","-decrypt","-binary","-inform","DER",
                    "-inkey",str(EXCHANGE_PRIV),"-recip",str(EXCHANGE_CERT)],data=enc)
    payload=json.loads(output.decode("utf-8"))
    if set(payload)!={"p12_b64","password_b64","recovery_b64","approved_source","signer_cert_sha256"}:
        raise RuntimeError("Unexpected signer envelope schema")
    if payload["approved_source"]!=EXPECTED_OWNER_SOURCE or payload["signer_cert_sha256"]!=EXPECTED_CERT_SHA:
        raise RuntimeError("Signer envelope source mismatch")
    p12=base64.b64decode(payload["p12_b64"],validate=True)
    pw=base64.b64decode(payload["password_b64"],validate=True)
    recovery=base64.b64decode(payload["recovery_b64"],validate=True)
    if digest(p12)!=EXPECTED_KEY_SHA or digest(recovery)!=EXPECTED_RECOVERY_SHA:
        raise RuntimeError("Exact already-signed key/recovery mismatch")
    if pw not in recovery:
        raise RuntimeError("Recovery and signing password disagree")
    if verify_cert_bytes(p12,pw)!=EXPECTED_CERT_SHA:
        raise RuntimeError("PKCS12 signing identity mismatch")
    backup_root_existing()
    protected_dir(BACKUP_PARENT,create=True)
    protected_dir(BACKUP,create=True)
    files={KEY_NAME:p12,PASS_NAME:pw+b"\n",RECOVERY_NAME:recovery}
    metadata=(json.dumps({
        "application_id":"com.pinkiptv.extreme",
        "key_alias":"pink-iptv-release-v1",
        "signer_cert_sha256":EXPECTED_CERT_SHA,
        "approved_apk_sha256":EXPECTED_SIGNED_APK_SHA,
        "approved_source":EXPECTED_OWNER_SOURCE,
        "vault":"owner original root vault",
        "backed_up":True,
        "key_generated_here":False},sort_keys=True)+"\n").encode()
    files[META_NAME]=metadata
    for directory in (VAULT,BACKUP):
        for name,content in files.items():
            p=directory/name
            if guarded(p):
                if p.read_bytes()!=content:
                    raise RuntimeError("Protected existing signer differs; refuse overwrite")
            else:
                write_new(p,content)
    verify_files()
    # Delete the one-time transport private key after vault and backup integrity passes.
    EXCHANGE_PRIV.unlink()
    EXCHANGE_CERT.unlink()
    ENCRYPTED.unlink()
    print("PINK_EXISTING_SIGNER_IMPORTED=PASS")
    print("PINK_EPHEMERAL_TRANSPORT_KEY_DESTROYED=PASS")

if __name__=="__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in {"prepare","import","verify"}:
        raise SystemExit("Expected protected prepare/import/verify action")
    try:
        if sys.argv[1]=="prepare": prepare()
        elif sys.argv[1]=="import": import_existing()
        else: verify_files()
    except Exception:
        print("PINK_VPS_SIGNING_VAULT_OPERATION=FAILED_WITHOUT_SECRET_OUTPUT",file=sys.stderr)
        raise SystemExit(1)
