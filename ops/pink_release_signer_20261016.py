"""Owner-authorized one-time PINK Android release signing, on the pinned VPS only.

No private key, keystore password, device credentials, or token is ever returned
to the GitHub runner. The private key stays root-owned on the VPS with a second
root-only backup. Signing input is an exact already-verified unsigned APK.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import stat
import subprocess
import sys

EXPECTED_UNSIGNED_SHA256 = "517702ff380edfc6c4b51177ecc04f6bb4379f7abb5ec5c3c299e6b7a58c603a"
EXPECTED_UNSIGNED_BYTES = 47331714
EXPECTED_SIGNER_ALIAS = "pink-iptv-release-v1"
INBOX = Path("/home/ubuntu/.pink-release-inbox-20261016")
UNSIGNED = INBOX / "PINK-IPTV-RELEASE-UNSIGNED.apk"
SIGNER_JAR = INBOX / "apksigner.jar"
SIGNED = INBOX / "PINK-IPTV-FINAL.apk"
PRIVATE_ROOT = Path("/var/lib/pink-iptv")
VAULT = PRIVATE_ROOT / "release-signing"
BACKUP_PARENT = Path("/var/backups/pink-iptv")
BACKUP = BACKUP_PARENT / "release-signing"
KEY = VAULT / "pink-iptv-release.p12"
PASSWORD = VAULT / "pink-iptv-release.password"
BACKUP_KEY = BACKUP / KEY.name
BACKUP_PASSWORD = BACKUP / PASSWORD.name
META = VAULT / "signer-metadata.json"


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def root_dir(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("Refuse symlinked signing directory")
    if not path.exists():
        path.mkdir(mode=0o700)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
        raise RuntimeError("Unsafe signing directory ownership")
    path.chmod(0o700)


def guarded_file(path: Path) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise RuntimeError("Unsafe signing key or password file")
    return True


def secret_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb", closefd=True) as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    path.chmod(0o600)


def quiet(command: list[str], *, read: bool = False) -> bytes:
    completed = subprocess.run(command, input=b"", stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False, timeout=180)
    if completed.returncode:
        raise RuntimeError("Trusted Android release tool failed")
    return completed.stdout if read else b""


def certificate_fingerprint() -> str:
    cert = quiet(["keytool", "-exportcert", "-alias", EXPECTED_SIGNER_ALIAS,
                  "-keystore", str(KEY), "-storetype", "PKCS12",
                  "-storepass:file", str(PASSWORD)], read=True)
    if len(cert) < 300 or len(cert) > 8192:
        raise RuntimeError("Signing certificate malformed")
    return hashlib.sha256(cert).hexdigest()


def verify_backup_pair() -> None:
    for target, backup in ((KEY, BACKUP_KEY), (PASSWORD, BACKUP_PASSWORD)):
        if not guarded_file(target) or not guarded_file(backup):
            raise RuntimeError("Incomplete persistent signer or backup")
        if sha(target) != sha(backup):
            raise RuntimeError("Signer backup drift")


def provision_once() -> tuple[str, bool]:
    """Provision once only. Existing keys can never be silently replaced."""
    os.umask(0o077)
    if not PRIVATE_ROOT.exists():
        PRIVATE_ROOT.mkdir(mode=0o700)
    root_dir(PRIVATE_ROOT)
    root_dir(VAULT)
    if not BACKUP_PARENT.is_dir() or BACKUP_PARENT.is_symlink():
        raise RuntimeError("Expected approved PINK backup root missing")
    if BACKUP_PARENT.lstat().st_uid != 0:
        raise RuntimeError("Backup root ownership drift")
    root_dir(BACKUP)

    original_exists = any(guarded_file(p) for p in
                          (KEY, PASSWORD, BACKUP_KEY, BACKUP_PASSWORD))
    if not original_exists:
        if META.exists() or META.is_symlink():
            raise RuntimeError("Signer metadata without signer files")
        pass_bytes = (secrets.token_hex(32) + "\n").encode("ascii")
        secret_file(PASSWORD, pass_bytes)
        quiet(["keytool", "-genkeypair", "-alias", EXPECTED_SIGNER_ALIAS,
               "-keyalg", "RSA", "-keysize", "4096", "-validity", "36500",
               "-dname", "CN=PINK IPTV, OU=Android Release, O=PINK IPTV, C=PT",
               "-keystore", str(KEY), "-storetype", "PKCS12",
               "-storepass:file", str(PASSWORD), "-keypass:file", str(PASSWORD),
               "-noprompt"])
        KEY.chmod(0o600)
        cert = certificate_fingerprint()
        secret_file(BACKUP_KEY, KEY.read_bytes())
        secret_file(BACKUP_PASSWORD, PASSWORD.read_bytes())
        verify_backup_pair()
        secret_file(META, (json.dumps({
            "application_id": "com.pinkiptv.extreme",
            "alias": EXPECTED_SIGNER_ALIAS,
            "certificate_sha256": cert,
            "owner_approved_source": "d48126cb8b95da3ea76646fbb8bf3de033216167",
            "signer_vault": "VPS root protected",
            "backup": "VPS root protected separate directory",
            "test_signing": False,
        }, sort_keys=True) + "\n").encode())
        return cert, True

    verify_backup_pair()
    if not guarded_file(META):
        raise RuntimeError("Missing immutable signer metadata")
    metadata = json.loads(META.read_text())
    cert = certificate_fingerprint()
    if metadata.get("certificate_sha256") != cert:
        raise RuntimeError("Signer changed; refuse key replacement")
    if metadata.get("alias") != EXPECTED_SIGNER_ALIAS:
        raise RuntimeError("Signer alias drift")
    return cert, False


def input_file(path: Path, min_size: int, max_size: int) -> None:
    if path.is_symlink():
        raise RuntimeError("Untrusted signing input symlink")
    st = path.lstat()
    owner = pwd.getpwnam("ubuntu").pw_uid
    if not stat.S_ISREG(st.st_mode) or st.st_uid != owner:
        raise RuntimeError("Signing input not from expected service user")
    if st.st_size < min_size or st.st_size > max_size:
        raise RuntimeError("Signing input size mismatch")


def run_sign() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Root-only signing boundary")
    if INBOX.is_symlink() or not INBOX.is_dir():
        raise RuntimeError("Signing inbox absent or symlinked")
    st = INBOX.lstat()
    if st.st_uid != pwd.getpwnam("ubuntu").pw_uid or st.st_mode & 0o077:
        raise RuntimeError("Signing inbox permissions invalid")
    input_file(UNSIGNED, EXPECTED_UNSIGNED_BYTES, EXPECTED_UNSIGNED_BYTES)
    input_file(SIGNER_JAR, 100000, 5000000)
    if sha(UNSIGNED) != EXPECTED_UNSIGNED_SHA256:
        raise RuntimeError("APK differs from independently certified unsigned build")

    fingerprint, newly_created = provision_once()

    # Never reuse a potentially replaced prior signed output.
    if SIGNED.is_symlink():
        raise RuntimeError("Signed APK path symlink")
    if SIGNED.exists():
        if not stat.S_ISREG(SIGNED.lstat().st_mode):
            raise RuntimeError("Unexpected signed output type")
        SIGNED.unlink()

    quiet(["java", "-cp", str(SIGNER_JAR),
           "com.android.apksigner.ApkSignerTool", "sign",
           "--ks", str(KEY), "--ks-type", "PKCS12",
           "--ks-key-alias", EXPECTED_SIGNER_ALIAS,
           "--ks-pass", "file:" + str(PASSWORD),
           "--key-pass", "file:" + str(PASSWORD),
           "--out", str(SIGNED), str(UNSIGNED)])
    quiet(["java", "-cp", str(SIGNER_JAR),
           "com.android.apksigner.ApkSignerTool", "verify",
           "--verbose", "--print-certs", str(SIGNED)])
    if SIGNED.stat().st_size < 10_000_000 or SIGNED.stat().st_size > 100_000_000:
        raise RuntimeError("Unexpected signed APK size")

    # Only the signed, public-distributable APK leaves the root sign boundary.
    ubuntu = pwd.getpwnam("ubuntu")
    os.chown(SIGNED, ubuntu.pw_uid, ubuntu.pw_gid)
    SIGNED.chmod(0o600)
    print("PINK_RELEASE_SIGNING=" + json.dumps({
        "status": "SIGNED_AND_VERIFIED",
        "application_id": "com.pinkiptv.extreme",
        "unsigned_sha256": EXPECTED_UNSIGNED_SHA256,
        "signed_sha256": sha(SIGNED),
        "signed_bytes": SIGNED.stat().st_size,
        "certificate_sha256": fingerprint,
        "permanent_signer_preserved_on_vps": True,
        "protected_local_backup_preserved": True,
        "signer_created": newly_created,
        "secrets_disclosed": False,
        "vpn_leases_modified": False,
    }, sort_keys=True, separators=(",", ":")))


def selftest() -> None:
    assert len(EXPECTED_UNSIGNED_SHA256) == 64
    assert EXPECTED_UNSIGNED_BYTES == 47331714
    assert VAULT != BACKUP
    assert PRIVATE_ROOT != BACKUP_PARENT
    assert KEY.suffix == ".p12"
    assert SIGNED.name == "PINK-IPTV-FINAL.apk"
    print("PINK_SIGNING_STATIC_BOUNDARY_SELFTEST=PASS")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected exactly one subcommand")
    if sys.argv[1] == "selftest":
        selftest()
    elif sys.argv[1] == "sign":
        run_sign()
    else:
        raise SystemExit("Unknown signing command")
