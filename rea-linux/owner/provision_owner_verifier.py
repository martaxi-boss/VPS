#!/usr/bin/env python3
"""One-time, owner-controlled Ed25519 PUBLIC verifier enrollment for original REA.

Run on the owner's existing VPS as the REA SSH user (ubuntu). This script cannot
generate private keys, unlock a sensitive tool, rotate an installed trust root,
or change any REA service. It is never connected to a GitHub request action.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PARTS = (".local", "share", "rea-chatgpt-trial", "sealed-bridge")
BASENAME = "owner-approval-public.pem"


def normalized_public_key(source):
    if not isinstance(source, bytes) or not 40 <= len(source) <= 1024:
        raise ValueError("Expected a short PEM public key, never a private key")
    if b"PRIVATE KEY" in source or b"BEGIN PUBLIC KEY" not in source:
        raise ValueError("Input must be the owner's Ed25519 PUBLIC key only")
    key = serialization.load_pem_public_key(source)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Expected an Ed25519 public key")
    pem = key.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, hashlib.sha256(der).hexdigest()


def private_policy_directory(home, uid):
    root = Path(home)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("Unexpected SSH home")
    if root.stat().st_uid != uid:
        raise RuntimeError("SSH home is not owned by the executing user")
    current = root
    for part in PARTS:
        current = current / part
        if current.is_symlink():
            raise RuntimeError("Refusing a symlink in the private policy path")
        current.mkdir(mode=0o700, exist_ok=True)
        st = current.stat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != uid
                or stat.S_IMODE(st.st_mode) & 0o022):
            raise RuntimeError("Unsafe policy directory ownership or permissions")
    if stat.S_IMODE(current.stat().st_mode) != 0o700:
        raise RuntimeError("REA private policy directory must have mode 0700")
    return current


def checked_existing(path, expected_pem, uid):
    if path.is_symlink():
        raise RuntimeError("Refusing owner verifier symlink")
    if not path.exists():
        return None
    st = path.stat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != uid
            or stat.S_IMODE(st.st_mode) != 0o600):
        raise RuntimeError("Existing owner verifier permissions are unsafe")
    observed, _ = normalized_public_key(path.read_bytes())
    if observed != expected_pem:
        raise RuntimeError("Different owner verifier already installed: deliberate offline rotation required")
    return "ALREADY_PROVISIONED_MATCHING"


def enroll(source, expected_fingerprint, home=None):
    if os.geteuid() == 0:
        raise RuntimeError("Never enroll the owner verifier as root")
    if (not isinstance(expected_fingerprint, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint)):
        raise ValueError("Expected lowercase SHA-256 of DER public key")
    pem, digest = normalized_public_key(source)
    if digest != expected_fingerprint:
        raise ValueError("Public key fingerprint differs from owner's device")
    uid = os.geteuid()
    directory = private_policy_directory(home or Path.home(), uid)
    destination = directory / BASENAME
    existing = checked_existing(destination, pem, uid)
    if existing is not None:
        return existing, digest
    fd, staging = tempfile.mkstemp(prefix=".rea-owner-public-", dir=str(directory))
    try:
        with os.fdopen(fd, "wb") as writer:
            os.fchmod(writer.fileno(), 0o600)
            writer.write(pem)
            writer.flush()
            os.fsync(writer.fileno())
        try:
            os.link(staging, str(destination), follow_symlinks=False)
            state = "PROVISIONED"
        except FileExistsError:
            state = checked_existing(destination, pem, uid)
            if state is None:
                raise RuntimeError("Owner verifier provisioning race")
        if checked_existing(destination, pem, uid) is None:
            raise RuntimeError("Cannot verify installed public owner key")
        return state, digest
    finally:
        Path(staging).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key-file", required=True,
                        help="Path to PUBLIC PEM only (or /dev/stdin)")
    parser.add_argument("--expected-sha256", required=True,
                        help="Owner-confirmed SHA-256 of DER public key")
    parser.add_argument("--approve-enrollment", action="store_true")
    args = parser.parse_args()
    if not args.approve_enrollment:
        parser.error("Explicit --approve-enrollment is required")
    raw = Path(args.public_key_file).read_bytes()
    state, fingerprint = enroll(raw, args.expected_sha256)
    print("REA_OWNER_VERIFIER_STATUS=" + state)
    print("REA_OWNER_VERIFIER_SHA256=" + fingerprint)
    print("REA_OWNER_PRIVATE_KEY_ON_VPS=NO")


if __name__ == "__main__":
    main()
