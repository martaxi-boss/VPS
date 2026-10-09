"""Guarded, rollback-armed PINK backend migration 0002 -> 0006.

Only the pinned backend app modules and additive Alembic versions may change.
The WireGuard server, existing peer controller, service EnvironmentFiles,
customers, credentials, firewall, APK and release signing never change here.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tarfile
import time

APP = Path("/srv/pink-iptv/backend")
BACKUP = Path("/var/backups/pink-iptv/task081")
TIMER = "pink-backend-081-rollback"
OLD_TREE_SHA = "ac766478e977d4f381472ab3da8d2076cb0770b59fe2145db7096b5eebdc4a61"  # pragma: allowlist secret -- read-only source fingerprint
OLD_VPN_SHA = "d2e73d88a65602fbbb51a5460dc4d3edab3b8f8da0d3e271e07fad12c775065a"  # pragma: allowlist secret -- read-only source fingerprint
OLD_REV = "20261005_0002"
NEW_REV = "20261009_0006"
MIGRATIONS = {
    "20261008_0003_auth_rate_windows.py",
    "20261009_0004_vpn_address_releases.py",
    "20261009_0005_vpn_device_timestamps.py",
    "20261009_0006_vpn_rate_windows.py",
}


def run(*args: str, timeout: int = 35) -> str:
    return subprocess.run(
        args, text=True, capture_output=True, check=True, timeout=timeout
    ).stdout.strip()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def app_tree_sha() -> str:
    data = hashlib.sha256()
    for path in sorted((APP / "app").rglob("*.py")):
        data.update(str(path.relative_to(APP)).encode() + b"\x00")
        data.update(hashlib.sha256(path.read_bytes()).digest())
    return data.hexdigest()


def pg(db: str, sql: str) -> str:
    assert db.isidentifier()
    return run(
        "runuser", "-u", "postgres", "--", "psql",
        "-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql,
    )


def database_name() -> str:
    names = pg("postgres", "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate").splitlines()
    matches = [name for name in names if name.isidentifier() and pg(
        name, "SELECT COUNT(*) FROM information_schema.tables "
              "WHERE table_schema='public' AND table_name='vpn_installations'"
    ) == "1"]
    assert len(matches) == 1
    return matches[0]


def revision(db: str) -> str:
    value = pg(db, "SELECT version_num FROM alembic_version")
    assert value in {OLD_REV, "20261008_0003", "20261009_0004", "20261009_0005", NEW_REV}
    return value


def installation_fingerprint(db: str) -> str:
    """Digest preexisting lease ownership and token hashes without emitting PII."""
    value = pg(db, """
        SELECT md5(COALESCE(string_agg(
            id::text || ':' || mapping_id::text || ':' || public_key || ':' ||
            COALESCE(address, 'NULL') || ':' || token_sha256 || ':' ||
            expires_at::text || ':' || COALESCE(revoked_at::text, 'NULL'),
            '|' ORDER BY id
        ), ''))
        FROM vpn_installations
    """)
    assert len(value) == 32 and all(c in "0123456789abcdef" for c in value)
    return value


def process_quota_ten() -> bool:
    pid = int(run("systemctl", "show", "pink-iptv-backend", "-p", "MainPID", "--value"))
    assert pid > 0
    env = Path(f"/proc/{pid}/environ").read_bytes().split(b"\x00")
    return b"VPN_MAX_INSTALLATIONS_PER_ACCOUNT=10" in env


def healthy() -> None:
    for attempt in range(24):
        backend = subprocess.run(
            ["systemctl", "is-active", "pink-iptv-backend"],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        vpn = subprocess.run(
            ["systemctl", "is-active", "pink-vpn"],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        api = subprocess.run([
            "curl", "--silent", "--show-error", "--max-time", "2",
            "http://127.0.0.1:8010/openapi.json"
        ], capture_output=True, text=True, timeout=5)
        if backend == "active" and vpn == "active" and api.returncode == 0:
            try:
                routes = json.loads(api.stdout)["paths"]
                if "/v1/vpn/enroll" in routes:
                    return
            except (ValueError, KeyError, TypeError):
                pass
        if attempt < 23:
            time.sleep(1)
    raise RuntimeError("Backend restart not healthy within bounded window")


def migration(direction: str, target: str) -> None:
    assert direction in ("upgrade", "downgrade")
    assert target in (NEW_REV, OLD_REV)
    # All secret-bearing settings are read only in the child process. Never log
    # its env, stdout, stderr or exception payload.
    script = (
        "from dotenv import dotenv_values\n"
        "from alembic import command\nfrom alembic.config import Config\n"
        "import os\n"
        "for p in ('/etc/pink-iptv/backend.env', '/etc/pink-iptv/secrets.env', '/etc/pink-iptv/vpn.env'):\n"
        "    os.environ.update({k:v for k,v in dotenv_values(p).items() if v is not None})\n"
        "getattr(command, os.environ['PINK081_MIGRATION_DIRECTION'])(Config('alembic.ini'), "
        "os.environ['PINK081_MIGRATION_TARGET'])\n"
    )
    child_env = dict(os.environ, PINK081_MIGRATION_DIRECTION=direction,
                     PINK081_MIGRATION_TARGET=target)
    outcome = subprocess.run(
        [str(APP / ".venv/bin/python"), "-c", script],
        cwd=APP, env=child_env, capture_output=True, text=True, timeout=100,
    )
    if outcome.returncode != 0:
        raise RuntimeError("PINK081 migration command failed (details redacted)")


def safe_archive(archive: Path, sha256: str, destination: Path) -> Path:
    assert archive.is_file() and not archive.is_symlink()
    assert len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256)
    assert digest(archive.read_bytes()) == sha256
    assert not destination.exists()
    destination.mkdir(mode=0o700)
    allowed = {"backend/app/", "backend/alembic/versions/"}
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        assert 12 <= len(members) <= 120
        total_size = 0
        for member in members:
            assert member.isfile() and not member.issym() and not member.islnk()
            assert ".." not in Path(member.name).parts and not Path(member.name).is_absolute()
            assert any(member.name.startswith(prefix) for prefix in allowed)
            assert member.name.endswith(".py") and len(member.name) < 240
            assert 0 < member.size <= 3_000_000
            total_size += member.size
        assert total_size <= 20_000_000
        # Manually extract validated regular files. No tarfile filter API
        # version dependency and no symlink/hardlink/owner materialization.
        for member in members:
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(member) as source_file, target.open("xb") as output:
                assert source_file is not None
                shutil.copyfileobj(source_file, output)
    sources = list((destination / "backend/app").rglob("*.py"))
    assert len(sources) >= 8
    migrations = {p.name for p in (destination / "backend/alembic/versions").glob("*.py")}
    assert migrations == MIGRATIONS
    return destination / "backend"


def check() -> None:
    assert os.geteuid() == 0 and run("hostname") == "vps-32bea5b6"
    assert not BACKUP.exists()
    assert APP.is_dir() and not APP.is_symlink()
    assert run("systemctl", "is-active", "pink-vpn") == "active"
    assert run("systemctl", "is-active", "pink-iptv-backend") == "active"
    assert (APP / "app/vpn.py").is_file()
    assert digest((APP / "app/vpn.py").read_bytes()) == OLD_VPN_SHA
    assert app_tree_sha() == OLD_TREE_SHA
    assert revision(database_name()) == OLD_REV
    assert process_quota_ten()
    healthy()
    print("PINK081_EXACT_OLD_BACKEND_QUOTA10_READY=PASS")


def backup_original(db: str) -> None:
    BACKUP.mkdir(mode=0o700)
    os.chmod(BACKUP, 0o700)
    shutil.copytree(APP / "app", BACKUP / "old_app")
    shutil.copytree(APP / "alembic/versions", BACKUP / "old_versions")
    shutil.copy2(__file__, BACKUP / "rollback.py")
    os.chmod(BACKUP / "rollback.py", 0o600)
    state = {"database": db,
             "installation_rows": int(pg(db, "SELECT COUNT(*) FROM vpn_installations")),
             "installation_digest_before": installation_fingerprint(db),
             "old_tree_sha": OLD_TREE_SHA,
             "source_sha": "",
             "new_vpn_sha": ""}
    (BACKUP / "state.json").write_text(json.dumps(state))
    os.chmod(BACKUP / "state.json", 0o600)
    with (BACKUP / "database.pgdump").open("wb") as output:
        outcome = subprocess.run(
            ["runuser", "-u", "postgres", "--", "pg_dump", "-Fc", "-d", db],
            stdout=output, stderr=subprocess.DEVNULL, timeout=90,
        )
        assert outcome.returncode == 0
    os.chmod(BACKUP / "database.pgdump", 0o600)
    assert (BACKUP / "database.pgdump").stat().st_size > 1000
    run("pg_restore", "--list", str(BACKUP / "database.pgdump"), timeout=30)
    # Read/decompress every data object from the private backup without
    # restoring into or changing any live database. The TOC alone is not a
    # sufficient integrity test for a corrupted data payload.
    run("pg_restore", "--file=/dev/null", str(BACKUP / "database.pgdump"), timeout=100)
    print("PINK081_COMPLETE_PGDUMP_STREAM_RESTORABILITY_CHECK=PASS")
    print("PINK081_DURABLE_CODE_AND_DB_BACKUP=PASS")


def install_source(source: Path) -> None:
    uid = pwd.getpwnam("pink-iptv").pw_uid
    gid = pwd.getpwnam("pink-iptv").pw_gid
    for file in (source / "app").rglob("*"):
        assert file.is_file() and file.suffix == ".py"
        relative = file.relative_to(source / "app")
        target = APP / "app" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, target)
        os.chown(target, uid, gid)
    for file in (source / "alembic/versions").glob("*.py"):
        assert file.name in MIGRATIONS
        target = APP / "alembic/versions" / file.name
        assert not target.exists()
        shutil.copy2(file, target)
        os.chown(target, uid, gid)


def apply(archive: Path, sha256: str, new_vpn_sha: str, source_sha: str) -> None:
    check()
    assert len(new_vpn_sha) == 64 and all(c in "0123456789abcdef" for c in new_vpn_sha)
    assert len(source_sha) == 40 and all(c in "0123456789abcdef" for c in source_sha)
    staging = safe_archive(archive, sha256, BACKUP.with_name("task081-source-" + source_sha[:10]))
    db = database_name()
    backup_original(db)
    state = json.loads((BACKUP / "state.json").read_text())
    state["source_sha"] = source_sha
    state["new_vpn_sha"] = new_vpn_sha
    old_files = {
        str(p.relative_to(BACKUP / "old_app"))
        for p in (BACKUP / "old_app").rglob("*.py")
    }
    incoming_files = {
        str(p.relative_to(staging / "app"))
        for p in (staging / "app").rglob("*.py")
    }
    assert old_files and incoming_files
    # Record exactly which new Python modules this update adds, for a
    # non-destructive and repeatable selective rollback.
    state["added_app_py"] = sorted(incoming_files - old_files)
    (BACKUP / "state.json").write_text(json.dumps(state))
    run("systemd-run", "--unit=" + TIMER, "--on-active=15m",
        "/usr/bin/python3", str(BACKUP / "rollback.py"), "rollback")
    assert run("systemctl", "is-active", TIMER + ".timer") == "active"
    print("PINK081_ROLLBACK_TIMER_ARMED=PASS")
    run("systemctl", "stop", "pink-iptv-backend")
    assert run("systemctl", "is-active", "pink-vpn") == "active"
    install_source(staging)
    assert digest((APP / "app/vpn.py").read_bytes()) == new_vpn_sha
    print("PINK081_STAGED_NEW_CODE_INSTALLED=PASS")
    migration("upgrade", NEW_REV)
    assert revision(db) == NEW_REV
    # The API is still stopped. Verify each legacy lease's key, token, owner,
    # address, expiry and revocation survived the schema upgrade exactly.
    assert installation_fingerprint(db) == state["installation_digest_before"]
    print("PINK081_EXISTING_LEASE_OWNERSHIP_EXACTLY_PRESERVED=PASS")
    print("PINK081_ADDITIVE_MIGRATION_COMPLETE=PASS")
    run("systemctl", "start", "pink-iptv-backend")
    verify()
    print("PINK081_NEW_BACKEND_READY_NO_GATEWAY_MUTATION=PASS")


def verify() -> None:
    assert BACKUP.is_dir() and not (BACKUP / "accepted").exists()
    state = json.loads((BACKUP / "state.json").read_text())
    assert revision(state["database"]) == NEW_REV
    assert digest((APP / "app/vpn.py").read_bytes()) == state["new_vpn_sha"]
    assert int(pg(state["database"], "SELECT COUNT(*) FROM vpn_installations")) >= state["installation_rows"]
    assert process_quota_ten()
    healthy()
    api = json.loads(run(
        "curl", "--silent", "--show-error", "--max-time", "8",
        "http://127.0.0.1:8010/openapi.json",
    ))
    assert "/v1/vpn/installations" in api["paths"]
    assert "/v1/vpn/installations/release" in api["paths"]
    assert run("systemctl", "is-active", TIMER + ".timer") == "active"
    print("PINK081_BACKEND_0006_AND_OWNER_RECOVERY_ENDPOINTS_VERIFIED=PASS")


def rollback() -> None:
    if not BACKUP.is_dir() or (BACKUP / "accepted").exists():
        return
    state = json.loads((BACKUP / "state.json").read_text())
    db = state["database"]
    current = revision(db)
    # An address released by the new system MUST NOT be resurrected in an old
    # backend. Refuse downgrade if any IP ownership has changed.
    if current != OLD_REV:
        assert pg(db, "SELECT COUNT(*) FROM vpn_installations WHERE address IS NULL") == "0"
        if current in {"20261009_0004", "20261009_0005", NEW_REV}:
            assert pg(db, "SELECT COUNT(*) FROM vpn_address_releases") == "0"
    run("systemctl", "stop", "pink-iptv-backend")
    if current != OLD_REV:
        migration("downgrade", OLD_REV)
    assert revision(db) == OLD_REV
    # Selective in-place restore is retryable even after a partial rollback.
    # Do not remove the entire live app/versions directory, which could leave
    # the server unbootable when a copy operation encounters an IO failure.
    uid = pwd.getpwnam("pink-iptv").pw_uid
    gid = pwd.getpwnam("pink-iptv").pw_gid
    saved = BACKUP / "old_app"
    assert saved.is_dir() and not saved.is_symlink()
    for path in sorted(saved.rglob("*.py")):
        relative = path.relative_to(saved)
        target = APP / "app" / relative
        assert target.is_file() and not target.is_symlink()
        shutil.copy2(path, target)
        os.chown(target, uid, gid)
    for item in state["added_app_py"]:
        relative = Path(item)
        assert not relative.is_absolute() and ".." not in relative.parts
        assert relative.suffix == ".py"
        assert not (saved / relative).exists()
        target = APP / "app" / relative
        if target.exists():
            assert target.is_file() and not target.is_symlink()
            target.unlink()
    for name in MIGRATIONS:
        candidate = APP / "alembic/versions" / name
        if candidate.exists():
            assert candidate.is_file() and not candidate.is_symlink()
            candidate.unlink()
    assert app_tree_sha() == OLD_TREE_SHA
    run("systemctl", "start", "pink-iptv-backend")
    healthy()
    assert process_quota_ten()
    (BACKUP / "rolled-back").write_text("verified safe code/schema inverse\\n")
    print("PINK081_OLD_APP_AND_SCHEMA_EXACTLY_RESTORED=PASS")


def accept() -> None:
    verify()
    (BACKUP / "accepted").write_text("accepted PINK backend source and migrations\\n")
    run("systemctl", "stop", TIMER + ".timer")
    print("PINK081_BACKEND_0006_ACCEPTED=PASS")


if __name__ == "__main__":
    try:
        action = sys.argv[1] if len(sys.argv) > 1 else ""
        if action == "check":
            check()
        elif action == "apply" and len(sys.argv) == 6:
            apply(Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5])
        elif action in ("verify", "rollback", "accept") and len(sys.argv) == 2:
            {"verify": verify, "rollback": rollback, "accept": accept}[action]()
        else:
            raise RuntimeError("Unsupported operation")
    except Exception:
        print("PINK081_OPERATION_FAILED_REDACTED", flush=True)
        raise SystemExit(1)
