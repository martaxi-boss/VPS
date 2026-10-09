"""Read-only production readiness for the four additive PINK backend migrations.

Requires root on pinned host; no customer records, tokens, peer keys or env
contents leave the host. No service, DB, filesystem or WireGuard writes.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess

APP = Path("/srv/pink-iptv/backend")
EXPECT_VPN_SHA = "d2e73d88a65602fbbb51a5460dc4d3edab3b8f8da0d3e271e07fad12c775065a"  # pragma: allowlist secret -- immutable public source checksum


def run(*args):
    return subprocess.run(args, text=True, check=True, capture_output=True, timeout=20).stdout.strip()


def pg(database, sql):
    assert re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", database)
    return run("runuser", "-u", "postgres", "--", "psql", "-X", "-At",
               "-v", "ON_ERROR_STOP=1", "-d", database, "-c", sql)


def inspect():
    assert os.geteuid() == 0 and run("hostname") == "vps-32bea5b6"
    for service in ("nginx", "postgresql", "pink-vpn", "pink-iptv-backend"):
        assert run("systemctl", "is-active", service) == "active"
    assert APP.is_dir() and not APP.is_symlink()
    assert (APP / ".venv/bin/python").is_file()
    assert (APP / "app/vpn.py").is_file()
    sha = hashlib.sha256((APP / "app/vpn.py").read_bytes()).hexdigest()
    assert sha == EXPECT_VPN_SHA
    assert (APP / "alembic.ini").is_file()
    python_files = sorted((APP / "app").rglob("*.py"))
    assert 8 <= len(python_files) <= 90
    digest = hashlib.sha256()
    for path in python_files:
        digest.update(str(path.relative_to(APP)).encode() + b"\x00")
        digest.update(hashlib.sha256(path.read_bytes()).digest())

    # Check the exact installed runtime can load the libraries already needed
    # by the new backend. We do not evaluate Settings or read live secrets.
    run(str(APP / ".venv/bin/python"), "-c",
        "import fastapi, sqlalchemy, alembic, pydantic, dotenv, httpx")
    revisions = [
        row for row in pg("postgres",
            "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate"
        ).splitlines() if row.isidentifier() and pg(row,
            "SELECT COUNT(*) FROM information_schema.tables WHERE "
            "table_schema='public' AND table_name='vpn_installations'") == "1"
    ]
    assert len(revisions) == 1
    database = revisions[0]
    current_rev = pg(database, "SELECT version_num FROM alembic_version")
    assert current_rev == "20261005_0002"
    live_rows = pg(database,
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE address IS NULL), "
        "COUNT(*) FILTER (WHERE revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP) "
        "FROM vpn_installations").split("|")
    assert len(live_rows) == 3 and all(item.isdigit() for item in live_rows)
    assert int(live_rows[1]) == 0
    size = int(pg(database, "SELECT pg_database_size(current_database())"))
    assert 0 <= size <= 100_000_000_000
    free_bytes = os.statvfs(str(APP)).f_frsize * os.statvfs(str(APP)).f_bavail
    assert free_bytes >= 5 * max(size, 50_000_000)
    run("pg_dump", "--version")
    run("pg_restore", "--version")
    assert (APP / "app").stat().st_uid >= 0
    source = (APP / "app/vpn.py").read_text()
    assert 'router = APIRouter(prefix="/v1/vpn")' in source
    print("PINK079_NON_MUTATING_LIVE_READINESS=PASS")
    print("PINK079_BACKEND_TREE_SHA256=" + digest.hexdigest())
    print("PINK079_OLD_VPN_SOURCE_SHA256=" + sha)
    print("PINK079_MIGRATION_BASE=" + current_rev)
    print("PINK079_INSTALLATION_ROWS=" + live_rows[0])
    print("PINK079_NULL_ADDRESS_ROWS=" + live_rows[1])
    print("PINK079_ACTIVE_LEASES=" + live_rows[2])
    print("PINK079_PG_DB_BYTES_BAND=" + ("UNDER_100MB" if size < 100_000_000 else "100MB_PLUS"))
    print("PINK079_BACKUP_DISK_MARGIN_5X=PASS")
    print("PINK079_PYTHON_DEPENDENCIES=PASS")


if __name__ == "__main__":
    try:
        inspect()
    except Exception:
        print("PINK079_READ_ONLY_INSPECTION_FAILED_REDACTED", flush=True)
        raise SystemExit(1)
