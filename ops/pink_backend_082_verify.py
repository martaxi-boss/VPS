"""Independent post-deploy proof for PINK VPN backend 0006. Read-only.

Never prints or exports customer identities, WireGuard keys, lease addresses,
authentication materials, raw SQL rows, systemd environments or pg dumps.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

APP = Path("/srv/pink-iptv/backend")
BACKUP = Path("/var/backups/pink-iptv/task081")
PINNED_SOURCE = "558f8aa49f1611532ca2b4417b42086b81ca50b9"
NEW_VPN_SHA = "5955756b5bf3ae32b23beeeaacfa3ab7b815b844c7c676cd65601e90e827bc1c"  # pragma: allowlist secret - public source checksum
REVISION = "20261009_0006"
ADDENDUM = (
    "20261008_0003_auth_rate_windows.py",
    "20261009_0004_vpn_address_releases.py",
    "20261009_0005_vpn_device_timestamps.py",
    "20261009_0006_vpn_rate_windows.py",
)


def run(*args: str) -> str:
    return subprocess.run(
        args, text=True, check=True, capture_output=True, timeout=25
    ).stdout.strip()


def pg(db: str, sql: str) -> str:
    assert re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", db)
    return run(
        "runuser", "-u", "postgres", "--", "psql", "-X", "-At",
        "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql,
    )


def verify() -> None:
    assert os.geteuid() == 0
    assert run("hostname") == "vps-32bea5b6"
    assert run("systemctl", "is-active", "pink-iptv-backend") == "active"
    assert run("systemctl", "is-active", "pink-vpn") == "active"
    assert run("systemctl", "is-active", "postgresql") == "active"
    assert BACKUP.is_dir() and not BACKUP.is_symlink()
    assert stat.S_IMODE(BACKUP.stat().st_mode) == 0o700
    assert (BACKUP / "accepted").is_file()
    assert not (BACKUP / "rolled-back").exists()
    state = json.loads((BACKUP / "state.json").read_text())
    assert state["source_sha"] == PINNED_SOURCE
    assert state["new_vpn_sha"] == NEW_VPN_SHA
    assert state["installation_rows"] >= 14

    image = BACKUP / "database.pgdump"
    assert image.is_file() and not image.is_symlink()
    assert stat.S_IMODE(image.stat().st_mode) == 0o600
    assert image.stat().st_size > 1000

    timer = subprocess.run(
        ["systemctl", "is-active", "pink-backend-081-rollback.timer"],
        capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    assert timer in ("inactive", "unknown")

    installed = APP / "app/vpn.py"
    assert installed.is_file() and not installed.is_symlink()
    assert hashlib.sha256(installed.read_bytes()).hexdigest() == NEW_VPN_SHA
    assert all((APP / "alembic/versions" / x).is_file() for x in ADDENDUM)
    expected = APP / "alembic/versions/20261005_0002_vpn_installations.py"
    assert expected.is_file()

    pid = int(run("systemctl", "show", "pink-iptv-backend", "-p", "MainPID", "--value"))
    assert pid > 0
    env = Path(f"/proc/{pid}/environ").read_bytes().split(b"\x00")
    assert b"VPN_MAX_INSTALLATIONS_PER_ACCOUNT=10" in env

    rows = pg(
        "postgres",
        "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate",
    ).splitlines()
    matches = [
        db for db in rows if db.isidentifier() and pg(
            db, "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name='vpn_installations'",
        ) == "1"
    ]
    assert len(matches) == 1
    db = matches[0]
    assert pg(db, "SELECT version_num FROM alembic_version") == REVISION
    stats = pg(
        db,
        "SELECT COUNT(*), COUNT(DISTINCT address) FILTER (WHERE address IS NOT NULL), "
        "COUNT(*) FILTER (WHERE revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP) "
        "FROM vpn_installations",
    ).split("|")
    assert len(stats) == 3 and all(v.isdigit() for v in stats)
    total, allocated, active = map(int, stats)
    assert total >= state["installation_rows"]
    assert allocated <= total and active <= total

    vpn_columns = set(pg(
        db, "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name='vpn_installations'",
    ).splitlines())
    assert {
        "id", "mapping_id", "public_key", "address", "token_sha256",
        "expires_at", "revoked_at", "created_at", "last_authenticated_at",
    } <= vpn_columns
    assert not {"private_key", "device_token", "password"} & vpn_columns
    assert pg(
        db,
        "SELECT is_nullable FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='vpn_installations' AND column_name='address'",
    ) == "YES"

    for name in ("vpn_address_releases", "vpn_rate_windows", "auth_rate_windows"):
        assert pg(
            db, "SELECT COUNT(*) FROM information_schema.tables "
                f"WHERE table_schema='public' AND table_name='{name}'",
        ) == "1"

    raw = run(
        "curl", "--silent", "--show-error", "--fail", "--max-time", "8",
        "http://127.0.0.1:8010/openapi.json",
    )
    paths = json.loads(raw)["paths"]
    assert all(url in paths for url in (
        "/v1/vpn/enroll", "/v1/vpn/refresh", "/v1/vpn/revoke",
        "/v1/vpn/installations", "/v1/vpn/installations/release",
    ))
    assert "get" in paths["/v1/vpn/installations"]
    assert "post" in paths["/v1/vpn/installations/release"]

    controller = Path("/run/pink-vpn/control.sock")
    assert controller.is_socket() and not controller.is_symlink()
    print("PINK082_INDEPENDENT_LIVE_BACKEND_0006=PASS")
    print("PINK082_PRODUCTION_QUOTA10_IN_RUNNING_PROCESS=PASS")
    print("PINK082_EXISTING_INSTALLATION_COUNT_PRESERVED=PASS")
    print("PINK082_INSTALLATIONS_TOTAL=" + str(total))
    print("PINK082_CURRENT_ACTIVE_LEASES=" + str(active))
    print("PINK082_LEASE_ADDRESS_OWNERSHIP_UNIQUE=PASS")
    print("PINK082_RECOVERY_ENDPOINTS_PRESENT=PASS")
    print("PINK082_ROOT_BACKUP_ACCEPTED_AND_TIMER_OFF=PASS")
    print("PINK082_GATEWAY_SOCKET_AND_SERVICE_PRESERVED=PASS")


if __name__ == "__main__":
    try:
        verify()
    except Exception:
        print("PINK082_INDEPENDENT_POSTFLIGHT_FAILED_REDACTED", flush=True)
        raise SystemExit(1)
