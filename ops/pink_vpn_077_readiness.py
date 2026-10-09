"""Owner-scoped, read-only live VPN rollout readiness, sanitized aggregate proof.

Never prints customer identifiers, keys, credentials, raw system env, IPs or SQL rows.
Does not start/stop services, change firewall/peers/DB, install or deploy.
"""

from pathlib import Path
import hashlib
import os
import re
import subprocess


ROOT = Path("/srv/pink-iptv/backend")
VPN_ENV = Path("/etc/pink-iptv/vpn.env")
ALLOWED_QUOTAS = set(range(1, 11))


def capture(*args: str) -> str:
    return subprocess.run(
        args, capture_output=True, text=True, check=True, timeout=20
    ).stdout.strip()


def pg(db: str, sql: str) -> str:
    assert db.isidentifier()
    return capture(
        "runuser", "-u", "postgres", "--", "psql", "-X", "-At",
        "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql,
    )


def service(name: str) -> bool:
    return capture("systemctl", "is-active", name) == "active"


def inspect() -> None:
    assert os.geteuid() == 0
    assert capture("hostname") == "vps-32bea5b6"
    assert service("pink-iptv-backend") and service("pink-vpn")
    assert ROOT.joinpath("app/vpn.py").is_file()
    unit_files = capture(
        "systemctl", "show", "pink-iptv-backend", "-p", "EnvironmentFiles", "--value"
    )
    assert str(VPN_ENV) in unit_files and VPN_ENV.is_file()
    print("PINK077_EXPECTED_VPN_ENVFILE_IS_UNIT_BOUND=PASS")
    source = ROOT.joinpath("app/config.py").read_text()
    version = re.search(
        r"vpn_max_installations_per_account\s*:\s*int\s*=\s*Field\(default=(\d+)",
        source,
    )
    assert version is not None
    effective_default = int(version.group(1))
    assert effective_default in ALLOWED_QUOTAS

    # Whitelist exactly one non-secret numeric override; never echo any other
    # EnvironmentFile data, unit variables or service command line.
    override = None
    if VPN_ENV.is_file():
        for line in VPN_ENV.read_text().splitlines():
            if line.startswith("VPN_MAX_INSTALLATIONS_PER_ACCOUNT="):
                value = line.partition("=")[2].strip().strip("'\"")
                assert value.isdigit()
                override = int(value)
                assert override in ALLOWED_QUOTAS

    names = pg("postgres", "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate").splitlines()
    matches = [
        name for name in names if name.isidentifier() and pg(name,
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' "
        "AND table_name='vpn_installations'") == "1"
    ]
    assert len(matches) == 1
    database = matches[0]
    active = pg(database, """
        SELECT COUNT(*), COUNT(DISTINCT mapping_id), COUNT(DISTINCT address)
        FROM vpn_installations
        WHERE revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP
    """).split("|")
    assert len(active) == 3 and all(t.isdigit() for t in active)
    revisions = pg(database, "SELECT version_num FROM alembic_version").splitlines()
    assert len(revisions) == 1 and re.fullmatch(r"[A-Za-z0-9_]{1,40}", revisions[0])

    peer_lines = capture("wg", "show", "pinkvpn", "peers").splitlines()
    count = sum(bool(line.strip()) for line in peer_lines)
    changes = {
        "auth_rate_windows": "20261008_0003",
        "vpn_address_releases": "20261009_0004",
        "vpn_rate_windows": "20261009_0006",
    }
    existing = {}
    for table in changes:
        sql = ("SELECT COUNT(*) FROM information_schema.tables WHERE "
               "table_schema='public' AND table_name='" + table + "'")
        count_table = pg(database, sql)
        assert count_table in {"0", "1"}
        existing[table] = count_table == "1"
    files = [p.name for p in ROOT.joinpath("alembic/versions").glob("*.py")]
    assert len(files) < 100
    print("PINK077_READ_ONLY_NO_CUSTOMER_IDENTIFIERS=PASS")
    print("PINK077_RUNTIME_DEFAULT_SLOTS=" + str(effective_default))
    print("PINK077_RUNTIME_ENV_OVERRIDE=" + (str(override) if override else "UNSET"))
    print("PINK077_DATABASE_MIGRATION=" + revisions[0])
    print("PINK077_ACTIVE_INSTALLATIONS=" + active[0])
    print("PINK077_ACTIVE_ACCOUNT_COUNT=" + active[1])
    print("PINK077_ACTIVE_OWNED_ADDRESSES=" + active[2])
    print("PINK077_LIVE_PEER_COUNT=" + str(count))
    for table, found in existing.items():
        print("PINK077_" + table.upper() + "=" + ("PRESENT" if found else "ABSENT"))
    print("PINK077_MIGRATION_FILES_COUNT=" + str(len(files)))
    print("PINK077_BACKEND_VPN_SOURCE_SHA256=" +
          hashlib.sha256(ROOT.joinpath("app/vpn.py").read_bytes()).hexdigest())


if __name__ == "__main__":
    try:
        inspect()
    except Exception:
        print("PINK077_READ_ONLY_INSPECTION_FAILED_REDACTED", flush=True)
        raise SystemExit(1)
