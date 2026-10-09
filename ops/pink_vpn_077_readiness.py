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

    # Task078 ambiguous-write recovery: inspect state without touching anything.
    possible_backup = Path("/var/backups/pink-iptv/task078")
    print("PINK077_TASK078_BACKUP_PRESENT=" + str(possible_backup.is_dir()))
    if possible_backup.is_dir():
        for entry in ("baseline", "state.json", "quota.py", "accepted", "rolled-back"):
            print("PINK077_TASK078_" + entry.replace(".", "_").upper() +
                  "_PRESENT=" + str((possible_backup / entry).is_file()))
        state = possible_backup / "state.json"
        if state.is_file():
            metadata = __import__("json").loads(state.read_text())
            current_hash = hashlib.sha256(VPN_ENV.read_bytes()).hexdigest()
            kind = "NEW" if current_hash == metadata.get("new_sha256") else (
                "ORIGINAL" if current_hash == metadata.get("original_sha256") else "OTHER"
            )
            print("PINK077_TASK078_ENV_CONTENT_STATUS=" + kind)
    temp = VPN_ENV.with_name("vpn.env.task078.next")
    print("PINK077_TASK078_TEMP_FILE_PRESENT=" + str(temp.exists()))
    if temp.exists():
        print("PINK077_TASK078_TEMP_MODE=" + oct(temp.stat().st_mode & 0o777))
    if possible_backup.is_dir():
        quota_script = possible_backup / "quota.py"
        print("PINK077_TASK078_BACKUP_SCRIPT_PYCOMPILE=" + str(
            subprocess.run(["python3", "-c", "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')", str(quota_script)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10).returncode == 0
        ) if quota_script.is_file() else "MISSING")
    status = subprocess.run(
        ["systemctl", "is-active", "pink-vpn-quota-078-rollback.timer"],
        capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    print("PINK077_TASK078_TIMER_ACTIVE=" + str(status == "active"))
    for name in ("pink-vpn-quota-078-rollback.timer", "pink-vpn-quota-078-r2-rollback.timer"):
        timer = subprocess.run(
            ["systemctl", "is-active", name], capture_output=True, text=True, timeout=8
        ).stdout.strip()
        print("PINK077_TASK078_" + ("R2" if "-r2-" in name else "R1") +
              "_TIMER_STATE=" + (timer if timer in ("active", "inactive", "failed", "unknown") else "UNCLASSIFIED"))
    pid = int(capture("systemctl", "show", "pink-iptv-backend", "-p", "MainPID", "--value"))
    assert pid > 0
    process_env = Path(f"/proc/{pid}/environ").read_bytes().split(b"\\x00")
    print("PINK077_TASK078_PROCESS_HAS_QUOTA10=" +
          str(b"VPN_MAX_INSTALLATIONS_PER_ACCOUNT=10" in process_env))
    if (possible_backup / "accepted").is_file():
        metadata = __import__("json").loads((possible_backup / "state.json").read_text())
        assert hashlib.sha256(VPN_ENV.read_bytes()).hexdigest() == metadata["new_sha256"]
        assert b"VPN_MAX_INSTALLATIONS_PER_ACCOUNT=10" in process_env
        assert override == 10 and status != "active"
        assert revisions[0] == "20261005_0002"
        print("PINK077_POST_R3_LIVE_TEN_SLOTS_NO_MIGRATIONS=PASS")
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
