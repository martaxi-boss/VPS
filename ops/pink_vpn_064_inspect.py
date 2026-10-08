"""READ-ONLY VPN quota and WireGuard activity inspection (no customer/peer records).

Uses local PostgreSQL peer auth; never reads backend environment or secrets.
Only server-side SQL aggregates and anonymous WireGuard peer counts leave the host.
"""
import os
import subprocess
import time


AGGREGATE_SQL = """
WITH active AS (
  SELECT mapping_id, COUNT(*) AS installed
  FROM vpn_installations
  WHERE revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP
  GROUP BY mapping_id
), at_limit AS (
  SELECT vpn.expires_at
  FROM vpn_installations vpn JOIN active USING (mapping_id)
  WHERE active.installed >= 5 AND vpn.revoked_at IS NULL
    AND vpn.expires_at > CURRENT_TIMESTAMP
)
SELECT
 (SELECT COUNT(*) FROM active),
 (SELECT COUNT(*) FROM active WHERE installed >= 5),
 (SELECT COALESCE(MAX(installed), 0) FROM active),
 (SELECT COALESCE(SUM(installed), 0) FROM active),
 (SELECT COUNT(*) FROM at_limit),
 (SELECT COUNT(*) FROM at_limit WHERE expires_at <= CURRENT_TIMESTAMP + interval '1 hour'),
 (SELECT COALESCE(FLOOR(EXTRACT(EPOCH FROM MIN(expires_at) - CURRENT_TIMESTAMP)/60)::integer,-1) FROM at_limit),
 (SELECT COALESCE(FLOOR(EXTRACT(EPOCH FROM MAX(expires_at) - CURRENT_TIMESTAMP)/60)::integer,-1) FROM at_limit)
"""


def capture(*args):
    result = subprocess.run(args, text=True, capture_output=True, check=True, timeout=20)
    return result.stdout.strip()


def pg(database, sql):
    return capture("runuser", "-u", "postgres", "--", "psql", "-X", "-At",
                   "-v", "ON_ERROR_STOP=1", "-d", database, "-c", sql)


def inspect():
    assert os.geteuid() == 0 and capture("hostname") == "vps-32bea5b6"
    assert capture("systemctl", "is-active", "pink-iptv-backend") == "active"
    assert capture("systemctl", "is-active", "pink-vpn") == "active"
    names = pg("postgres", "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate").splitlines()
    selected = []
    for name in names:
        assert name and name.isidentifier()
        if pg(name, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='vpn_installations'") == "1":
            selected.append(name)
    assert len(selected) == 1
    raw = pg(selected[0], AGGREGATE_SQL).split("|")
    assert len(raw) == 8 and all(v.lstrip("-").isdigit() for v in raw)
    keys = ["accounts_with_active_leases", "accounts_at_five_or_more",
            "maximum_installs_one_account", "total_active_installs",
            "installs_in_full_accounts", "full_account_installs_expire_within_hour",
            "earliest_full_account_expiry_minutes", "latest_full_account_expiry_minutes"]
    counts = dict(zip(keys, (int(v) for v in raw)))
    now = int(time.time())
    peers = capture("wg", "show", "pinkvpn", "latest-handshakes").splitlines()
    recent = 0
    for line in peers:
        parts = line.split()
        assert len(parts) == 2 and parts[1].isdigit()
        last = int(parts[1])
        if 0 < last <= now and now-last <= 900:
            recent += 1
    print("PINK064_ANONYMOUS_LOCAL_DATABASE_READ_ONLY=PASS", flush=True)
    for name, value in counts.items():
        print("PINK064_" + name.upper() + "=" + str(value), flush=True)
    print("PINK064_WIREGUARD_PEERS_PRESENT=" + str(len(peers)), flush=True)
    print("PINK064_WIREGUARD_HANDSHAKES_LAST_15MIN=" + str(recent), flush=True)


if __name__ == "__main__":
    try:
        inspect()
    except Exception:
        print("PINK064_INSPECTION_FAILED_REDACTED", flush=True)
        raise SystemExit(1)
