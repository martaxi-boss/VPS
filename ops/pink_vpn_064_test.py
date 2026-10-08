"""Task064 local regression: aggregate only, no account/peer identifiers output."""
import contextlib
import importlib.util
import io
from pathlib import Path


PATH = Path(__file__).with_name("pink_vpn_064_inspect.py")
spec = importlib.util.spec_from_file_location("pink064", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fake(*args):
    if args == ("hostname",):
        return "vps-32bea5b6"
    if args == ("systemctl", "is-active", "pink-iptv-backend"):
        return "active"
    if args == ("systemctl", "is-active", "pink-vpn"):
        return "active"
    if args[:3] == ("runuser", "-u", "postgres"):
        cmd = args[-1]
        if "FROM pg_database" in cmd:
            return "postgres\npink_iptv_private_db"
        if "information_schema.tables" in cmd:
            return "1" if args[-3] == "pink_iptv_private_db" else "0"
        if "WITH active AS" in cmd:
            return "1|1|5|5|5|0|95|140"
    if args[:3] == ("wg", "show", "pinkvpn"):
        return "secret-public-key-A 0\nsecret-public-key-B 100"
    raise AssertionError("Unexpected command")


def main():
    original_capture = module.capture
    original_uid = module.os.geteuid
    original_time = module.time.time
    try:
        module.capture = fake
        module.os.geteuid = lambda: 0
        module.time.time = lambda: 1000
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            module.inspect()
        output = capture.getvalue()
        assert "PINK064_ANONYMOUS_LOCAL_DATABASE_READ_ONLY=PASS" in output
        assert "PINK064_ACCOUNTS_AT_FIVE_OR_MORE=1" in output
        assert "PINK064_WIREGUARD_PEERS_PRESENT=2" in output
        assert "PINK064_WIREGUARD_HANDSHAKES_LAST_15MIN=1" in output
        assert "pink_iptv_private_db" not in output
        assert "secret-public-key" not in output
        assert "PASSWORD" not in output
        assert "runuser" not in output
        source = PATH.read_text()
        assert "DATABASE_URL" not in source and "/proc/" not in source
        assert "DELETE FROM" not in source and "UPDATE " not in source
        assert "psql" in source and "AGGREGATE_SQL" in source
        print("PINK064_AGGREGATE_PRIVACY_NO_DB_SECRETS=PASS")
    finally:
        module.capture = original_capture
        module.os.geteuid = original_uid
        module.time.time = original_time


if __name__ == "__main__":
    main()
