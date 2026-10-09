"""Local no-SSH tests for quota-only exact inverse content rules."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


def load():
    p = Path(__file__).with_name("pink_vpn_078_quota.py")
    spec = spec_from_file_location("pink_vpn_078_quota", p)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test() -> None:
    q = load()
    assert q.desired(b"VPN_ENABLED=true\n") == (
        b"VPN_ENABLED=true\nVPN_MAX_INSTALLATIONS_PER_ACCOUNT=10\n"
    )
    assert q.desired(b"VPN_ENABLED=true") == (
        b"VPN_ENABLED=true\nVPN_MAX_INSTALLATIONS_PER_ACCOUNT=10\n"
    )
    assert q.desired(b"") == b"VPN_MAX_INSTALLATIONS_PER_ACCOUNT=10\n"
    for content in (
        b"VPN_MAX_INSTALLATIONS_PER_ACCOUNT=5\n",
        b"  VPN_MAX_INSTALLATIONS_PER_ACCOUNT=10\n",
        b"VPN_ENABLED=true\x00\n",
        b"A" * 100001,
    ):
        try:
            q.desired(content)
        except AssertionError:
            pass
        else:
            raise AssertionError("Unsafe env candidate accepted")
    source = Path(__file__).with_name("pink_vpn_078_quota.py").read_text()
    assert 'BACKUP / "baseline"' in source
    assert 'on-active=8m' in source
    assert 'def rollback()' in source and 'def verify()' in source
    assert 'process_has_expected_quota()' in source
    assert 'run("systemctl", "restart", UNIT)' in source
    assert "pg_restore" not in source and "wg set" not in source
    print("PINK078_QUOTA_APPEND_AND_INVERSE_LOCAL_TEST=PASS")


if __name__ == "__main__":
    test()
