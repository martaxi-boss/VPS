"""Local no-SSH tests for quota-only exact inverse content rules."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json


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
    assert "PINK078_PHASE=ROLLBACK_TIMER_ARMED" in source
    assert "PINK078_PHASE=BACKEND_API_HEALTHY" in source
    assert "pg_restore" not in source and "wg set" not in source

    # Actual backend service restarts can precede HTTP readiness. A short,
    # bounded retry is necessary, but permanent failure must still fail closed.
    original_run = q.subprocess.run
    original_sleep = q.time.sleep
    try:
        calls = [0]
        def simulated_run(args, **_kwargs):
            if args[0] == "systemctl":
                return SimpleNamespace(stdout="active", returncode=0)
            calls[0] += 1
            return SimpleNamespace(stdout="503" if calls[0] == 1 else "200",
                                   returncode=0)
        q.subprocess.run = simulated_run
        q.time.sleep = lambda _delay: None
        q.healthy()
        assert calls[0] == 2

        def always_failing(args, **_kwargs):
            if args[0] == "systemctl":
                return SimpleNamespace(stdout="active", returncode=0)
            return SimpleNamespace(stdout="503", returncode=0)
        q.subprocess.run = always_failing
        try:
            q.healthy()
        except RuntimeError:
            pass
        else:
            raise AssertionError("Permanent backend unhealthy accepted")
    finally:
        q.subprocess.run = original_run
        q.time.sleep = original_sleep

    # Previous failed attempt may only be archived, not overwritten or deleted,
    # after the old environment is proven restored and rollback timer inactive.
    with TemporaryDirectory() as directory:
        root = Path(directory)
        q.BACKUP = root / "task078"
        q.ENV = root / "vpn.env"
        q.ENV.write_bytes(b"VPN_ENABLED=true\\n")
        q.BACKUP.mkdir(mode=0o700)
        (q.BACKUP / "baseline").write_bytes(q.ENV.read_bytes())
        (q.BACKUP / "state.json").write_text(json.dumps({
            "original_sha256": q.digest(q.ENV.read_bytes()),
            "new_sha256": q.digest(q.desired(q.ENV.read_bytes())),
        }))
        (q.BACKUP / "quota.py").write_text("fixture previous attempt")
        q.healthy = lambda: None
        q.subprocess.run = lambda _args, **_kwargs: SimpleNamespace(stdout="inactive")
        try:
            q.archive_aborted_attempt(preserve_only=True)
            assert q.BACKUP.exists()
            assert q.ENV.read_bytes() == b"VPN_ENABLED=true\\n"
            q.archive_aborted_attempt()
        finally:
            q.subprocess.run = original_run
        assert not q.BACKUP.exists()
        archived = list(root.glob("task078-aborted-*"))
        assert len(archived) == 1
        assert (archived[0] / "baseline").read_bytes() == q.ENV.read_bytes()
        assert (archived[0] / "quota.py").read_text() == "fixture previous attempt"
        assert q.ENV.read_bytes() == b"VPN_ENABLED=true\\n"

    print("PINK078_QUOTA_APPEND_INVERSE_AND_STARTUP_RECOVERY=PASS")


if __name__ == "__main__":
    test()
