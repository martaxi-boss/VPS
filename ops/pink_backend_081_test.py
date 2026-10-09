"""No-VPS source scope, archive safety and rollback contract tests."""
from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import tarfile


def load():
    path = Path(__file__).with_name("pink_backend_081_rollout.py")
    spec = spec_from_file_location("pink081", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_archive(path, q, *, bad=None):
    files = {
        **{f"backend/app/module_{n}.py": b"pass\n" for n in range(8)},
        **{f"backend/alembic/versions/{name}": b"pass\n" for name in q.MIGRATIONS},
    }
    with tarfile.open(path, "w:gz") as bundle:
        for name, payload in sorted(files.items()):
            meta = tarfile.TarInfo(name)
            meta.size = len(payload)
            bundle.addfile(meta, BytesIO(payload))
        if bad:
            member = tarfile.TarInfo(bad)
            member.size = 0
            member.type = tarfile.SYMTYPE if "link" in bad else tarfile.REGTYPE
            member.linkname = "/etc/passwd"
            bundle.addfile(member, BytesIO())
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test():
    q = load()
    assert len(q.MIGRATIONS) == 4
    assert q.OLD_REV == "20261005_0002"
    assert q.NEW_REV == "20261009_0006"
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        good = root / "legitimate.tgz"
        sha = fixture_archive(good, q)
        source = q.safe_archive(good, sha, root / "unpacked")
        assert len(list((source / "app").glob("*.py"))) == 8
        assert {p.name for p in (source / "alembic/versions").glob("*.py")} == q.MIGRATIONS

        for index, name in enumerate(("../escape.py", "backend/app/badlink.py")):
            bad = root / f"malicious_{index}.tgz"
            bad_sha = fixture_archive(bad, q, bad=name)
            try:
                q.safe_archive(bad, bad_sha, root / f"rejected_{index}")
            except (AssertionError, ValueError):
                pass
            else:
                raise AssertionError("Malicious archive entry accepted")
        try:
            q.safe_archive(good, "0" * 64, root / "bad-digest")
        except AssertionError:
            pass
        else:
            raise AssertionError("Incorrect source archive SHA accepted")

    source = Path(__file__).with_name("pink_backend_081_rollout.py").read_text()
    assert "systemd-run" in source and "def rollback()" in source
    assert "pg_dump" in source and "pg_restore" in source
    assert "vpn_address_releases" in source
    assert "process_quota_ten()" in source
    assert "Cannot" not in source or "rollback" in source
    assert "wg set" not in source and "iptables -F" not in source
    assert "shutil.copytree(BACKUP" in source
    print("PINK081_SOURCE_PACKAGING_ROLLBACK_AND_MIGRATION_LOCAL_TEST=PASS")


if __name__ == "__main__":
    test()
