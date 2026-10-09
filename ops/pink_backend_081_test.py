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
    assert 'run("pg_restore", "--file=/dev/null"' in source
    assert "shutil.rmtree(APP" not in source
    assert 'state["added_app_py"]' in source
    assert "candidate.unlink()" in source

    # Prove a partial upgrade can be inverted without deleting the existing
    # app tree, old Alembic files or unrelated local resources.
    import json
    import os
    from types import SimpleNamespace

    with TemporaryDirectory() as directory:
        root = Path(directory)
        app = root / "backend"
        backup = root / "backup"
        (app / "app").mkdir(parents=True)
        (app / "alembic/versions").mkdir(parents=True)
        (backup / "old_app").mkdir(parents=True)
        (backup / "old_versions").mkdir(parents=True)
        (backup / "old_app/__init__.py").write_text("original = True\\n")
        (backup / "old_app/existing.py").write_text("ORIGINAL = 1\\n")
        (app / "app/__init__.py").write_text("original = False\\n")
        (app / "app/existing.py").write_text("UPDATED = 2\\n")
        (app / "app/new_module.py").write_text("NEW = True\\n")
        (app / "app/unrelated-resource.dat").write_bytes(b"preserved")
        (app / "alembic/versions/original.py").write_text("ORIGINAL = 1\\n")
        (backup / "old_versions/original.py").write_text("ORIGINAL = 1\\n")
        for name in q.MIGRATIONS:
            (app / "alembic/versions" / name).write_text("new migration\\n")
        (backup / "state.json").write_text(json.dumps({
            "database": "pink_fixture",
            "added_app_py": ["new_module.py"],
        }))
        original = {
            "APP": q.APP, "BACKUP": q.BACKUP, "OLD_TREE_SHA": q.OLD_TREE_SHA,
            "revision": q.revision, "healthy": q.healthy, "process_quota_ten": q.process_quota_ten,
            "run": q.run, "chown": q.os.chown, "getpwnam": q.pwd.getpwnam,
        }
        try:
            q.APP, q.BACKUP = app, backup
            (app / "app/__init__.py").write_text("original = True\\n")
            (app / "app/existing.py").write_text("ORIGINAL = 1\\n")
            (app / "app/new_module.py").unlink()
            q.OLD_TREE_SHA = q.app_tree_sha()
            (app / "app/existing.py").write_text("UPDATED = 2\\n")
            (app / "app/new_module.py").write_text("NEW = True\\n")
            q.revision = lambda _db: q.OLD_REV
            q.healthy = lambda: None
            q.process_quota_ten = lambda: True
            q.run = lambda *args, **kwargs: "OK"
            q.os.chown = lambda *_args: None
            q.pwd.getpwnam = lambda _name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            q.rollback()
            assert (app / "app/existing.py").read_text() == "ORIGINAL = 1\\n"
            assert not (app / "app/new_module.py").exists()
            assert (app / "app/unrelated-resource.dat").read_bytes() == b"preserved"
            assert (app / "alembic/versions/original.py").is_file()
            assert all(not (app / "alembic/versions" / n).exists() for n in q.MIGRATIONS)
            assert (backup / "rolled-back").is_file()
        finally:
            for k, v in original.items():
                if k == "chown":
                    q.os.chown = v
                elif k == "getpwnam":
                    q.pwd.getpwnam = v
                else:
                    setattr(q, k, v)

    print("PINK081_BACKUP_STREAM_AND_SELECTIVE_INVERSE_TEST=PASS")


if __name__ == "__main__":
    test()
