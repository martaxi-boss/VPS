"""Reuse only the exact source-CI artifact; no host effects or private inputs."""
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.request
import zipfile

SOURCE = "81728bde5a35b035140198d3817d9ef3a886912e"


def api(path):
    request = urllib.request.Request("https://api.github.com/repos/martaxi-boss/pink-iptv/" + path,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    if sys.argv[1] == "metadata":
        import time
        deadline = time.monotonic() + 1200
        while True:
            runs = api("actions/runs?head_sha=" + SOURCE + "&per_page=100")["workflow_runs"]
            exact = {}
            for name in ("PINK Extreme Android 042", "Backend CI"):
                matching = [r for r in runs if r["name"] == name and r["head_sha"] == SOURCE]
                if matching:
                    exact[name] = max(matching, key=lambda r: r["id"])
            if len(exact) == 2 and all(r["status"] == "completed" for r in exact.values()):
                assert all(r["conclusion"] == "success" for r in exact.values()), "Exact source CI failed"
                break
            assert time.monotonic() < deadline, "Exact source CI pending beyond bounded wait"
            time.sleep(20)
        run = exact["PINK Extreme Android 042"]
        assert api("git/ref/heads/builder/physical-ui-recovery-059")["object"]["sha"] == SOURCE
        artifacts = api("actions/runs/"+str(run["id"])+"/artifacts")["artifacts"]
        artifact, = [a for a in artifacts if a["name"] == "PINK-IPTV-Extreme-042" and not a["expired"]]
        assert artifact["workflow_run"]["head_sha"] == SOURCE
        assert artifact["digest"].startswith("sha256:")
        with open(os.environ["GITHUB_ENV"], "a") as env:
            env.write("PINK_DIRECT_RUN=" + str(run["id"]) + "\n")
            env.write("PINK_DIRECT_ARTIFACT=" + str(artifact["id"]) + "\n")
        print("EXACT_SOURCE_CI_ARTIFACT_METADATA=PASS;source="+SOURCE+";run="+str(run["id"])+";artifact="+str(artifact["id"])+";digest="+artifact["digest"])
        return
    assert sys.argv[1] == "files"
    root = Path(os.environ["RUNNER_TEMP"]) / "pink-deliverable"
    assert json.loads((root / "provenance.json").read_text())["implementation_sha"] == SOURCE
    expected = {"PINK-IPTV-Extreme-1.9.0-debug.apk", "PINK-IPTV-Extreme-instrumentation.apk", "PINK-IPTV-Extreme-source.tar.gz"}
    seen = set()
    for line in (root / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*")
        assert name in expected and name not in seen
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
        seen.add(name)
        print("EXACT_SOURCE_FILE_SHA256=" + name + ":" + digest)
    assert seen == expected
    with zipfile.ZipFile(root / "PINK-IPTV-Extreme-1.9.0-debug.apk") as apk:
        names = apk.namelist()
        for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
            assert "lib/" + abi + "/libwg-go.so" in names
        assert not any(n.endswith("/libwg.so") or n.endswith("/libwg-quick.so") for n in names)
    with zipfile.ZipFile(root / "PINK-IPTV-Extreme-instrumentation.apk") as apk:
        assert "classes.dex" in apk.namelist()
    print("EXACT_SOURCE_CI_APK_INSTRUMENTATION_CHECKSUMS_AND_PAYLOAD=PASS")


if __name__ == "__main__":
    main()
