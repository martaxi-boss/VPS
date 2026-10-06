"""Reuse only the exact source-CI artifact; no host effects or private inputs."""
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.request
import zipfile

SOURCE = "632a805591e0df5f9e950ac748cea2658193301f"
RUN = 37523839126
ARTIFACT = 11442635716
DIGEST = "sha256:8c7ff54eda7250c18d8bbba74f391358862a6640200b4517111463448863cf17"


def api(path):
    request = urllib.request.Request("https://api.github.com/repos/martaxi-boss/pink-iptv/" + path,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    if sys.argv[1] == "metadata":
        run = api("actions/runs/" + str(RUN))
        assert run["head_sha"] == SOURCE and run["conclusion"] == "success"
        assert run["name"] == "PINK Extreme Android 042"
        assert api("git/ref/heads/builder/physical-ui-recovery-059")["object"]["sha"] == SOURCE
        runs = api("actions/runs?head_sha=" + SOURCE + "&per_page=100")["workflow_runs"]
        for name in ("PINK Extreme Android 042", "Backend CI"):
            relevant = [r for r in runs if r["name"] == name]
            assert relevant and all(r["status"] == "completed" and r["conclusion"] == "success" for r in relevant)
        artifact = api("actions/artifacts/" + str(ARTIFACT))
        assert artifact["name"] == "PINK-IPTV-Extreme-042" and not artifact["expired"]
        assert artifact["digest"] == DIGEST and artifact["workflow_run"]["id"] == RUN
        assert artifact["workflow_run"]["head_sha"] == SOURCE
        with open(os.environ["GITHUB_ENV"], "a") as env:
            env.write("PINK060_SOURCE_RUN=" + str(RUN) + "\n")
            env.write("PINK060_SOURCE_ARTIFACT=" + str(ARTIFACT) + "\n")
        print("EXACT_SOURCE_CI_ARTIFACT_METADATA=PASS")
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
