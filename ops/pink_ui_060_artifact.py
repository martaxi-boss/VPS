"""Reuse exact current APK/instrumentation after authorization-metadata Recovery."""
import json
import os
from pathlib import Path
import socket
import sys
import urllib.request
import zipfile

SOURCE = "6e0537634a40619f331268c4c7f7bdefd15231ce"
PREP = "2e26eb0ceca31026be7d8001638066046a84f3a3"
RUN = 37441906746
ARTIFACT = 11401693691
DIGEST = "sha256:660c8b887eb6704b825b80634e67b9fb4f3c02a5e92ba11494f291238989225f"


def api(repo, path):
    request = urllib.request.Request("https://api.github.com/repos/" + repo + "/" + path,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    if sys.argv[1] == "metadata":
        run = api("martaxi-boss/VPS", "actions/runs/" + str(RUN))
        assert run["head_sha"] == PREP and run["conclusion"] == "success"
        assert run["name"] == "PINK actual UI proof 060"
        artifact = api("martaxi-boss/VPS", "actions/artifacts/" + str(ARTIFACT))
        assert artifact["name"] == "PINK-IPTV-Extreme-060" and not artifact["expired"]
        assert artifact["digest"] == DIGEST and artifact["workflow_run"]["id"] == RUN
        assert artifact["workflow_run"]["head_sha"] == PREP
        assert api("martaxi-boss/pink-iptv", "git/ref/heads/builder/physical-ui-recovery-059")["object"]["sha"] == SOURCE
        runs = api("martaxi-boss/pink-iptv", "actions/runs?head_sha=" + SOURCE + "&per_page=100")["workflow_runs"]
        for name in ("PINK Extreme Android 042", "Backend CI"):
            relevant = [r for r in runs if r["name"] == name]
            assert relevant and all(r["head_sha"] == SOURCE and r["status"] == "completed"
                                    and r["conclusion"] == "success" for r in relevant)
        print("EXACT_INITIAL_APK_ARTIFACT_SOURCE_CI_REUSE_AUTHENTICATED=PASS")
        return
    assert sys.argv[1] == "files"
    root = Path(os.environ["RUNNER_TEMP"]) / "pink056-artifact"
    assert json.loads((root / "provenance.json").read_text())["implementation_sha"] == SOURCE
    with zipfile.ZipFile(root / "PINK-IPTV-Extreme-1.9.0-debug.apk") as apk:
        names = apk.namelist()
        for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
            assert "lib/" + abi + "/libwg-go.so" in names
        assert not any(n.endswith("/libwg.so") or n.endswith("/libwg-quick.so") for n in names)
    with zipfile.ZipFile(root / "PINK-IPTV-Extreme-instrumentation.apk") as apk:
        assert "classes.dex" in apk.namelist()
    addresses = socket.getaddrinfo("pink-iptv.duckdns.org", 443, family=socket.AF_INET)
    assert any(item[4][0] == "146.59.145.3" for item in addresses)
    print("RUNNER_FIXED_CONTROL_DNS_EXPECTED_TARGET=PASS")
    print("EXACT_INITIAL_APK_SOURCE_INSTRUMENTATION_UNCHANGED=PASS")


if __name__ == "__main__":
    main()
