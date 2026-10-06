"""Transfer an existing certified APK without building or touching the host."""
import hashlib
import io
import json
import os
from pathlib import Path
import urllib.request
import zipfile

SOURCE = "9e1fc82c9c964a079d876671990a41a73689955e"
PREP = 37393882520
PROOF = 37395113639
ARTIFACT = 11382109825
ARCHIVE_DIGEST = "aa49b10f8033f74576d7582cd10094c0d3ef246c155b668338ccb403f0ba2fd5"


def request(path):
    return urllib.request.Request(
        "https://api.github.com/repos/martaxi-boss/" + path,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json"},
    )


def get(path):
    with urllib.request.urlopen(request(path), timeout=60) as response:
        return json.load(response)


def main():
    for repo, run_id, sha in [
        ("VPS", PREP, "97cdb724d7892a71460ee1cda046e99012bd60b7"),
        ("VPS", PROOF, "8835c74a66aa21b1956e632c76f1acd389de6928"),
        ("VPS", 37395786647, "cda18ad29c80caadf9a07d45f8036d0f9f49de22"),
        ("pink-iptv", 37393208549, SOURCE),
        ("pink-iptv", 37393208560, SOURCE),
    ]:
        run = get(f"{repo}/actions/runs/{run_id}")
        assert run["head_sha"] == sha
        assert run["status"] == "completed" and run["conclusion"] == "success"
    artifact = get(f"VPS/actions/artifacts/{ARTIFACT}")
    assert artifact["name"] == "PINK-IPTV-Extreme-056" and not artifact["expired"]
    assert artifact["workflow_run"]["id"] == PREP
    assert artifact["digest"] == "sha256:" + ARCHIVE_DIGEST
    with urllib.request.urlopen(request(f"VPS/actions/artifacts/{ARTIFACT}/zip"),
                                timeout=120) as response:
        archive_bytes = response.read()
    assert hashlib.sha256(archive_bytes).hexdigest() == ARCHIVE_DIGEST
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        provenance = json.loads(archive.read("provenance.json"))
        assert provenance["implementation_sha"] == SOURCE
        sums = dict(line.split()[::-1] for line in
                    archive.read("SHA256SUMS").decode().splitlines())
        original_name = "PINK-IPTV-Extreme-1.9.0-debug.apk"
        apk = archive.read(original_name)
    digest = hashlib.sha256(apk).hexdigest()
    assert sums[original_name] == digest
    output = Path(os.environ["PINK_OUTPUT"])
    output.mkdir(parents=True, exist_ok=True)
    part_size = 24 * 1024 * 1024
    parts = []
    for offset in range(0, len(apk), part_size):
        chunk = apk[offset:offset + part_size]
        name = f"part-{len(parts):02d}"
        (output / name).write_bytes(chunk)
        parts.append({"name": name, "size": len(chunk),
                      "sha256": hashlib.sha256(chunk).hexdigest()})
    assert 0 < len(parts) <= 16
    joined = b"".join((output / part["name"]).read_bytes() for part in parts)
    assert joined == apk and hashlib.sha256(joined).hexdigest() == digest
    manifest = {
        "filename": "PINK-IPTV-Extreme-9e1fc82c.apk",
        "original_filename": original_name,
        "size": len(apk), "sha256": digest, "source": SOURCE,
        "preparation_run": PREP, "real_proof_run": PROOF,
        "artifact_id": ARTIFACT, "artifact_sha256": ARCHIVE_DIGEST,
        "parts": parts,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as state:
        state.write("part_count=" + str(len(parts)) + "\n")
    print("EXACT_SUCCESSFUL_PROVENANCE_AND_ARCHIVE_DIGEST=PASS")
    print("EXACT_CERTIFIED_APK_COPY_AND_ROUNDTRIP=PASS")
    print("NO_HOST_ACCESS_OR_SECRET_FIXTURE=PASS")
    print("APK_SHA256=" + digest)
    print("APK_BYTES=" + str(len(apk)))


if __name__ == "__main__":
    main()
