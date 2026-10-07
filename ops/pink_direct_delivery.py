"""Copy only the already tested APK; no build, host access or account fixture."""
import hashlib
import json
import os
from pathlib import Path
from pink_direct_artifact import SOURCE, main as verify_files


def main():
    import sys
    sys.argv = [sys.argv[0], "files"]
    verify_files()
    root = Path(os.environ["RUNNER_TEMP"])
    original = root / "pink-deliverable/PINK-IPTV-Extreme-1.9.0-debug.apk"
    apk = original.read_bytes()
    digest = hashlib.sha256(apk).hexdigest()
    output = root / "pink-direct-delivery"
    output.mkdir()
    filename = "PINK-IPTV-" + SOURCE[:8] + ".apk"
    (output / filename).write_bytes(apk)
    parts = []
    size = 24 * 1024 * 1024
    for offset in range(0, len(apk), size):
        chunk = apk[offset:offset + size]
        name = f"part-{len(parts):02d}"
        (output / name).write_bytes(chunk)
        parts.append({"name": name, "size": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest()})
    assert 0 < len(parts) <= 16
    assert hashlib.sha256(b"".join((output / part["name"]).read_bytes() for part in parts)).hexdigest() == digest
    manifest = {"filename": filename, "source": SOURCE, "size": len(apk), "sha256": digest,
                "source_ci_run": int(os.environ["PINK_DIRECT_RUN"]),
                "source_artifact_id": int(os.environ["PINK_DIRECT_ARTIFACT"]),
                "real_proof_run": int(os.environ["GITHUB_RUN_ID"]), "parts": parts}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as handle:
        handle.write("part_count=" + str(len(parts)) + "\n")
    print("EXACT_TESTED_APK_DELIVERY_COPY=PASS;source=" + SOURCE + ";sha256=" + digest)


if __name__ == "__main__":
    main()
