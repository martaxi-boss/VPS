"""Narrowly pin the already successful official emulator acquisition path."""
import argparse
import hashlib
from pathlib import Path
import subprocess

RUNNER_REVISION = "1dcd0090116d15e7c562f8db72807de5e036a4ed"
INSTALLER_SHA256 = "6dcdca7083c61ac812f023d6e7e99d3599c52ceb18cccc79850411beaf095538"
EMULATOR_BUILD = "16428233"  # Exact37.2.12.0 binary in successful R16.


def pinned_installer(original):
    if hashlib.sha256(original).hexdigest() != INSTALLER_SHA256:
        raise ValueError("Official pinned runner installer drift")
    source = original.decode("utf-8")
    lines = source.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines)
               if "yield exec.exec(" in line and "sdkmanager --install emulator --channel=" in line]
    if len(matches) != 1:
        raise ValueError("Mutable emulator acquisition boundary unavailable")
    index = matches[0]
    # The official action applies emulator-build only AFTER downloading latest.
    # Skip that preceding mutable download; preserve its fixed Google HTTPS
    # build URL, curl failure handling, ZIP extraction and all SDK/AVD/test logic.
    lines[index] = "            if (emulatorBuild !== '" + EMULATOR_BUILD + "') throw new Error('Pinned emulator build required');\n"
    result = "".join(lines).replace("Installing latest emulator.", "Installing exact certified emulator build.")
    assert "sdkmanager --install emulator --channel=" not in result
    assert "https://dl.google.com/android/repository/emulator-" in result
    assert "unzip -o -q emulator.zip" in result
    return result.encode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("runner", type=Path)
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "-C", str(args.runner), "rev-parse", "HEAD"], text=True).strip()
    if revision != RUNNER_REVISION:
        raise ValueError("Official emulator runner revision mismatch")
    installer = args.runner / "lib/sdk-installer.js"
    installer.write_bytes(pinned_installer(installer.read_bytes()))
    print("EXACT_CERTIFIED_EMULATOR_ACQUISITION_PATCH=PASS;build=" + EMULATOR_BUILD)


if __name__ == "__main__":
    main()
