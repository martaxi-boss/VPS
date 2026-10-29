# REA 6.8.0 original — Apktool preinstalled: real verification (2026-10-29)

## Certified result: 6/6 PASS, zero cleanup_incomplete

- Final GitHub Actions verification: https://github.com/martaxi-boss/VPS/actions/runs/40930862236 (job 123648595928, SUCCESS).
- First independent real run: https://github.com/martaxi-boss/VPS/actions/runs/40930609384 (job 123647712389, SUCCESS).
- Already installed launcher: /usr/bin/apktool, version **2.7.0-dirty**.
- Engine: untouched official morluto/rea REA 6.8.0, commit 160d821ac9a0310afcb8d1fc427862dd6508add5; preflight checks compiled SHA and dependency lock.
- Execution exclusively via existing pinned GitHub Actions -> SSH -> unprivileged ubuntu -> standalone official REA CLI.
- No old MCP, no new workflows, no service changes, no extra provider installations, no edits to other projects.
- Java: existing JDK 21 supplied per invocation only.
- Input: previously verified public Appium ApiDemos 6.0.18 APK, sha256 a9eecf37b26cd084855c530db81c2bb1b91f4c1b095a04f47aa7c20e2791f686, unchanged.

## Real verification matrix

| Operation | Result |
|---|---|
| Launch preinstalled Apktool and parse version | PASS |
| Official REA inspect-apktool-client, match launcher/version | PASS |
| Official REA decode-android-resources on a real APK: manifest, package, strings, decoded content, SHA-256 binding | PASS |
| Official REA decode-android-resources with real locale table-only projection | PASS |
| Process capture 8 subprocesses with complete cleanup | PASS |
| Process capture 30 subprocesses with complete cleanup | PASS |

Two runs: 6 PASS / 0 FAIL each and no cleanup_incomplete.

Test script: rea-linux/tests/rea_original_apktool_functional_20261029.py.
On-VPS evidence: /home/ubuntu/rea-original-upstream-680-evidence/apktool-original-20261029/ (per-operation complete CLI JSON, STDERR, summary, capture scenarios).

## Security scope

The preinstalled version **2.7.0-dirty** is functionally compatible (upstream accepts Apktool 2.7.0+). However it is older than 2.9.2, the upstream fix threshold for **CVE-2024-21633**. The original REA documentation (docs/apktool-resource-analysis.md) warns that distribution **backported fixes cannot be inferred from the version alone**. Therefore do not treat this verification as a security clearance for arbitrary/untrusted APKs; verify the Debian/Ubuntu package patches or use an authorized patched version before decoding untrusted material.

No software was updated or installed during the test.

## Root-cause interpretation

The old persistent MCP service was not exercised. The present CLI-only success supports a possible old transport/process lifecycle cause, but does **not** prove causal responsibility of the old MCP or definitively exclude another provider/environment condition.

All verification claims are scoped to the actual tested operations and inputs, not the complete REA tool catalog.
