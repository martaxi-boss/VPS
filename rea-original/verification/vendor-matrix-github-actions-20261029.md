# REA official original — existing suppliers through GitHub Actions (2026-10-29)

## Decision and architecture

The only approved command path is **GitHub Actions -> pinned SSH -> unprivileged Ubuntu -> original REA CLI**. No connection to the prior Google/MCP bridge, no new MCP, no provider installation and no mutation/restart of the prior MCP service. Deleting the old bridge has **not** been executed as part of this reversible investigation.

The original engine remains the pristine public checkout `morluto/rea` tag `rea-agents-6.8.0`, commit `160d821ac9a0310afcb8d1fc427862dd6508add5`. The original compiled modules and reuse of existing compatible Node dependencies were verified before every test. Provider paths were passed only in the test process environment; no old engine settings were copied.

### Source and evidence

- Source code of the probe: `rea-linux/tests/rea_original_existing_vendors_matrix_20261029.py`
- Existing GitHub SSH workflow: `.github/workflows/rea-mcp-transport-20261027.yml` — legacy filename, **actual implementation does not invoke the old MCP**.
- First complete success: https://github.com/martaxi-boss/VPS/actions/runs/40922347893
- Additional installed-file discovery success: https://github.com/martaxi-boss/VPS/actions/runs/40923129893
- Initial test-harness error (not an REA failure): https://github.com/martaxi-boss/VPS/actions/runs/40921713852 — corrected and verified on subsequent runs.
- Private individual CLI JSON, stderr, original-source checks and provider observations: `/home/ubuntu/rea-original-upstream-680-evidence/vendor-matrix-20261029`

## Positive and negative results

Both successful runs logged:

- `REA_VENDOR_MATRIX_ORIGINAL_SOURCE=PINNED_UNMODIFIED`
- `REA_VENDOR_MATRIX_EXISTING_DEPENDENCIES=VERIFIED_REUSED`
- `REA_VENDOR_MATRIX_EXTERNAL_INSTALLS=0`
- `REA_VENDOR_MATRIX_OLD_MCP_CONNECTION=NOT_USED`
- `REA_VENDOR_MATRIX_CAPTURE_PASS=30`, `REA_VENDOR_MATRIX_CAPTURE_FAIL=0`
- `REA_VENDOR_MATRIX_CLEANUP_INCOMPLETE=0`
- `REA_VENDOR_MATRIX_TOOL_FAMILY_TESTS=3`, `REA_VENDOR_MATRIX_TOOL_FAMILY_FAIL=0`
- `REA_VENDOR_MATRIX_OUTCOME=PASS`.

The 30 real process captures are 14 CLI baseline captures (6x8 and 8x30 short-lived children), 14 with existing provider executable paths exposed by process-local environment, and 2 parallel captures. Cleanup owned group and temporary root were both verified; no `cleanup_incomplete` occurred. One case in the **initial test-harness-failure run** reported settlement `unverifiable` with cleanup verified, not a cleanup failure; do not erase this distinction.

### Original supplier observations

| Supplier | Existing executable/file observed by unprivileged ubuntu | Original doctor / real operation | Decision |
|---|---|---|---|
| Kuna | YES | Doctor exit 0, healthy; **real CLI analysis of /usr/bin/true PASS** | Usable in tested original CLI scope |
| Wakaru | YES | No individual tool invocation | Discovery only |
| mitmdump/mitmproxy | YES | No network interception invoked | Discovery only |
| Chromium/Playwright browser | YES | No live CDP target used | Discovery only |
| Rizin, radare2, GDB | YES | No provider-specific operation exercised in this batch | Discovery only |
| Apktool, ADB, Binwalk, TShark, Sigrok | YES | No device or tool-specific operation exercised | Discovery only |
| WABT, Java, ffmpeg, objdump | YES | No tool-specific operation exercised | Discovery only |
| Ghidra | NO verified installation root in bounded local provider scan | Doctor exit 1, healthy=false; analysis not attempted | Needs standalone-user installation-path/permission resolution, **not** proof absent from VPS |
| JADX headless JAR 0.7.1 | NO accessible official JAR found in bounded local provider scan | Doctor exit 1, healthy=false | Needs approved absolute `REA_JADX_MCP_JAR` path if existing, **not** a package install |
| Hopper | Launcher previously reported installed | Doctor exit 1, healthy=false; no license-specific action | Not certified usable under isolated original process |
| Unblob | Not found in the isolated tested paths | Not exercised | Inventory incomplete for this user context |
| IDA / JEB | Previously staged optional integrations, license/endpoint not fully active | Not started; no license or MCP bridge activated | Remain excluded |

The following previously certified operation families were **retested in the original** with real source-owned inputs:

1. `inspect-elf-notes /usr/bin/true --json` — PASS.
2. `inspect-artifact /usr/bin/true --json` — PASS.
3. `analyze /usr/bin/true --provider kuna --json` — PASS.

**The previous 170 scoped certifications are not imported into the original.** Those names are a useful checklist; the old evidence does not certify the new original environment, and many tools are MCP-only rather than available through a standalone CLI command.

## Interpretation

With this direct GitHub SSH architecture, simply exposing the suppliers already accessible to the `ubuntu` original CLI did **not** reproduce `cleanup_incomplete`. This does not establish that the historical Google MCP connector or any particular old bridge is the cause: the old integration was a persistent root-running MCP and the current experiment is a fresh CLI under `ubuntu`, so multiple variables remain different.

The old bridge/service was intentionally **not removed** in this diagnostic test. Its removal is a separate consequential change requiring ensuring it has no remaining dependents; no existing project or vendor installation was deleted.
