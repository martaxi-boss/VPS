# REA original 6.8.0 — Inventario de programas externos (29 October 2026)

## Observed evidence
- GitHub Actions: https://github.com/martaxi-boss/VPS/actions/runs/40933509144 — SUCCESS.
- Official original: morluto/rea, rea-agents-6.8.0, commit 160d821ac9a0310afcb8d1fc427862dd6508add5; compiled hashes passed.
- Ubuntu Linux 24.04 x86_64, SSH as ubuntu, only official original REA CLI; old MCP unused.
- Audit: rea-linux/tests/rea_original_external_supplier_gap_audit_20261029.py.
- Detailed read-only JSON: /home/ubuntu/rea-original-upstream-680-evidence/external-supplier-gaps-20261029/summary.json (VPS).
- Zero new external suppliers installed on VPS; no service or source changes.

## Already installed; do not reinstall
19/19 primary existence/accessibility checks: Ghidra, JDK21, JADX jar, Unblob, Kuna, Wakaru, mitmdump/mitmproxy, Rizin, GDB, objdump, Binwalk executable, Apktool, ADB, TShark, Sigrok, FFmpeg, WABT wasm2wat, 7z, prlimit.
Also observed: GDB multiarch, radare2, Hopper executable, Cutter 2.5 AppImage, Chromium/Playwright, Frida Node binding.
Existence alone does not prove licensing, sessions, input compatibility or full operation certification.

## Missing only as optional additions
| Component | Current finding | Decision |
|---|---|---|
| ILSpyCmd | Not detected on ubuntu PATH/known locations | Free Linux-compatible optional C# reconstruction; not required for shipped managed parser |
| .NET runtime | Not detected | Install only if choosing ILSpyCmd; no mandatory need |
| pwndbg plugin & venv | Not detected | Free Linux-compatible optional deep core/crash analysis; not mandatory |
| Mono | Not detected | No installation indicated |
| Frida CLI | Not detected; Frida Node binding already present | Not needed by the REA Frida adapter |
| IDA | No executable/configuration found | Exclude due to license/GUI/upstream MCP constraints, given current user policy |
| JEB | No launcher/endpoint found | Exclude due to license/own MCP constraints |
| pwntools in default ubuntu Python | Not detected | Historical separate service interpreter had pwntools; check preexisting interpreter before installing |

## Present but not yet authorized/ready as sessions
Hopper launcher present but no proven license/demo analysis; Cutter installed but authenticated GUI v2 bridge unproven; Chromium installed without authorized CDP target; ADB/Frida device targets not established.

## Binwalk caveat
/usr/bin/binwalk is present, but the standalone version probe --version exited 3 under ubuntu; the official firmware REA requires the compatible 3.1.x version banner. This is a version/path/launch readiness uncertainty, not evidence that the supplier is absent. Verify configured candidate and a real original REA inspect-firmware-regions call before proposing reinstallation or certification.

## Conclusion
None of the 19 selected baseline external executable/package presence checks is missing. This DOES NOT certify all 229 tools. Only two free optional install families merit discussion if required by tasks: ILSpyCmd + .NET, pwndbg + venv. Do not install paid suppliers, new MCP endpoints, or macOS-only tools. Do not reinstall components already present. No changes to other projects.
