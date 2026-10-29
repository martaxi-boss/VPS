# REA original 6.8.0 — optional Ubuntu suppliers installed and functionally accepted (2026-10-29)

## Final state: PASS (both optional supplier families, real tests, zero cleanup_incomplete)

**Successful proof runs:**
- Original Ubuntu readiness, space, repository, sudo and GDB Python 3.12 preflight: https://github.com/martaxi-boss/VPS/actions/runs/40935476920 (SUCCESS).
- Official Ubuntu dotnet-sdk-10.0 and isolated ILSpyCmd 11.2.0.10050 install plus real C# decompilation: https://github.com/martaxi-boss/VPS/actions/runs/40935937235 (SUCCESS).
- Isolated pwndbg 2026.09.15 installation from pinned upstream Git commit 55596aa676a2756efb8d67034f31675170eabe48 with real GDB 15.1 plugin load and ELF inspection: https://github.com/martaxi-boss/VPS/actions/runs/40936431917 (SUCCESS).
- Separate isolated pwntools 4.15.0, the exact version required by REA's recorded-core adapter: https://github.com/martaxi-boss/VPS/actions/runs/40937469940 (SUCCESS).
- **Final real original REA CLI acceptance** with a generated controlled Linux ELF core, pwndbg debug context, fresh ILSpy decompilation, and 8 + 30 post-supplier subprocess cleanup tests: https://github.com/martaxi-boss/VPS/actions/runs/40937637409 (SUCCESS; job 123672301044).

## Programs added only for point 1

| Component | Version / selected path | Result |
|---|---|---|
| .NET SDK and runtime | Ubuntu official dotnet-sdk-10.0 from noble-updates/noble-security, /usr/bin/dotnet | Installed, SDK 10 PASS, no apt upgrades/removals |
| ILSpyCmd | 11.2.0.10050, /home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0/ilspycmd | PASS decompiling a compiled real C# library; REA original managed inspection also PASS |
| pwndbg | 2026.09.15, Git SHA 55596aa676a2756efb8d67034f31675170eabe48, isolated uv tool venv | PASS GDB plugin import, actual ELF inspection, and original REA recorded core adapter |
| pwntools | 4.15.0, /home/ubuntu/.local/share/rea-optional-pwntools-4.15.0/bin/python | PASS. Separate from the Pwndbg venv to preserve its working dependencies |
| uv bootstrap (installation helper) | 0.13.6, isolated /home/ubuntu/.local/share/rea-optional-uv-0.13.6/bin/uv | PASS; not exposed as another REA tool |

### Integration paths for *future* original REA CLI invocations

Set the following variables **on each invocation** (no global service changes):

```sh
export REA_ILSPY_CMD_PATH=/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0/ilspycmd
export REA_PWNDBG_GDB=/usr/bin/gdb
export REA_PWNDBG_GDBINIT=/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15/tools/pwndbg/share/pwndbg/gdbinit.py
export REA_PWNDBG_VENV_PATH=/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15/tools/pwndbg
export REA_PWNTOOLS_PYTHON=/home/ubuntu/.local/share/rea-optional-pwntools-4.15.0/bin/python
```

Do not automatically source these exports in the legacy REA service or in other users' profiles. The official REA metadata parser already works without ILSpy, but ILSpy provides a real optional reconstruction oracle.

## End-to-end test of the original official REA

- REA source remains pinned to upstream morluto/rea rea-agents-6.8.0, commit 160d821ac9a0310afcb8d1fc427862dd6508add5.
- C# controlled library was built in evidence directory and decompiled by the installed ILSpy; expected answer 42 recovered.
- Source-owned Linux C fixture compiled under GDB, generating a real ELF ET_CORE without changing kernel core settings.
- `rea inspect-recorded-crash <real-core> --debugger-context --json` returned PASS; actual `debugger.pwndbg_version` = 2026.09.15 and `connection=core`.
- `rea capture-process` with 8 children, then 30 children: both PASS, owned group and temporary root cleaned.
- **cleanup_incomplete = 0** across the final acceptance tests.
- Original REA code, compiled owner hashes, original services, previous MCP transport, other projects: **not changed**.
- No new MCP, plugins, skills, workflow file, provider duplicates or additions to the 229-tool catalog.
- The existing workflow `.github/workflows/rea-mcp-transport-20261027.yml` had its test target changed in place; its existing SSH pin/authentication/host verified and reused.

## Why two Python environments?

The Pwndbg 2026.09.15 package's own compatible dependency resolver selected pwntools 4.14.1, while the official REA recorded core adapter **requires 4.15.0 exactly**. Replacing the dependency inside the working Pwndbg venv risked a regression. The correction was a separate REA-owned `REA_PWNTOOLS_PYTHON` 4.15.0 venv, independently verified by a real original CLI core-dump analysis. Intermediate incomplete test runs were retained as diagnostic evidence, but the final run is SUCCESS.

## Preserved on VPS

`/home/ubuntu/rea-original-upstream-680-evidence/optional-free-suppliers-20261029/`

- `preflight.json`, `ilspy-install-result.json`, `pwndbg-install-result.json`, `pwntools-install-result.json`, `final-acceptance.json`
- CLI and GDB stdout/stderr, inert controlled fixtures, source- and output-identities.

Scripts under VPS branch: `rea-linux/install/rea_original_optional_free_suppliers_20261029.py` and `rea-linux/tests/rea_original_optional_free_supplier_acceptance_20261029.py`.

**Scope:** point 1 (missing free optional Ubuntu programs/dependencies) completed. Existing Binwalk PATH/version readiness or GUI/device/session-dependent suppliers remain separate questions, not installations in point 1.
