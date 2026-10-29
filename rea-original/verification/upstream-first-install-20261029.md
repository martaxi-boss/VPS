# REA official upstream — first independent VPS installation (29 October 2026)

## Objective

Run the original public project as a separate project for diagnostics, without the existing MCP bridge and without modifying the previously deployed REA instance.

## Source and installation

- Official upstream: `morluto/rea`
- Pinned tag: `rea-agents-6.8.0`
- Exact Git commit: `160d821ac9a0310afcb8d1fc427862dd6508add5`
- Original source directory: `/home/ubuntu/rea-original-upstream-680`
- Evidence directory: `/home/ubuntu/rea-original-upstream-680-evidence`
- Independent compilation: `npm run build:cached` succeeded
- Node: existing 24.22.1 executable
- npm packages: existing `node_modules` were reused **only after exact official package-lock equality and npm installed-dependency lock verification**; no separate `npm ci` was required.
- No existing REA compiled engine modules, runtime patches, service, MCP endpoint or bridge were reused.
- Entry: official `scripts/rea.mjs capture-process` CLI, launched directly by GitHub Actions → pinned SSH.
- This experiment does not establish that all external providers are configured; provider readiness is a separate test.

## Successful real GitHub Actions execution

- Workflow run: https://github.com/martaxi-boss/VPS/actions/runs/40913611670
- Workflow implementation commit: `f0d52082179acc09fd49393cf6bd355c522bbb23`
- Outcome: `success`, `REA_ORIGINAL_ACCEPTANCE=PASS`, `REA_ORIGINAL_FAILED_CAPTURES=0`
- Clone: PASS, source commit match PASS, dependency lock verification PASS, official build PASS, version 6.8.0 PASS.
- Original compiled SHA-256 `dist/process/ProcessOwnership.js`: `2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852`
- Original compiled SHA-256 `dist/process/ProcessOwnershipObservation.js`: `81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655`

## Six native CLI capture tests

| Case | CLI exit | Cleanup | Settlement | Result |
|---|---:|---|---|---|
| 8 subprocesses, #1 | 0 | owned process group verified; temporary root removed | quiesced | PASS |
| 8 subprocesses, #2 | 0 | owned process group verified; temporary root removed | quiesced | PASS |
| 8 subprocesses, #3 | 0 | owned process group verified; temporary root removed | quiesced | PASS |
| 30 subprocesses, #1 | 0 | owned process group verified; temporary root removed | quiesced | PASS |
| 30 subprocesses, #2 | 0 | owned process group verified; temporary root removed | quiesced | PASS |
| 30 subprocesses, #3 | 0 | owned process group verified; temporary root removed | quiesced | PASS |

Each case launched /usr/bin/python3 invoking /usr/bin/true children. All returned error=none and exit code 0. Evidence JSON and stderr are retained in the independent VPS evidence directory.

## Interpretation and limitations

This demonstrates the upstream source, existing compatible dependencies and direct GitHub SSH execution can complete the initial real capture workload without `cleanup_incomplete`. It does **not** prove that the historical intermittent error can never occur, nor that the earlier MCP-path defect is definitely caused by a particular bridge. The independent test is CLI-only; provider-specific integrations and a long stress run have not yet been certified.

No changes to the existing deployed REA service or other project workloads were required.
