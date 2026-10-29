# REA original — historical cleanup failure replay (29 Oct 2026)

## Scope and invariant

Reproduce the known failing **process capture and cleanup** scenario families on the *untouched official original* `morluto/rea` tag `rea-agents-6.8.0` at exact source commit `160d821ac9a0310afcb8d1fc427862dd6508add5`, using **GitHub Actions -> pinned SSH -> original CLI**.

- Main job: https://github.com/martaxi-boss/VPS/actions/runs/40917230549
- Original CLI checkout: `/home/ubuntu/rea-original-upstream-680`
- Private evidence files: `/home/ubuntu/rea-original-upstream-680-evidence/historical-replay-20261029/`
- Test script: `rea-linux/tests/rea_original_historical_failure_replay_20261029.py`
- Workflow commit (the tested code): `39deaea3f33160e8242e3b1dc197cb0388ef67a6`
- User/account: unprivileged `ubuntu`; the previous MCP runtime operated as `root`. Do **not** claim user-identity/environment equivalence.
- No vendor/provider installation; no npm package install; existing Node and original-lock-compatible Node modules reused; original compiled modules verified byte-for-byte against prior clean build.
- No MCP connection, service restart, service change or modification to other projects.

## Real execution result

**88/88 capture checks passed**, **0 failed**, **0 `cleanup_incomplete`**.

The script checks for every capture: CLI return code 0, valid Evidence, expected normal/abnormal exit or signal/timeout, `normalized_result.cleanup.owned_process_group` verified, `normalized_result.cleanup.temporary_root` removed, and absence of `cleanup_incomplete` in both stdout and stderr. The full Evidence output is retained under the path above.

| Historical scenario profile / reproduction class | Cases | Cleanup verdict |
|---|---:|---|
| `/bin/true` and `/usr/bin/true` default window | 12 | 12 PASS |
| `/usr/bin/false` and `/usr/bin/printf` | 6 | 6 PASS |
| 8 short-lived subprocesses, default window | 16 | 16 PASS |
| 30 short-lived subprocesses, default window | 20 | 20 PASS |
| 12 short-lived subprocesses | 4 | 4 PASS |
| Nested subprocess, individual Python child, stdout/stderr, environment | 8 | 8 PASS |
| Non-zero exit, forced timeout, idle timeout | 6 | 6 PASS |
| SIGTERM, SIGKILL, terminal resize | 6 | 6 PASS |
| 8/30 subprocesses with explicit `settle_ms=800` | 4 | 4 PASS |
| Independent two-way parallel captures of 30 subprocesses | 6 | 6 PASS |
| **Total** | **88** | **88 PASS** |

### Important settlement nuance

Among the **82 sequential runs** with a printed settlement state, **81 were `quiesced`** and **one**, `children-30-09`, was `unverifiable`, although its owned-process group and temporary-root cleanup were both reported verified/removed and no cleanup error occurred. The 6 parallel cases printed PASS but did not print the settlement state in their one-line logs; the Evidence documents remain saved on the VPS.

**This is not proof of full pre-cleanup quiescence in all cases.** It is also **not equivalent to `cleanup_incomplete`**. The earlier system had `settlement=unverifiable` for some default-window scenarios, which motivates recording the distinction.

## Comparison with the previous failing environment

The earlier installed REA integration repeatedly returned `cleanup_incomplete` and `environment_errno_ESRCH` for Linux `kworker` processes after 8/30 child captures. The current original CLI replay did not reproduce that code within 88 executions.

The known command families and default/extended observation profiles were reconstructed from existing historical reports. **Not all literal historical MCP request argument objects were retained**, and the new path is CLI as the unprivileged `ubuntu` user, whereas the old service was a persistent **root** MCP. The results establish clean behavior for these original-CLI tests, but do **not** isolate a single cause such as the MCP bridge, persistent service state, root vs ubuntu environment, or compiled modifications. A true one-variable-at-a-time comparison requires controlling these remaining differences.

No claim of all 229 original tools being fully certified or all external suppliers being functionally available is made from these capture checks.

## Bottom line

**Original CLI cleanup regression: PASS (88/88), no `cleanup_incomplete` observed, one non-quiesced verification window.** Original engine source and pre-existing providers unchanged. Evidence: [GitHub Actions run 40917230549](https://github.com/martaxi-boss/VPS/actions/runs/40917230549).
