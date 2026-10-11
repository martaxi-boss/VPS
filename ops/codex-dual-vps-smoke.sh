#!/usr/bin/env bash
# One-time, explicitly Owner-triggered test of the security-reviewed two-Codex
# executor in a disposable VPS checkout. No installation, push or deployment.
set -Eeuo pipefail
umask 077

if [ "$#" -ne 1 ] || ! [[ "$1" =~ ^[0-9]+-[0-9]+-dual$ ]]; then
  echo "Invalid trusted smoke job identifier" >&2
  exit 2
fi

job="$1"
base="$HOME/codex-bridge/jobs/$job"
proof="$base/proof.json"
expected="364ade7ca0e5bca1e788d04cad8bbe071cd22f88"
source="$base/source"
runs="$base/runs"
codex_cli="$HOME/codex-agent/node_modules/.bin/codex"
budget_root="$HOME/codex-bridge/.account-budget"
budget_policy="$base/codex_resource_policy.py"
budget_job_base="${job%-dual}"

test -d "$base" || exit 2
printf '{"status":"PREPARING","reason":"preflight_pending"}\n' > "$proof"

blocked() {
  # Fixed reason codes only: no model output, secrets or raw terminal logs.
  printf '{"status":"BLOCKED","reason":"%s"}\n' "$1" > "$proof"
  echo "CODEX_DUAL_SMOKE_BLOCKED: $1" >&2
  exit 3
}


# Share the existing signed-in account's 24h soft-token ledger; never bypass it.
# Unknown/missing model usage is charged conservatively, including failed runs.
finish_smoke() {
  status=$?
  trap - EXIT
  if [ -s "$base/budget-reservation-1.json" ] ||
     [ -s "$base/budget-reservation-2.json" ]; then
    if ! python3 - "$runs" "$base" <<'BUDGET_USAGE'
import json
from pathlib import Path
import sys
runs, base = map(Path, sys.argv[1:])
for idx, name in enumerate(("smoke-alpha", "smoke-beta"), start=1):
    logs = list(runs.glob("run-*/" + name + ".jsonl")) if runs.exists() else []
    usage = {"observed": False}
    if len(logs) == 1 and logs[0].stat().st_size <= 2000000:
        values = {"input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0}
        count = 0
        try:
            for line in logs[0].read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if event.get("type") != "turn.completed":
                    continue
                part = event.get("usage")
                if not isinstance(part, dict) or any(
                    type(part.get(k)) is not int or part[k] < 0 for k in values
                ) or part["cached_input_tokens"] > part["input_tokens"]:
                    count = 0
                    break
                for key in values:
                    values[key] += part[key]
                count += 1
        except (OSError, ValueError, TypeError):
            count = 0
        if count:
            usage = {"observed": True, **values}
    (base / ("budget-usage-" + str(idx) + ".json")).write_text(
        json.dumps(usage) + "\n", encoding="utf-8"
    )
BUDGET_USAGE
    then
      echo 'Could not parse private usage evidence; conservative budget settlement required' >&2
    fi
    for idx in 1 2; do
      if [ -s "$base/budget-reservation-$idx.json" ]; then
        [ -s "$base/budget-usage-$idx.json" ] ||
          printf '{"observed":false}\n' > "$base/budget-usage-$idx.json"
        if ! python3 "$budget_policy" settle "$budget_root" "$budget_job_base-$idx" \
             "$base/budget-usage-$idx.json" > "$base/budget-settlement-$idx.json"; then
          echo 'Shared Codex token-ledger settlement failed' >&2
          status=5
        fi
      fi
    done
  fi
  if [ "$status" -eq 5 ]; then
    printf '{"status":"FAILED","reason":"shared_budget_settlement_failed"}\n' > "$proof"
  fi
  exit "$status"
}
trap finish_smoke EXIT

test -f "$budget_policy" || blocked "shared_budget_policy_missing"
test -x "$codex_cli" || blocked "installed_cli_missing"
"$codex_cli" login status > /dev/null 2>&1 || blocked "codex_authentication_unavailable"
command -v flock > /dev/null || blocked "flock_unavailable"
command -v timeout > /dev/null || blocked "timeout_unavailable"
python3 --version > /dev/null 2>&1 || blocked "python_unavailable"

# Reserve BOTH existing Codex account slots before launching the new executor.
# These are the same locks used by the established VPS Codex bridge.
exec 8>"$HOME/codex-bridge/.codex-slot-1.lock"
exec 9>"$HOME/codex-bridge/.codex-slot-2.lock"
flock -n 8 || blocked "first_codex_slot_busy"
flock -n 9 || blocked "second_codex_slot_busy"

test ! -e "$source" || blocked "source_workspace_reuse"
git clone --quiet --depth 1 --branch main -- \
  https://github.com/martaxi-boss/Project-leader-codex.git "$source" ||
  blocked "repository_checkout_failed"
source_head="$(git -C "$source" rev-parse HEAD)" || blocked "source_sha_unavailable"
[ "$source_head" = "$expected" ] || blocked "unexpected_specialization_revision"

# Reserve two low-effort turns using the very same central ledger as all
# existing VPS Codex jobs. Each reservation is conservatively settled on exit.
python3 "$budget_policy" reserve "$budget_root" "$budget_job_base-1" low \
  > "$base/budget-reservation-1.json" || blocked "shared_soft_budget_unavailable"
python3 "$budget_policy" reserve "$budget_root" "$budget_job_base-2" low \
  > "$base/budget-reservation-2.json" || blocked "shared_soft_budget_unavailable"
test -s "$base/budget-reservation-1.json" || blocked "shared_soft_budget_unavailable"
test -s "$base/budget-reservation-2.json" || blocked "shared_soft_budget_unavailable"

mkdir -m 700 "$base/bin" "$runs"
cat > "$base/bin/codex" <<'WRAPPER'
#!/usr/bin/env bash
# Host-owned telemetry wrapper; invokes the already-authenticated real CLI.
set -euo pipefail
name="unmatched"
for argument in "$@"; do
  case "$argument" in
    */worker-1) name="worker-1" ;;
    */worker-2) name="worker-2" ;;
  esac
done
if [ "$name" != "unmatched" ]; then
  printf 'START\t%s\t%s\n' "$name" "$(date +%s%N)" >> "$CODEX_SMOKE_EVENTS"
fi
set +e
"$HOME/codex-agent/node_modules/.bin/codex" "$@"
status=$?
set -e
if [ "$name" != "unmatched" ]; then
  printf 'END\t%s\t%s\n' "$name" "$(date +%s%N)" >> "$CODEX_SMOKE_EVENTS"
fi
exit "$status"
WRAPPER
chmod 700 "$base/bin/codex"
export CODEX_SMOKE_EVENTS="$base/worker-events.tsv"
export PATH="$base/bin:$PATH"

cat > "$base/manifest.json" <<'ORDER'
{
  "target_repository": "martaxi-boss/Project-leader-codex",
  "mode": "parallel",
  "tasks": [
    {
      "id": "smoke-alpha",
      "task": "Corrige um typo de prova: cria apenas codex-smoke/alpha.txt com a linha literal CODEX_ALPHA_OK. Nao alteres nenhum outro ficheiro; nao faças commit nem push.",
      "paths": ["codex-smoke/alpha.txt"],
      "reasoning_effort": "low"
    },
    {
      "id": "smoke-beta",
      "task": "Corrige um typo de prova: cria apenas codex-smoke/beta.txt com a linha literal CODEX_BETA_OK. Nao alteres nenhum outro ficheiro; nao faças commit nem push.",
      "paths": ["codex-smoke/beta.txt"],
      "reasoning_effort": "low"
    }
  ]
}
ORDER
chmod 600 "$base/manifest.json"

printf '{"status":"RUNNING","reason":"two_codex_workers_invoked"}\n' > "$proof"
cd "$source"
set +e
timeout --signal=TERM --kill-after=15s 600s \
  python3 -m codex.dual run --manifest "$base/manifest.json" \
  --repo-dir "$source" --runs-dir "$runs" --timeout 420 --execute \
  > "$base/runner.json" 2> "$base/runner.stderr"
cli_status=$?
set -e
if [ "$cli_status" -ne 0 ]; then
  printf '{"status":"FAILED","reason":"dual_executor_nonzero","exit_code":%d}\n' \
    "$cli_status" > "$proof"
  echo "CODEX_DUAL_SMOKE_FAILED: dual_executor_nonzero" >&2
  exit 4
fi

python3 - "$base/runner.json" "$CODEX_SMOKE_EVENTS" "$runs" "$source" "$expected" "$proof" <<'CHECK'
import json
from pathlib import Path
import sys
from codex import dual

raw_path, events_path, runs_path, source_path, expected_sha, report_path = sys.argv[1:]
expected = {
    "smoke-alpha": ("worker-1", "codex-smoke/alpha.txt", "CODEX_ALPHA_OK"),
    "smoke-beta": ("worker-2", "codex-smoke/beta.txt", "CODEX_BETA_OK"),
}
proof = {
    "status": "FAIL",
    "revision": expected_sha,
    "mode": "parallel",
    "workers": [],
    "simultaneous_processes": False,
    "source_checkout_unchanged": False,
    "published_changes": False,
}
try:
    payload = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    workers = payload.get("workers")
    root = Path(runs_path).resolve(strict=True)
    if payload.get("mode") != "parallel" or not isinstance(workers, list) or len(workers) != 2:
        raise ValueError("invalid_executor_shape")
    for worker in workers:
        identifier = worker.get("id")
        if identifier not in expected:
            raise ValueError("unexpected_worker_identity")
        location, owned, literal = expected[identifier]
        workspace = Path(worker["workspace"]).resolve(strict=True)
        if not workspace.is_relative_to(root) or workspace.name != location:
            raise ValueError("invalid_private_worker_path")
        actual_content = (workspace / owned).read_text(encoding="utf-8").strip()
        scoped = (
            worker.get("new_paths") == [owned]
            and worker.get("out_of_scope") == []
            and worker.get("ref_changes") == []
            and worker.get("commit_detected") is False
            and worker.get("status") == "completed"
            and actual_content == literal
        )
        proof["workers"].append({
            "id": identifier,
            "status": worker.get("status", "unknown"),
            "owned_path": owned,
            "scope_verified": bool(scoped),
            "duration_seconds": worker.get("duration_seconds"),
        })
    proof["workers"].sort(key=lambda x: x["id"])
    events = {}
    for line in Path(events_path).read_text(encoding="utf-8").splitlines():
        tag, name, stamp = line.split("\t")
        if tag not in ("START", "END") or name not in ("worker-1", "worker-2"):
            raise ValueError("invalid_telemetry")
        key = (tag, name)
        if key in events:
            raise ValueError("duplicate_telemetry_event")
        events[key] = int(stamp)
    if len(events) == 4:
        start = max(events[("START", "worker-1")], events[("START", "worker-2")])
        finish = min(events[("END", "worker-1")], events[("END", "worker-2")])
        proof["simultaneous_processes"] = start < finish
    base = Path(source_path)
    # Auditing after untrusted model execution must never inherit host Git
    # environment or invoke worker-controlled fsmonitor/hooks/diff helpers.
    git_sha = dual._git(base, "rev-parse", "HEAD")
    cleanliness = dual._git(base, "status", "--porcelain")
    proof["source_checkout_unchanged"] = git_sha == expected_sha and not cleanliness
    proof["status"] = "PASS" if (
        len(proof["workers"]) == 2
        and all(x["scope_verified"] for x in proof["workers"])
        and proof["simultaneous_processes"]
        and proof["source_checkout_unchanged"]
    ) else "FAIL"
except (ValueError, KeyError, TypeError, OSError, dual.PlanError) as exc:
    proof["reason"] = str(exc)[:100].replace("\n", " ")
Path(report_path).write_text(
    json.dumps(proof, sort_keys=True, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
if proof["status"] != "PASS":
    raise SystemExit("Codex smoke results did not meet all acceptance controls")
CHECK
printf 'CODEX_DUAL_LIVE_SMOKE=PASS\n'
