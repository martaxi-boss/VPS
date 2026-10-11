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

test -d "$base" || exit 2
printf '{"status":"PREPARING","reason":"preflight_pending"}\n' > "$proof"

blocked() {
  # Fixed reason codes only: no model output, secrets or raw terminal logs.
  printf '{"status":"BLOCKED","reason":"%s"}\n' "$1" > "$proof"
  echo "CODEX_DUAL_SMOKE_BLOCKED: $1" >&2
  exit 3
}

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
import subprocess
import sys

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
    git_sha = subprocess.run(
        ["git", "-C", str(base), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    cleanliness = subprocess.run(
        ["git", "-C", str(base), "status", "--porcelain"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    proof["source_checkout_unchanged"] = git_sha == expected_sha and not cleanliness
    proof["status"] = "PASS" if (
        len(proof["workers"]) == 2
        and all(x["scope_verified"] for x in proof["workers"])
        and proof["simultaneous_processes"]
        and proof["source_checkout_unchanged"]
    ) else "FAIL"
except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as exc:
    proof["reason"] = str(exc)[:100].replace("\n", " ")
Path(report_path).write_text(
    json.dumps(proof, sort_keys=True, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
if proof["status"] != "PASS":
    raise SystemExit("Codex smoke results did not meet all acceptance controls")
CHECK
printf 'CODEX_DUAL_LIVE_SMOKE=PASS\n'
