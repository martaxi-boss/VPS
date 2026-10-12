#!/usr/bin/env bash
# Trusted VPS-side Codex executor: generates a patch, NEVER receives GitHub write credentials.
set -Eeuo pipefail
umask 077

job="${1:-}"
[[ "$job" =~ ^[0-9]+-[0-9]+(-[12])?$ ]] || { echo 'Invalid job key' >&2; exit 2; }
base="$HOME/codex-bridge/jobs/$job"
repo="$base/repository"
report="$base/report.md"
patch="$base/patch.diff"
usage="$base/usage.json"
cli="$HOME/codex-agent/node_modules/.bin/codex"
# The legacy bridge directory may predate private-0700 rules. Never
# chmod that shared directory (other existing Codex entrypoints use it);
# reserve tokens in a new private per-account child instead.
budget_root="$HOME/codex-bridge/.account-budget"

on_exit() {
  code=$?
  trap - EXIT
  # Reserve before a model call and count every completed/failed Codex turn.
  # Unknown usage is conservatively charged the full reservation.
  if [ -s "$base/budget-reservation.json" ]; then
    if ! python3 "$base/codex_resource_policy.py" settle "$budget_root" "$job" "$usage"       > "$base/budget-settlement.json"; then
      echo 'Shared Codex token-ledger settlement failed' >&2
      code=16
    fi
  fi
  if [ "$code" -ne 0 ]; then
    printf 'CODEX_EXECUTION_FAILED=%s\n' "$code" > "$base/outcome.txt"
  fi
  exit "$code"
}
trap on_exit EXIT

test -s "$base/codex-task.txt"
test -f "$base/codex_patch_guard.py"
test -f "$base/codex_resource_policy.py"
test -s "$base/codex-reasoning.txt"
effort="$(cat "$base/codex-reasoning.txt")"
case "$effort" in low|medium|high) ;; *) echo 'Invalid trusted Codex thinking level' >&2; exit 10 ;; esac
test -x "$cli"
"$cli" login status > /dev/null 2>&1 || { echo 'Codex login unavailable' >&2; exit 3; }

IFS= read -r header < "$base/codex-task.txt" || :
case "$header" in
  TARGET_REPOSITORY=martaxi-boss/VPS) slug='martaxi-boss/VPS' ;;
  TARGET_REPOSITORY=martaxi-boss/Project-leader) slug='martaxi-boss/Project-leader' ;;
  TARGET_REPOSITORY=martaxi-boss/Project-leader-codex) slug='martaxi-boss/Project-leader-codex' ;;
  TARGET_REPOSITORY=martaxi-boss/pink-iptv) slug='martaxi-boss/pink-iptv' ;;
  *) echo 'Unsupported target; fail closed' >&2; exit 4 ;;
esac

test ! -e "$repo" || { echo 'Existing workspace refused' >&2; exit 5; }
git clone --quiet --depth 1 --branch main -- "https://github.com/$slug.git" "$repo"
head="$(git -C "$repo" rev-parse HEAD)"
printf '%s\n' "$slug" > "$base/target.txt"
printf '%s\n' "$head" > "$base/base-sha.txt"

# Reconstruct the canonical Project Leader Skill at one immutable revision.
# This is a separate read-only clone; only the task target is mutable.
canonical="$repo"
if [ "$slug" != "martaxi-boss/Project-leader" ]; then
  canonical="$base/project-leader-canonical"
  test ! -e "$canonical" || { echo "Canonical workspace already exists" >&2; exit 5; }
  git clone --quiet --depth 1 --branch main -- \
    "https://github.com/martaxi-boss/Project-leader.git" "$canonical"
fi
python3 "$base/codex-project-leader-bootstrap.py" \
  "$canonical" "$slug" "$head" "$base/project-leader-rules.md" \
  "$base/project-leader-runtime.json"

cat > "$base/prompt.md" <<'RULES'
You are the IMPLEMENTER, not an auditor-only agent. Execute the bounded Owner task in this disposable checkout.
Edit the actual repository files needed for the request, then run ONLY safe local tests relevant to the edit.
Never edit workflow/authorization/credentials/control-plane files; if such a change is essential,
explain the exact blocker in the final response instead of bypassing governance.
Do not access home-directory secrets, production services, SSH, external accounts or paid resources.
Do not push, commit, open PRs, deploy or modify files outside this checkout. A separate trusted
GitHub runner reviews the actual patch and handles publication, independent CI and merge.
Do not claim PASS without evidence. Stop on a genuine Human Gate and explain what is required.
Keep the edit minimal; preserve tests, functionality, safety and historical evidence.
Use European Portuguese in your final report. Never print credentials or authentication data.

PROJECT LEADER CANONICAL RULES:
RULES
cat "$base/project-leader-rules.md" >> "$base/prompt.md"
printf '\nOWNER TASK:\n' >> "$base/prompt.md"
cat "$base/codex-task.txt" >> "$base/prompt.md"

cd "$repo"
# Bound total concurrent model calls on this single signed-in account across
# all normal and explicit parallel tasks. This lock is held until CLI exits.
command -v flock >/dev/null || { echo "Missing flock; Codex was not started" >&2; exit 10; }
lockdir="$HOME/codex-bridge"
mkdir -p -m 700 "$lockdir"
exec 8>"$lockdir/.codex-slot-1.lock"
exec 9>"$lockdir/.codex-slot-2.lock"
slot=0
for _ in $(seq 1 90); do
  if flock -n 8; then slot=1; break; fi
  if flock -n 9; then slot=2; break; fi
  sleep 5
done
[ "$slot" -ne 0 ] || { echo "No Codex execution slot available; no tokens spent" >&2; exit 11; }
printf 'CODEX_EXECUTION_SLOT=%s\n' "$slot"
# The trusted runner may publish only this fixed, non-sensitive state:
# policy denied a reservation before Codex CLI could start.
if ! python3 "$base/codex_resource_policy.py" reserve "$budget_root" "$job" "$effort" > "$base/budget-reservation.json"; then
  printf 'SOFT_BUDGET_POLICY_BLOCKED\n' > "$base/codex-preflight-signal.txt"
  exit 4
fi
test -s "$base/budget-reservation.json" || { echo 'Codex token reservation missing' >&2; exit 17; }
printf 'CODEX_SHARED_SOFT_TOKEN_RESERVATION=ACCEPTED\n'
# JSONL output gives direct per-run token counts when Codex emits turn.completed.usage.
# It does NOT prove any percentage of the account's weekly quota.
printf 'CODEX_MODEL=gpt-5.6-sol\nCODEX_REASONING_EFFORT=%s\nCODEX_TARGET_SHA=%s\n' "$effort" "$head"
set +e
timeout --signal=TERM --kill-after=15s 35m \
  "$cli" exec --model gpt-5.6-sol -c "model_reasoning_effort=$effort" \
    --sandbox workspace-write --json --output-last-message "$report" - \
    < "$base/prompt.md" > "$base/cli.jsonl" 2> "$base/cli.stderr"
code=$?
set -e

python3 - "$base/cli.jsonl" "$usage" <<'PY'
import json, sys
from pathlib import Path
values = None
for line in Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace').splitlines():
    try:
        obj = json.loads(line)
    except ValueError:
        continue
    if obj.get('type') == 'turn.completed' and isinstance(obj.get('usage'), dict):
        values = obj['usage']
result = {'observed': False}
if values is not None:
    required = ('input_tokens', 'cached_input_tokens', 'output_tokens')
    if all(type(values.get(k)) is int and values[k] >= 0 for k in required):
        result = {'observed': True, **{k: values[k] for k in required}}
Path(sys.argv[2]).write_text(json.dumps(result) + '\n', encoding='utf-8')
PY

if [ "$code" -ne 0 ]; then
  echo "Codex exited with code $code; no patch accepted" >&2
  exit "$code"
fi
test -s "$report" || { echo 'Codex returned no report' >&2; exit 6; }

# Independent mechanical guard rejects protected files, symlinks, secrets and oversized diffs.
python3 "$base/codex_patch_guard.py" "$patch" > "$base/patch-metrics.txt"
printf 'CODEX_EXECUTION_COMPLETE\n'
