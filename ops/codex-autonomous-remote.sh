#!/usr/bin/env bash
# Trusted VPS-side Codex executor: generates a patch, NEVER receives GitHub write credentials.
set -Eeuo pipefail
umask 077

job="${1:-}"
[[ "$job" =~ ^[0-9]+-[0-9]+(-[12]|-p[2-8]-[12])?$ ]] || { echo 'Invalid job key' >&2; exit 2; }
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
test -f "$base/codex_quota_resume.py"
test -f "$base/codex_account_limits.py"
test -f "$base/codex_quota_workspace.py"
test -f "$base/codex_audit_strategy.py"
test -s "$base/codex-reasoning.txt"
effort="$(cat "$base/codex-reasoning.txt")"
case "$effort" in low|medium|high) ;; *) echo 'Invalid trusted Codex thinking level' >&2; exit 10 ;; esac
test -x "$cli"
# ChatGPT subscription usage and API-key billing have different limits.
# Verify the auth mode without printing any tokens or login response to logs.
auth_status="$("$cli" login status 2>&1)" || {
  printf 'CHATGPT_AUTH_REQUIRED\n' > "$base/codex-preflight-signal.txt"
  echo 'ChatGPT Codex login unavailable; no model started' >&2
  exit 3
}
if [ "$auth_status" != 'Logged in using ChatGPT' ] ||
   [ -n "${OPENAI_API_KEY:-}" ] || [ -n "${CODEX_API_KEY:-}" ]; then
  printf 'CHATGPT_AUTH_REQUIRED\n' > "$base/codex-preflight-signal.txt"
  echo 'ChatGPT subscription login required; API-key billing was refused; no model started' >&2
  exit 3
fi
printf 'CODEX_AUTH_MODE=CHATGPT\n'
# Quota read is advisory. The Owner can start with ANY amount of remaining
# provider allowance. Only a REAL BLOCKED response stops the model preflight;
# absent/unknown availability is left to the signed-in Codex CLI itself.
# Never manufacture a 10% reserve or a virtual local quota.
quota_status="UNKNOWN"
if python3 "$base/codex_account_limits.py" read "$cli" > "$base/provider-quota.json"; then
  quota_status="$(python3 - "$base/provider-quota.json" <<'PY_QUOTA'
import json, sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    if data.get('source') != 'codex_app_server' or data.get('auth') != 'chatgpt':
        raise ValueError
    status = data.get('status')
    if status not in ('AVAILABLE', 'BLOCKED'):
        raise ValueError
    print(status)
except (OSError, ValueError, TypeError):
    print('UNKNOWN')
PY_QUOTA
)" || quota_status="UNKNOWN"
fi
case "$quota_status" in
  BLOCKED)
    printf 'CODEX_QUOTA_BLOCKED\n' > "$base/codex-preflight-signal.txt"
    echo 'CODEX_REAL_CHATGPT_QUOTA=BLOCKED; no model started; Owner controls restart' >&2
    exit 75
    ;;
  AVAILABLE)
    echo 'CODEX_REAL_CHATGPT_QUOTA=AVAILABLE; no artificial reserve'
    ;;
  UNKNOWN)
    # Auth mode was verified separately. Actual signed-in Codex execution
    # is authoritative: a provider quota error will stop and checkpoint.
    echo 'CODEX_REAL_CHATGPT_QUOTA=UNKNOWN; signed-in provider decides; no fabricated limit'
    ;;
esac

IFS= read -r header < "$base/codex-task.txt" || :
slug="${header#TARGET_REPOSITORY=}"
if [ "$header" = "$slug" ] || \
   ! python3 "$base/project_target.py" validate "$slug" >/dev/null 2>&1; then
  echo 'Unsupported target; fail closed' >&2
  exit 4
fi

test ! -e "$repo" || { echo 'Existing workspace refused' >&2; exit 5; }
git clone --quiet --depth 1 --branch main -- "https://github.com/$slug.git" "$repo"
head="$(git -C "$repo" rev-parse HEAD)"
printf '%s\n' "$slug" > "$base/target.txt"
printf '%s\n' "$head" > "$base/base-sha.txt"

# The Manager audited an exact repository tree before dispatch. If that HEAD
# moved, stop BEFORE consuming Codex tokens; the Manager must re-audit.
if ! python3 "$base/codex_audit_strategy.py" verify_checkout "$base/codex-task.txt" "$head"; then
  printf 'AUDIT_STALE_BLOCKED\n' > "$base/codex-preflight-signal.txt"
  echo 'Audited source changed; no model started' >&2
  exit 20
fi

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
Act under the pinned Project Leader Skill: inspect, execute, test, correct, retest
and continue within scope until the assigned objective is genuinely finished.
Recover ordinary bugs, build failures, formatting errors and recoverable conflicts
without requesting further Owner instructions. Use bounded evidence-based retries;
never spend tokens on blind repeats. Do not mistake PR_STAGED for merged/done.
Escalate a HUMAN_GATE only for indispensable Owner-exclusive intervention or
new uncovered material decisions. If completing the correction requires edits
outside authorized paths, report the precise blocked scope to the trusted
Publisher instead of bypassing protection or suppressing failing checks.
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
# Keep the private locked usage ledger and no-replay guard; the provider's
# actual ChatGPT usage limits (not an arbitrary VPS token counter) decide quota.
if ! python3 "$base/codex_resource_policy.py" reserve "$budget_root" "$job" "$effort" > "$base/budget-reservation.json"; then
  printf 'LOCAL_LEDGER_PREFLIGHT_FAILED\n' > "$base/codex-preflight-signal.txt"
  echo 'Private usage ledger or duplicate job failed validation; no model started' >&2
  exit 4
fi
test -s "$base/budget-reservation.json" || { echo 'Codex usage ledger record missing' >&2; exit 17; }
printf 'CODEX_USAGE_LEDGER=RECORDED\n'
# JSONL output gives direct per-run token counts when Codex emits turn.completed.usage.
# It does NOT prove any percentage of the account's weekly quota.
printf 'CODEX_MODEL=gpt-5.6-sol\nCODEX_REASONING_EFFORT=%s\nCODEX_TARGET_SHA=%s\n' "$effort" "$head"
set +e
timeout --signal=TERM --kill-after=15s 35m \
  "$cli" exec --model gpt-5.6-sol -c "model_reasoning_effort=$effort" \
    -c 'model_provider="openai"' \
    -c 'openai_base_url="https://chatgpt.com/backend-api/codex"' \
    -c 'chatgpt_base_url="https://chatgpt.com/backend-api/"' \
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
  # Only a genuine quota error emitted by the signed-in provider triggers
  # Owner-only resumption. Never auto-dispatch on a clock or a local estimate.
  state="$(python3 "$base/codex_quota_resume.py" classify "$base/cli.jsonl" "$base/cli.stderr")" || exit 18
  if [ "$state" = "QUOTA_BLOCKED" ]; then
    printf 'CODEX_QUOTA_BLOCKED\n' > "$base/codex-preflight-signal.txt"
    # Work may already contain changed and new files. Never discard the
    # original private clone after a genuine provider quota rejection.
    # No partial patch is automatically published or executed.
    if ! python3 "$base/codex_quota_workspace.py" secure "$base" "$job"; then
      echo 'QUOTA_PRIVATE_CHECKPOINT_UNVERIFIED; keep VPS workspace for Owner recovery' >&2
    fi
    echo 'CODEX_PROVIDER_QUOTA_PAUSED=YES; private worktree retained; Owner decides' >&2
    exit 75
  fi
  echo "Codex exited with code $code; no patch accepted" >&2
  exit "$code"
fi
test -s "$report" || { echo 'Codex returned no report' >&2; exit 6; }

# Independent mechanical guard rejects protected files, symlinks, secrets and oversized diffs.
python3 "$base/codex_patch_guard.py" "$patch" > "$base/patch-metrics.txt"
# Recheck the actual diff against the independent audited ownership contract.
python3 "$base/codex_audit_strategy.py" verify_changed "$base/codex-task.txt" > "$base/audit-paths.txt"
printf 'CODEX_EXECUTION_COMPLETE\n'
