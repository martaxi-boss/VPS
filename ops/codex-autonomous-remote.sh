#!/usr/bin/env bash
# Trusted VPS-side Codex executor: generates a patch, NEVER receives GitHub write credentials.
set -Eeuo pipefail
umask 077

job="${1:-}"
[[ "$job" =~ ^[0-9]+-[0-9]+$ ]] || { echo 'Invalid job key' >&2; exit 2; }
base="$HOME/codex-bridge/jobs/$job"
repo="$base/repository"
report="$base/report.md"
patch="$base/patch.diff"
usage="$base/usage.json"
cli="$HOME/codex-agent/node_modules/.bin/codex"

on_exit() {
  code=$?
  if [ "$code" -ne 0 ]; then
    printf 'CODEX_EXECUTION_FAILED=%s\n' "$code" > "$base/outcome.txt"
  fi
}
trap on_exit EXIT

test -s "$base/codex-task.txt"
test -f "$base/codex_patch_guard.py"
test -x "$cli"
"$cli" login status > /dev/null 2>&1 || { echo 'Codex login unavailable' >&2; exit 3; }

IFS= read -r header < "$base/codex-task.txt" || :
case "$header" in
  TARGET_REPOSITORY=martaxi-boss/VPS) slug='martaxi-boss/VPS' ;;
  TARGET_REPOSITORY=martaxi-boss/Project-leader) slug='martaxi-boss/Project-leader' ;;
  *) echo 'Unsupported target; fail closed' >&2; exit 4 ;;
esac

test ! -e "$repo" || { echo 'Existing workspace refused' >&2; exit 5; }
git clone --quiet --depth 1 --branch main -- "https://github.com/$slug.git" "$repo"
head="$(git -C "$repo" rev-parse HEAD)"
printf '%s\n' "$slug" > "$base/target.txt"
printf '%s\n' "$head" > "$base/base-sha.txt"

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

OWNER TASK:
RULES
cat "$base/codex-task.txt" >> "$base/prompt.md"

cd "$repo"
# JSONL output gives direct per-run token counts when Codex emits turn.completed.usage.
# It does NOT prove any percentage of the account's weekly quota.
printf 'CODEX_MODEL=gpt-5.6-terra\nCODEX_REASONING_EFFORT=medium\nCODEX_TARGET_SHA=%s\n' "$head"
set +e
timeout --signal=TERM --kill-after=15s 35m \
  "$cli" exec --model gpt-5.6-terra -c model_reasoning_effort=medium \
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
