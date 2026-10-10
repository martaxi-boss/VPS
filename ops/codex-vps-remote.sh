#!/usr/bin/env bash
# Codex CLI is already installed and signed in as ubuntu on the VPS.
# This job only audits a new clone. It never touches production paths.
set -Eeuo pipefail
umask 077

job_key="$1"
if [[ ! "$job_key" =~ ^[0-9]+-[0-9]+$ ]]; then
  echo "Invalid job identifier" >&2
  exit 2
fi

base="$HOME/codex-bridge/jobs/$job_key"
repo_dir="$base/repository"
report="$base/report.md"
prompt="$base/prompt.md"
codex="$HOME/codex-agent/node_modules/.bin/codex"

finish() {
  local status=$?
  if [ "$status" -ne 0 ] && [ ! -s "$report" ]; then
    printf 'Codex audit failed (exit code %s). Inspect the workflow result; no production files were changed.\n' "$status" > "$report"
  fi
  exit "$status"
}
trap finish EXIT

test -d "$base"
test -s "$base/task.txt"
test -x "$codex"

# The signed-in account is stored only on this VPS; no auth file is copied to CI.
"$codex" login status > /dev/null 2>&1 || {
  echo "Codex is not signed in on the VPS" >&2
  exit 3
}

# Fresh private workspace for each run. Never run Codex in the production tree.
if [ -e "$repo_dir" ]; then
  echo "Refusing to reuse an existing job directory" >&2
  exit 4
fi
git clone --quiet --depth 1 --branch main -- \
  https://github.com/martaxi-boss/VPS.git "$repo_dir"

cat > "$prompt" <<'RULES'
Please audit only the checked-out GitHub repository in your current working directory.
Operate only inside this repository. Never use sudo, SSH, deployments, cloud APIs,
credentials, production data, or files outside this repository.
You must not modify any files. Do not execute project scripts or tests that could
change data or contact services; static inspection only.
Report your findings in European Portuguese, including filenames, severity,
uncertainties, and a concise final conclusion. Never print tokens or secrets.

USER REQUEST:
RULES
cat "$base/task.txt" >> "$prompt"
printf '\n' >> "$prompt"

cd "$repo_dir"
# Always use the read-only Codex sandbox. The project is a disposable clone.
timeout --signal=TERM --kill-after=15s 35m \
  "$codex" exec --sandbox read-only \
    --output-last-message "$report" - \
    < "$prompt" > "$base/cli.log" 2>&1

test -s "$report"
printf 'CODEX_VPS_AUDIT=PASS\n'
