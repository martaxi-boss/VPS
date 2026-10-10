#!/usr/bin/env bash
# One narrowly scoped Codex proposal for Project Leader; never touch production.
set -Eeuo pipefail
umask 077

job="${1:-}"
[[ "$job" =~ ^[0-9]+-[0-9]+$ ]] || { echo "Invalid job id" >&2; exit 2; }
base="$HOME/codex-bridge/jobs/$job"
repo="$base/project-leader"
report="$base/report.md"
patch="$base/patch.diff"
prompt="$base/prompt.md"
codex="$HOME/codex-agent/node_modules/.bin/codex"
allowed="plugins/project-leader/skills/project-leader/SKILL.md"
expected="55b7a054df5408ed82f4d7771e5a8c843af26563"

finish() {
  status=$?
  if [ "$status" -ne 0 ] && [ ! -s "$report" ]; then
    printf 'Codex proposal failed (exit %s). No change was accepted. Check protected VPS logs; do not report PASS.\n' "$status" > "$report"
  fi
}
trap finish EXIT

test -d "$base"
test -s "$base/codex-task.txt"
test -x "$codex"
"$codex" login status > /dev/null 2>&1 || { echo "Codex login unavailable" >&2; exit 3; }
test ! -e "$repo" || { echo "Refusing existing workspace" >&2; exit 4; }
git clone --quiet --depth 1 --branch main -- \
  https://github.com/martaxi-boss/Project-leader.git "$repo"
actual="$(git -C "$repo" rev-parse HEAD)"
[ "$actual" = "$expected" ] || {
  printf 'Project Leader changed since audit: expected %s, got %s. Replan instead of patching stale code.\n' "$expected" "$actual" > "$report"
  exit 5
}

cat > "$prompt" <<'RULES'
You are proposing ONE small and compatible edit to the Project Leader rule set.
The checked-out repository is the sole target and is pinned to the audited main SHA.

ONLY MODIFY: plugins/project-leader/skills/project-leader/SKILL.md.
Do NOT change any other file, code, test, workflow, policy, version, or dependency.
Do NOT deploy, push, commit, alter permissions, touch production, access secrets,
or install dependencies. Do not run project scripts with external effects.
Use the existing Project Leader architecture and names, not a new manager/daemon.

Goal: make explicit the owner's operating style: efficient token/usage management;
minimum ceremony and context; proactive, autonomous execution on already covered
work; genuine Human Gates only; strict safety, factual evidence, and no invented
results, quotas, model availability, approvals, or capabilities. Treat availability
and usage as UNKNOWN until directly observable. Keep existing mandatory tests,
Supervisor controls, CI, security, repository isolation, and standing authority.
Never trade proof/safety for speed or token savings.

Before editing, read only the relevant portions of this Skill and adjacent control
law if strictly necessary. Prefer a short addition to an existing section over a
new section. If all required rules are already explicit, make no change and explain.
Avoid unrelated rewrites or duplicating existing instructions.

Your final message must be concise European Portuguese with changed path and
what was actually verified, distinguishing proposals from validated behavior.

OWNER'S TASK:
RULES
cat "$base/codex-task.txt" >> "$prompt"
printf '\n' >> "$prompt"

cd "$repo"
timeout --signal=TERM --kill-after=15s 35m \
  "$codex" exec --sandbox workspace-write \
  --output-last-message "$report" - < "$prompt" > "$base/cli.log" 2>&1
test -s "$report"

# Strict mechanical scope and bounded-diff checks: no agent claims are trusted.
mapfile -t changes < <(git status --porcelain --untracked-files=all)
if [ "${#changes[@]}" -ne 1 ] || [ "${changes[0]:3}" != "$allowed" ]; then
  printf '\nSCOPE_REJECTED: expected only %s; observed %s changed paths. No patch accepted.\n' \
    "$allowed" "${#changes[@]}" >> "$report"
  exit 6
fi
git diff --check HEAD -- || {
  printf '\nDIFF_CHECK_FAILED: proposed change was rejected.\n' >> "$report"
  exit 7
}
git diff --no-ext-diff --unified=3 HEAD -- "$allowed" > "$patch"
test -s "$patch"
patch_lines="$(wc -l < "$patch")"
if [ "$patch_lines" -gt 160 ]; then
  printf '\nDIFF_TOO_LARGE: %s lines; refused to treat this as a minimal fix.\n' "$patch_lines" >> "$report"
  rm -f "$patch"
  exit 8
fi
printf '\nCODEX_PROJECT_LEADER_PROPOSAL=PASS\nPROJECT_LEADER_BASE_SHA=%s\nPATCH_LINES=%s\n' "$actual" "$patch_lines" >> "$report"
printf 'CODEX_PROJECT_LEADER_PROPOSAL=PASS\n'
