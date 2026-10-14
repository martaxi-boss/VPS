#!/usr/bin/env bash
# Explicit, read-only Coordinator AI smoke test for the existing Codex VPS.
# This script is never an issue, Telegram, or workflow trigger by itself.
set -Eeuo pipefail
set +x
umask 077

refuse() {
  # No private prompt, model output, stderr or local path is ever emitted.
  local reason='PRECHECK'
  if [ "$#" -gt 0 ]; then reason="$1"; fi
  case "$reason" in
    PRECHECK|NO_SLOT|CLONE|BOOTSTRAP|MODEL_AUTH|MODEL_EXEC|MODEL_FORMAT|MODEL_SCHEMA|MODEL_PATHS|NO_FINDINGS|MODEL_OTHER|PLAN_RECHECK) ;;
    *) reason='PRECHECK' ;;
  esac
  printf 'COORDINATOR_SMOKE_STATUS=REFUSED\nCOORDINATOR_SMOKE_REASON=%s\n' "$reason"
  printf '%s\n' 'COORDINATOR_SMOKE_STATUS=REFUSED' >&2
  exit 12
}

# One tested read-only planning implementation, exposed in two modes:
# 1) existing explicit no-dispatch smoke, 2) Owner-verified audited plan
#    transferred to the existing trusted Actions router for dispatch.
if { [ "$#" -ne 1 ] && [ "$#" -ne 3 ] && [ "$#" -ne 4 ]; } ||
   [[ ! "$1" =~ ^[1-9][0-9]{7,14}-[1-9][0-9]{0,3}$ ]]; then
  refuse
fi
job="$1"
mode='smoke'
encoded_order=''
private_assets=0
if [ "$#" -ge 3 ]; then
  [ "$2" = 'dispatch' ] || refuse
  mode='dispatch'
  encoded_order="$3"
  [ "${#encoded_order}" -ge 20 ] && [ "${#encoded_order}" -le 11000 ] || refuse
  [[ "$encoded_order" =~ ^[A-Za-z0-9+/=]+$ ]] || refuse
fi
if [ "$#" -eq 4 ]; then
  [ "$4" = 'with-private-attachments' ] || refuse
  private_assets=1
fi

# Use the already-authenticated account and the same two worker slots.
bridge="$HOME/codex-bridge"
root="$bridge/.coordinator-smoke"
cli="$HOME/codex-agent/node_modules/.bin/codex"
slug='martaxi-boss/Project-leader-codex'
control_slug='martaxi-boss/VPS'
order='Audit the existing Project-leader-codex documentation only. Inspect real tracked files and report one concrete verifiable documentation defect with its exact file path, if found. Do not invent findings, make changes, or dispatch agents.'
if [ "$mode" = dispatch ]; then
  order="$(printf '%s' "$encoded_order" | base64 -d 2>/dev/null)" || refuse
  [ "${#order}" -ge 25 ] && [ "${#order}" -le 8000 ] || refuse
  first="$(printf '%s' "$order" | head -n 1)"
  if [[ "$first" =~ ^TARGET_REPOSITORY=(martaxi-boss/[A-Za-z0-9][A-Za-z0-9._-]{0,99})$ ]]; then
    slug="${BASH_REMATCH[1]}"
  else
    refuse
  fi
fi

[ -d "$bridge" ] && [ ! -L "$bridge" ] || refuse
[ -x "$cli" ] && command -v flock >/dev/null 2>&1 || refuse CLONE
[ -z "${OPENAI_API_KEY:-}" ] && [ -z "${CODEX_API_KEY:-}" ] || refuse

# No chmod of an existing directory; require it to be already owner-only.
if [ -e "$root" ] || [ -L "$root" ]; then
  [ -d "$root" ] && [ ! -L "$root" ] || refuse
else
  mkdir -m 700 -- "$root" || refuse
fi
[ "$(stat -c '%u' -- "$root")" = "$(id -u)" ] || refuse
[ "$(stat -c '%a' -- "$root")" = '700' ] || refuse

workspace="$root/$job"
asset_bundle=''
asset_args=()
if [ "$private_assets" -eq 1 ]; then
  asset_bundle="$bridge/.coordinator-inbox/$job"
  # The bundle MUST already have arrived by an authenticated private
  # transport. A missing/unsafe bundle is never converted into text-only.
  [ -d "$asset_bundle" ] && [ ! -L "$asset_bundle" ] || refuse
  [ "$(stat -c '%u' -- "$asset_bundle")" = "$(id -u)" ] || refuse
  [ "$(stat -c '%a' -- "$asset_bundle")" = '700' ] || refuse
  asset_args=(--attachment-bundle "$asset_bundle")
fi
[ ! -e "$workspace" ] && [ ! -L "$workspace" ] || refuse

# Atomic, persistent anti-replay marker: a given Actions job is never started twice.
( set -C; : > "$root/.started-$job" ) 2>/dev/null || refuse
mkdir -m 700 -- "$workspace" || refuse
cleanup_private_workspace() {
  rm -rf -- "$workspace"
  # The unique run ID is strictly validated above. Selected Owner media
  # never remains in the private staging directory after an invoked run.
  if [ "$private_assets" -eq 1 ] && [ -n "$asset_bundle" ]; then
    rm -rf -- "$asset_bundle"
  fi
}
trap cleanup_private_workspace EXIT

control="$workspace/control"
target="$workspace/target"
private="$workspace/proof"
mkdir -m 700 -- "$private"

# Do not spend a model turn when both account slots are occupied.
exec 8>"$bridge/.codex-slot-1.lock"
exec 9>"$bridge/.codex-slot-2.lock"
if flock -n 8; then
  :
elif flock -n 9; then
  :
else
  refuse NO_SLOT
fi

# Fixed HTTPS targets, no user-controlled source, path, branch or ref.
# Hide Git stderr: neither remote details nor tokens belong in public logs.
git clone -q --depth 1 --single-branch --branch main -- \
  "https://github.com/$control_slug.git" "$control" >/dev/null 2>&1 || refuse CLONE
python3 "$control/ops/project_target.py" validate "$slug" >/dev/null 2>&1 || refuse
git clone -q --depth 1 --single-branch --branch main -- \
  "https://github.com/$slug.git" "$target" >/dev/null 2>&1 || refuse CLONE

for pair in "$control|$control_slug" "$target|$slug"; do
  checkout="${pair%%|*}"
  repo="${pair#*|}"
  [ "$(git -C "$checkout" remote get-url origin)" = "https://github.com/$repo.git" ] || refuse
  [ "$(git -C "$checkout" symbolic-ref --short HEAD)" = main ] || refuse
  [ -z "$(git -C "$checkout" status --porcelain --untracked-files=all)" ] || refuse
done
head="$(git -C "$target" rev-parse HEAD)"
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || refuse

# The Coordinator does not load Project Leader. The trusted worker runtime
# verifies and loads canonical rules for each isolated Codex implementer.
# Explicit, bounded document-only order. Coordinator AI is read-only, never
# dispatches workers, creates Issues/PRs, or modifies the target checkout.
# The authenticated Owner order is decoded only as data before target selection.

# Results live only in the disposable private workspace, not in a
# persistent directory. The only failure output is a trusted static class.
if ! python3 "$control/ops/coordinator_ai.py" \
  --order "$order" --checkout "$target" \
  --output-dir "$workspace/validated" \
  --codex "$cli" "${asset_args[@]}" > "$private/coordinator-result.json" \
  2>"$private/coordinator-error.txt"; then
  diagnostic='MODEL_OTHER'
  if grep -qxF 'COORDINATOR_AI_REFUSED: ChatGPT subscription login required; no model started' "$private/coordinator-error.txt"; then
    diagnostic='MODEL_AUTH'
  elif grep -qxF 'COORDINATOR_AI_REFUSED: Codex planning call failed' "$private/coordinator-error.txt"; then
    diagnostic='MODEL_EXEC'
  elif grep -qxF 'COORDINATOR_AI_REFUSED: Codex returned invalid JSON' "$private/coordinator-error.txt"; then
    diagnostic='MODEL_FORMAT'
  elif grep -qxF 'COORDINATOR_AI_REFUSED: Codex audit failed the existing phase planner' "$private/coordinator-error.txt"; then
    diagnostic='MODEL_SCHEMA'
  elif grep -qxF 'COORDINATOR_AI_REFUSED: Audit cites a non-versioned or non-regular path' "$private/coordinator-error.txt"; then
    diagnostic='MODEL_PATHS'
  elif grep -qxF 'COORDINATOR_AI_REFUSED: No verifiable repository finding; nothing to plan' "$private/coordinator-error.txt"; then
    diagnostic='NO_FINDINGS'
  fi
  refuse "$diagnostic"
fi

# Independently re-validate the private model output and print allowlisted
# metrics only. No prompts, arbitrary model strings or local paths are logged.
python3 - "$private/coordinator-result.json" "$workspace/validated" \
  "$control" "$slug" "$head" "$mode" <<'PY' || refuse PLAN_RECHECK
import base64
import json
from pathlib import Path
import stat
import sys

result_path, output_dir, control, target, head, mode = sys.argv[1:]
try:
    report = json.loads(Path(result_path).read_text(encoding="utf-8"))
    if (not isinstance(report, dict) or
            report.get("status") != "VALIDATED_PLAN_NO_DISPATCH" or
            report.get("target_repository") != target or
            report.get("revision") != head):
        raise ValueError("Invalid coordinator report")
    directory = Path(output_dir).resolve(strict=True)
    file = Path(report["output_file"]).resolve(strict=True)
    if (file.parent != directory or
            not stat.S_ISREG(file.stat().st_mode) or
            file.stat().st_size > 24_000 or
            file.stat().st_mode & 0o077):
        raise ValueError("Unsafe private result")
    sys.path.insert(0, str(Path(control) / "ops"))
    from codex_audit_strategy import plan_phases
    payload = json.loads(file.read_text(encoding="utf-8"))
    plan = plan_phases(payload)
    first = plan["phases"][0]
    if (plan["target_repository"] != target or
            plan["audited_revision"] != head or
            report.get("first_phase_workers") != first["worker_count"] or
            report.get("first_phase_mode") != first["mode"] or
            not 1 <= plan["phase_count"] <= 8 or
            first["worker_count"] not in (1, 2) or
            first["mode"] not in ("serial", "parallel")):
        raise ValueError("Inconsistent coordinator result")
except (OSError, ValueError, KeyError, TypeError, AssertionError, IndexError):
    raise SystemExit(13)
if mode == "smoke":
    print("COORDINATOR_SMOKE_STATUS=PASS")
    print("TARGET_REPOSITORY=" + target)
    print("TARGET_SHA=" + head)
    print("PHASE_COUNT=" + str(plan["phase_count"]))
    print("FIRST_PHASE_WORKERS=" + str(first["worker_count"]))
    print("FIRST_PHASE_MODE=" + first["mode"])
elif mode == "dispatch":
    # The validated JSON is transmitted only into a private runner temp file;
    # it never appears in an Issue, transcript or shell trace.
    raw_audit = file.read_bytes().strip()
    if not 0 < len(raw_audit) <= 24000:
        raise SystemExit(13)
    print("COORDINATOR_DISPATCH_STATUS=VALIDATED")
    print("TARGET_REPOSITORY=" + target)
    print("TARGET_SHA=" + head)
    print("PHASE_COUNT=" + str(plan["phase_count"]))
    print("FIRST_PHASE_WORKERS=" + str(first["worker_count"]))
    print("FIRST_PHASE_MODE=" + first["mode"])
    print("AUDIT_B64=" + base64.b64encode(raw_audit).decode("ascii"))
else:
    raise SystemExit(13)
PY
