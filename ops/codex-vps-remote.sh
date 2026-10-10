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
# Standard tier for ChatGPT Business: explicit model, no automatic expensive fallback.
codex_model="gpt-5.6-terra"

finish() {
  local status=$?
  rm -f -- "$base/codex-input.jpg" "$base/codex-input.png" "$base/codex-input.webp"
  if [ "$status" -ne 0 ] && [ ! -s "$report" ]; then
    # Only provide a sanitized, short error excerpt. Never upload the raw CLI log.
    python3 - "$base/cli.log" "$report" "$status" <<'PY'
import re
import sys
from pathlib import Path
log_path, report_path, status = sys.argv[1:]
raw = Path(log_path).read_text(encoding='utf-8', errors='replace') if Path(log_path).exists() else ''
errors = [line.strip() for line in raw.splitlines()
          if re.search(r'error|failed|fatal|denied|unsupported|quota|rate limit|network|auth|panic|sandbox|not found|timed out', line, re.I)]
def redact(line):
    line = re.sub(r'(?i)sk-[a-z0-9_-]{12,}', '[redacted]', line)
    line = re.sub(r'(?i)bearer\s+\S+', '[redacted]', line)
    line = re.sub(r'(?i)gh[opsru]_[a-z0-9_]{12,}', '[redacted]', line)
    line = re.sub(r'(?i)(api[_-]?key\s*[=:]\s*)\S+', r'\1[redacted]', line)
    return line[:220]
safe_tail = [line.strip() for line in raw.splitlines()[-16:]
             if line.strip() and not re.search(
                 r'token|secret|auth|password|bearer|credential|cookie|session', line, re.I)]
shown = errors[-6:] if errors else safe_tail[-6:]
excerpt = '\n'.join('- ' + redact(line) for line in shown)
message = ('Auditoria Codex falhou (codigo ' + status + '). CLI log bytes: ' + str(len(raw)) + '.\n'
           'Resumo de diagnostico sem registo completo:\n' +
           (excerpt or '- Sem erro textual identificado. Consultar o registo local protegido no VPS.') +
           '\nNao houve deploy nem alteracao dos ficheiros de producao.\n')
Path(report_path).write_text(message, encoding='utf-8')
PY
  fi
  exit "$status"
}
trap finish EXIT

test -d "$base"
test -s "$base/codex-task.txt"
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
cat "$base/codex-task.txt" >> "$prompt"
printf '\n' >> "$prompt"

printf 'CODEX_MODEL=%s\nCODEX_REASONING_EFFORT=medium\n' "$codex_model"

cd "$repo_dir"
# Attach only a privately staged Telegram screenshot (not a public URL).
image_args=()
image_count=0
for ext in jpg png webp; do
  img="$base/codex-input.$ext"
  if [ -f "$img" ]; then
    test -s "$img"
    image_count=$((image_count + 1))
    image_args=(--image "$img")
  fi
done
if [ "$image_count" -gt 1 ]; then
  echo "Multiple screenshots are not supported in this audit" >&2
  exit 13
fi
if [ "$image_count" -eq 1 ]; then
  printf '\nThe user attached a screenshot of an application error. Analyse it visually; propose a diagnosis without inventing source-code fixes when the application code is unavailable.\n' >> "$prompt"
fi
# Leave the stdin prompt after the output option so older Codex CLI parsers
# do not consume it as a second image path.
timeout --signal=TERM --kill-after=15s 35m \
  "$codex" exec --model "$codex_model" -c model_reasoning_effort=medium \
    --sandbox read-only "${image_args[@]}" \
    --output-last-message "$report" - \
    < "$prompt" > "$base/cli.log" 2>&1
test -s "$report"
# Codex may return exit code 0 after failing to read the repo due to the host sandbox.
# Treat an access-blocked audit as failure instead of publishing a false PASS.
if grep -Eiq 'Operation not permitted|filesystem-restricted execution requires bubblewrap|sandbox rejecting|cannot access repository|Nao consegui ler|Não consegui ler' "$report"; then
  echo 'Codex audit blocked by Linux sandbox; review host bwrap/AppArmor setup.' >&2
  exit 12
fi
printf 'CODEX_VPS_AUDIT=PASS\n'
