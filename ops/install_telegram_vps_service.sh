#!/usr/bin/env bash
# Execute on the VPS ONLY from an authenticated SSH session with sudo.
# Never echo or source the secrets file.
set -Eeuo pipefail
umask 077

stage=${1:?Private staging directory required}
[[ "$stage" == /home/ubuntu/telegram-vps-staging/* ]] || exit 2
test -f "$stage/telegram.env"
for name in telegram_gateway.py telegram_vps_service.py telegram_voice_transcribe.py codex-vps-remote.sh codex-project-leader-bootstrap.py; do
  test -s "$stage/$name"
done
test -s "$stage/project-leader-telegram.service"

id ubuntu >/dev/null
install -d -o root -g root -m 0755 /opt/project-leader-telegram /opt/project-leader-telegram/ops
install -d -o root -g ubuntu -m 0750 /etc/project-leader-telegram
install -o root -g root -m 0644 "$stage"/telegram_gateway.py "$stage"/telegram_vps_service.py \
  "$stage"/telegram_voice_transcribe.py "$stage"/codex-vps-remote.sh \
  "$stage"/codex-project-leader-bootstrap.py /opt/project-leader-telegram/ops/
install -o root -g ubuntu -m 0640 "$stage/telegram.env" /etc/project-leader-telegram/telegram.env
install -o root -g root -m 0644 "$stage/project-leader-telegram.service" \
  /etc/systemd/system/project-leader-telegram.service
install -d -o ubuntu -g ubuntu -m 0700 /home/ubuntu/.local/share/project-leader-telegram
install -d -o ubuntu -g ubuntu -m 0700 /home/ubuntu/codex-bridge/jobs
python3 -m py_compile /opt/project-leader-telegram/ops/telegram_vps_service.py \
  /opt/project-leader-telegram/ops/telegram_gateway.py
systemctl daemon-reload
systemctl enable --now project-leader-telegram.service >/dev/null
systemctl restart project-leader-telegram.service
sleep 3
systemctl is-active --quiet project-leader-telegram.service
# Never print the environment or journal contents, especially on a public Actions run.
echo 'TELEGRAM_SERVICE_SYSTEMD=ACTIVE'
