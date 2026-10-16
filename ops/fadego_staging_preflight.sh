#!/usr/bin/env bash
# FADEGO one-time staging host status. No edits, no sudo, no config reads.
set -euo pipefail

if [[ "$(id -un)" != "ubuntu" ]]; then
  echo "SSH_USER=UNEXPECTED"
  exit 2
fi
echo "SSH_AUTHENTICATED=YES"

port_status() {
  python3 - "$1" <<'PY'
import socket
import sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("127.0.0.1", port))
except OSError:
    print("CLOSED")
else:
    print("OPEN")
finally:
    s.close()
PY
}
for port in 80 443 3100; do
  state="$(port_status "$port")"
  printf 'LOCAL_PORT_%s=%s\n' "$port" "$state"
done

for service in nginx caddy docker; do
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$service"; then
    status="ACTIVE"
  else
    status="NOT_ACTIVE_OR_OTHER_INSTALL"
  fi
  printf 'SERVICE_%s=%s\n' "${service^^}" "$status"
done

if command -v docker >/dev/null 2>&1; then
  echo "DOCKER_CLI=AVAILABLE"
  if docker info >/dev/null 2>&1; then
    echo "DOCKER_DAEMON=ACCESSIBLE_BY_UBUNTU"
  else
    echo "DOCKER_DAEMON=NOT_ACCESSIBLE_BY_UBUNTU"
  fi
else
  echo "DOCKER_CLI=NOT_INSTALLED"
fi

status="$(curl -sS -o /dev/null --max-time 5 -w '%{http_code}' \
  http://127.0.0.1:3100/ 2>/dev/null || true)"
case "$status" in
  200) echo "FADEGO_LOCAL_HTTP=RESPONDS_200" ;;
  000|"") echo "FADEGO_LOCAL_HTTP=NOT_RESPONDING" ;;
  *) echo "FADEGO_LOCAL_HTTP=RESPONDS_NON_200" ;;
esac

# Check TLS to localhost only, using SNI fadego.duckdns.org and normal
# certificate verification. Prints status class, never page content.
status="$(curl -sS -o /dev/null --max-time 8 -w '%{http_code}' \
  --resolve fadego.duckdns.org:443:127.0.0.1 \
  https://fadego.duckdns.org/ 2>/dev/null || true)"
case "$status" in
  200) echo "FADEGO_HTTPS_VHOST=RESPONDS_200" ;;
  401) echo "FADEGO_HTTPS_VHOST=AUTH_GATE_401" ;;
  000|"") echo "FADEGO_HTTPS_VHOST=NOT_RESPONDING_OR_TLS_INVALID" ;;
  *) echo "FADEGO_HTTPS_VHOST=RESPONDS_OTHER" ;;
esac

echo "PREFLIGHT_READ_ONLY=COMPLETE"
