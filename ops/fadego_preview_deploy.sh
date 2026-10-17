#!/usr/bin/env bash
# FADEGO: public fake-data walkthrough ONLY; never disables real admin authentication.
set -Eeuo pipefail
umask 077

if [[ "$(id -u)" != 0 || "${FADEGO_PREVIEW_DEPLOY_APPROVED:-}" != "1" ]]; then
  echo "FADEGO_PREVIEW_REFUSED_AUTHORITY"; exit 2
fi

source_file="$1"
host_conf="/etc/nginx/sites-available/fadego-staging.conf"
html_path="/var/www/fadego-preview/index.html"
if [[ ! -f "$source_file" || -L "$source_file" ]]; then
  echo "FADEGO_PREVIEW_REFUSED_HTML_SOURCE"; exit 2
fi
if [[ ! -f "$host_conf" || -L "$host_conf" ]]; then
  echo "FADEGO_PREVIEW_REFUSED_VHOST"; exit 2
fi
if [[ "$(readlink -f /srv/fadego-staging/current)" != "/srv/fadego-staging/releases/7e2b6c0d00809eb65c800737daeb660c2869e077" ]]; then
  echo "FADEGO_PREVIEW_REFUSED_UNKNOWN_FADEGO_RELEASE"; exit 2
fi
if ! systemctl is-active --quiet fadego-staging.service || ! systemctl is-active --quiet nginx; then
  echo "FADEGO_PREVIEW_REFUSED_INACTIVE_SERVICE"; exit 2
fi
if [[ "$(stat -c '%U' "$host_conf")" != root ]]; then
  echo "FADEGO_PREVIEW_REFUSED_VHOST_OWNER"; exit 2
fi
if ! grep -Fq 'server_name fadego.duckdns.org;' "$host_conf" ||
   ! grep -Fq 'auth_basic "FADEGO - ambiente de testes";' "$host_conf" ||
   ! grep -Fq 'auth_basic_user_file /etc/nginx/fadego-staging.htpasswd;' "$host_conf" ||
   ! grep -Fq 'proxy_pass http://127.0.0.1:3100;' "$host_conf"; then
  echo "FADEGO_PREVIEW_REFUSED_VHOST_BOUNDARIES"; exit 2
fi
if [[ -e /var/www/fadego-preview && ( -L /var/www/fadego-preview || ! -d /var/www/fadego-preview ) ]]; then
  echo "FADEGO_PREVIEW_REFUSED_UNEXPECTED_DIR"; exit 2
fi
if [[ -e "$html_path" && -L "$html_path" ]]; then
  echo "FADEGO_PREVIEW_REFUSED_HTML_SYMLINK"; exit 2
fi
if grep -Eq '(fetch[[:space:]]*\(|XMLHttpRequest|WebSocket|sendBeacon|document[.]cookie)' "$source_file"; then
  echo "FADEGO_PREVIEW_REFUSED_NETWORK_OR_COOKIE_SCRIPT"; exit 2
fi
if ! grep -q 'FADEGO — Experimentar sem login' "$source_file"; then
  echo "FADEGO_PREVIEW_REFUSED_UNEXPECTED_CONTENT"; exit 2
fi
if grep -qF 'FADEGO_PREVIEW_BEGIN' "$host_conf" && ! grep -qF 'FADEGO_PREVIEW_END' "$host_conf"; then
  echo "FADEGO_PREVIEW_REFUSED_PARTIAL_EXISTING_BLOCK"; exit 2
fi

exec 9>/run/fadego-preview-deploy.lock
flock -n 9 || { echo "FADEGO_PREVIEW_ALREADY_DEPLOYING"; exit 2; }

# This folder contains only the self-contained fake-data HTML; no secrets.
install -d -o root -g root -m 0755 /var/www/fadego-preview
install -o root -g root -m 0644 "$source_file" "$html_path"

backup="$(mktemp /etc/nginx/sites-available/.fadego-preview-vhost.XXXXXXXX)"
cp -p "$host_conf" "$backup"
modified=0
clean_exit() {
  local rc=$?
  trap - EXIT
  if [[ "$rc" != 0 && "$modified" == "1" ]]; then
    cp -p "$backup" "$host_conf"
    nginx -t -q && systemctl reload nginx || true
    echo 'FADEGO_PREVIEW_ONLY_VHOST_ROLLED_BACK'
  fi
  rm -f "$backup"
  exit "$rc"
}
trap clean_exit EXIT

python3 - "$host_conf" <<'PYTHON'
from pathlib import Path
import sys

path = Path(sys.argv[1])
original = path.read_text(encoding="utf-8")
start = "    # FADEGO_PREVIEW_BEGIN: exact-path fake-data walkthrough\n"
finish = "    # FADEGO_PREVIEW_END\n"
if start in original:
    if finish not in original:
        raise SystemExit("FADEGO_PREVIEW_REFUSED_PARTIAL_VHOST")
    print("FADEGO_PREVIEW_VHOST=ALREADY_CONFIGURED")
    raise SystemExit(0)

anchor = "    client_max_body_size 1m;\n"
if original.count(anchor) != 1 or "    location / {" not in original:
    raise SystemExit("FADEGO_PREVIEW_REFUSED_UNKNOWN_NGINX_LAYOUT")
block = """
    # FADEGO_PREVIEW_BEGIN: exact-path fake-data walkthrough
    # Only /experimentar/ is public. Everything else inherits existing Basic Auth.
    location = /experimentar {
        auth_basic off;
        return 302 /experimentar/;
    }
    location = /experimentar/ {
        auth_basic off;
        access_log off;
        alias /var/www/fadego-preview/index.html;
        default_type text/html;
        charset utf-8;
        add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Cache-Control "private, no-store" always;
        add_header Content-Security-Policy "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
    }
    # FADEGO_PREVIEW_END
"""
path.write_text(original.replace(anchor, anchor + block, 1), encoding="utf-8")
print("FADEGO_PREVIEW_VHOST=PATCHED_OWN_HOST_ONLY")
PYTHON
modified=1
nginx -t -q
systemctl reload nginx
if ! systemctl is-active --quiet nginx || ! systemctl is-active --quiet fadego-staging.service; then
  echo "FADEGO_PREVIEW_REFUSED_SERVICE_REGRESSION"; exit 2
fi

# Verify local HTTPS and Basic Auth *without ever knowing/publishing Basic credentials*.
# systemctl reload acknowledges HUP before Nginx workers finish loading config;
# bounded poll prevents a false 401 on the previous worker generation.
preview_status="000"
for attempt in $(seq 1 18); do
  preview_status="$(curl -sS --max-time 6 --resolve fadego.duckdns.org:443:127.0.0.1 -o /dev/null -w '%{http_code}' https://fadego.duckdns.org/experimentar/ || true)"
  if [[ "$preview_status" == "200" ]]; then
    echo "FADEGO_PREVIEW_RELOAD_OBSERVED_AFTER_ATTEMPT=$attempt"
    break
  fi
  sleep 1
done
if [[ "$preview_status" != "200" ]]; then
  if nginx -T 2>/dev/null | grep -Fq 'FADEGO_PREVIEW_BEGIN'; then
    echo "FADEGO_PREVIEW_PARSED_NGINX_CONFIG=HAS_EXACT_ROUTE"
  else
    echo "FADEGO_PREVIEW_PARSED_NGINX_CONFIG=MISSING_EXACT_ROUTE"
  fi
  if [[ "$(readlink -f /etc/nginx/sites-enabled/fadego-staging.conf || true)" == "$host_conf" ]]; then
    echo "FADEGO_PREVIEW_ENABLED_VHOST=POINTS_TO_EXPECTED_FILE"
  else
    echo "FADEGO_PREVIEW_ENABLED_VHOST=NOT_EXPECTED_FILE"
  fi
  if curl -sS -I --max-time 6 --resolve fadego.duckdns.org:443:127.0.0.1 https://fadego.duckdns.org/experimentar/ | grep -qi '^www-authenticate: Basic'; then
    echo "FADEGO_PREVIEW_RESPONSE=STILL_BASIC_AUTH"
  else
    echo "FADEGO_PREVIEW_RESPONSE=OTHER_HTTP_RESPONSE"
  fi
fi
admin_status="$(curl -sS --max-time 12 --resolve fadego.duckdns.org:443:127.0.0.1 -o /dev/null -w '%{http_code}' https://fadego.duckdns.org/admin)"
home_status="$(curl -sS --max-time 12 --resolve fadego.duckdns.org:443:127.0.0.1 -o /dev/null -w '%{http_code}' https://fadego.duckdns.org/)"
api_status="$(curl -sS --max-time 12 --resolve fadego.duckdns.org:443:127.0.0.1 -o /dev/null -w '%{http_code}' https://fadego.duckdns.org/api/auth/session)"
printf 'FADEGO_PREVIEW_OBSERVED_STATUS demo=%s admin=%s home=%s api=%s\n' "$preview_status" "$admin_status" "$home_status" "$api_status"
if [[ "$preview_status" != "200" || "$admin_status" != "401" ||
      "$home_status" != "401" || "$api_status" != "401" ]]; then
  echo "FADEGO_PREVIEW_REFUSED_AUTH_BOUNDARY_REGRESSION"; exit 2
fi
echo 'FADEGO_PREVIEW=PUBLIC_FAKE_DATA_ONLY'
echo 'FADEGO_REAL_SITE_BASIC_AUTH=STILL_ENABLED'
echo 'FADEGO_PUBLIC_PREVIEW_HTTPS=200'
echo 'FADEGO_ALL_REAL_ADMIN_AND_API_PATHS=401'
echo 'FADEGO_ORIGINAL_RELEASE=UNCHANGED'
modified=0
