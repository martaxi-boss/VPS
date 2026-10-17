#!/usr/bin/env bash
# Owner-approved scissors emblem only; isolated FADEGO staging.
set -Eeuo pipefail
umask 077
NEW=531cf2ffdbddb31c29a244bff81fc4468fc9fe35
OLD=7e2b6c0d00809eb65c800737daeb660c2869e077
DIGEST=8386058306f181827baa886e58262d2834044fa18a8e7bb2f488ce8b77f7c7c8
ROOT=/srv/fadego-staging
VHOST=/etc/nginx/sites-available/fadego-staging.conf
PREVIEW=/var/www/fadego-preview/index.html
ENV=/etc/fadego-staging/app.env
VAULT=/root/project-secrets/fadego-staging/basic-password
if [[ $(id -u) != 0 || "${FADEGO_BRANDING_DEPLOY_APPROVED:-}" != 1 ]]; then
  echo 'FADEGO_BRAND_REFUSED_NO_APPROVAL'; exit 2
fi
exec 9>/run/fadego-staging-install.lock
flock -n 9 || { echo 'FADEGO_BRAND_REFUSED_CONCURRENT_INSTALL'; exit 2; }
for c in git node corepack nginx curl python3 runuser systemctl sha256sum; do
  command -v "$c" >/dev/null || { echo "FADEGO_BRAND_MISSING_TOOL=$c"; exit 2; }
done
[[ -L "$ROOT/current" && ! -L "$ROOT/releases" ]] || exit 2
[[ $(readlink -f "$ROOT/current") == "$ROOT/releases/$OLD" ]] || { echo 'FADEGO_BRAND_REFUSED_WRONG_OLD_RELEASE'; exit 2; }
[[ $(git -C "$ROOT/current" rev-parse HEAD) == "$OLD" ]] || exit 2
[[ ! -e "$ROOT/releases/$NEW" && ! -e "$ROOT/current.next" && ! -L "$ROOT/current.next" ]] || exit 2
[[ -f "$VHOST" && ! -L "$VHOST" && -f "$PREVIEW" && ! -L "$PREVIEW" ]] || exit 2
[[ -s "$ENV" && -s "$VAULT" && -s /etc/fadego-staging/send-closed.env ]] || exit 2
grep -Fxq 'BOOKING_EMAIL_PROVIDER=disabled' /etc/fadego-staging/send-closed.env
grep -Fxq 'GMAIL_LIVE_SEND_ENABLED=false' /etc/fadego-staging/send-closed.env
grep -Fxq 'EnvironmentFile=/etc/fadego-staging/send-closed.env' /etc/systemd/system/fadego-staging.service
grep -Fq '<span class="mark">F</span>' "$PREVIEW"
[[ $(grep -Fc 'FADEGO_PREVIEW_BEGIN' "$VHOST") == 1 && $(grep -Fc 'FADEGO_PREVIEW_END' "$VHOST") == 1 ]] || exit 2
systemctl is-active --quiet fadego-staging.service
systemctl is-active --quiet nginx

prior_vhost="$(mktemp /etc/nginx/sites-available/.fadego-brand.XXXXXXXX)"
prior_preview="$(mktemp /var/www/fadego-preview/.fadego-brand.XXXXXXXX)"
cp -p "$VHOST" "$prior_vhost"
cp -p "$PREVIEW" "$prior_preview"
recover() {
  local status=$?
  trap - EXIT
  if [[ "$status" != 0 ]]; then
    cp -p "$prior_vhost" "$VHOST"
    cp -p "$prior_preview" "$PREVIEW"
    nginx -t -q && systemctl reload nginx || true
    if [[ "$(readlink -f "$ROOT/current" || true)" == "$ROOT/releases/$NEW" ]]; then
      ln -s "$ROOT/releases/$OLD" "$ROOT/current.brand-revert"
      mv -Tf "$ROOT/current.brand-revert" "$ROOT/current"
      systemctl restart fadego-staging.service || true
    fi
    echo 'FADEGO_BRAND_RECOVERY=OLD_RELEASE_RESTORED'
  fi
  rm -f "$prior_vhost" "$prior_preview"
  exit "$status"
}
trap recover EXIT

# Certified release builder only touches the fadego_staging user and PostgreSQL database.
set -a
source "$ENV"
set +a
export BOOKING_EMAIL_PROVIDER=disabled GMAIL_LIVE_SEND_ENABLED=false
export FADEGO_STAGING_SUPERVISOR_APPROVED=1 FADEGO_STAGING_APPROVED_SHA="$NEW"
export HOME="$ROOT" COREPACK_HOME="$ROOT/.cache/corepack"
runuser -u fadego-staging -m -- bash "$ROOT/releases/$OLD/deploy/staging/native/build-release.sh"
[[ $(readlink -f "$ROOT/current") == "$ROOT/releases/$NEW" ]] || exit 2
[[ $(git -C "$ROOT/current" rev-parse HEAD) == "$NEW" ]] || exit 2
[[ $(sha256sum "$ROOT/current/public/fadego-mark.webp" | cut -d' ' -f1) == "$DIGEST" ]] || exit 2

systemctl restart fadego-staging.service
ready=0
for attempt in $(seq 1 40); do
  if [[ $(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:3100/ 2>/dev/null || true) == 200 ]]; then
    ready=1; break
  fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo 'FADEGO_BRAND_APP_NOT_READY'; exit 2; }
served="$(curl -fsS --max-time 12 http://127.0.0.1:3100/fadego-mark.webp | sha256sum | cut -d' ' -f1)"
[[ "$served" == "$DIGEST" ]] || { echo 'FADEGO_BRAND_BAD_APP_IMAGE'; exit 2; }
python3 - "$(systemctl show -p MainPID --value fadego-staging.service)" <<'PY_GATES'
import sys
pid = int(sys.argv[1])
if pid < 2: raise SystemExit("FADEGO_BRAND_NO_PROCESS")
with open(f"/proc/{pid}/environ", "rb") as f:
    values = dict(p.split(b"=", 1) for p in f.read().split(b"\0") if b"=" in p)
if values.get(b"BOOKING_EMAIL_PROVIDER") != b"disabled" or values.get(b"GMAIL_LIVE_SEND_ENABLED") != b"false":
    raise SystemExit("FADEGO_BRAND_UNSAFE_MAIL_GATES")
print("FADEGO_BRAND_MAIL_GATES=DISABLED")
PY_GATES
echo 'FADEGO_BRAND_APPLICATION=APPROVED_SCISSORS_IMAGE'

# Update existing no-login demo with exact same image, embedded as data URI only.
python3 - "$PREVIEW" "$VHOST" "$ROOT/current/public/fadego-mark.webp" <<'PY_PREVIEW'
from pathlib import Path
import base64,sys
htmlfile,conf,art = map(Path,sys.argv[1:])
html=htmlfile.read_text()
nginx=conf.read_text()
anchor='<span class="mark">F</span>'
if html.count(anchor)!=1: raise SystemExit('FADEGO_BRAND_UNEXPECTED_PREVIEW')
start='    # FADEGO_PREVIEW_BEGIN: exact-path fake-data walkthrough\n'
end='    # FADEGO_PREVIEW_END\n'
if nginx.count(start)!=1 or nginx.count(end)!=1: raise SystemExit('FADEGO_BRAND_UNEXPECTED_NGINX')
prefix,rest=nginx.split(start,1)
part,suffix=rest.split(end,1)
if part.count("img-src 'none'")!=1 or "connect-src 'none'" not in part:
    raise SystemExit('FADEGO_BRAND_PREVIEW_CSP_UNEXPECTED')
img='<img alt="" width="40" height="40" style="width:40px;height:40px;display:block;object-fit:contain;border-radius:9px" src="data:image/webp;base64,'+base64.b64encode(art.read_bytes()).decode()+'">'
htmlfile.write_text(html.replace(anchor,img))
conf.write_text(prefix+start+part.replace("img-src 'none'","img-src data:")+end+suffix)
print('FADEGO_BRAND_PREVIEW=OWNER_SCISSORS')
PY_PREVIEW
nginx -t -q
systemctl reload nginx

# No loss of Basic Auth outside the exact static demo.
demo=000
for attempt in $(seq 1 18); do
  demo="$(curl -sS --max-time 7 -o /dev/null -w '%{http_code}' --resolve fadego.duckdns.org:443:127.0.0.1 https://fadego.duckdns.org/experimentar 2>/dev/null || true)"
  [[ "$demo" == 200 ]] && break
  sleep 1
done
[[ "$demo" == 200 ]] || { echo 'FADEGO_BRAND_DEMO_NOT_PUBLIC'; exit 2; }
for route in / /admin /login /api/auth/session; do
  status="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' --resolve fadego.duckdns.org:443:127.0.0.1 "https://fadego.duckdns.org$route")"
  [[ "$status" == 401 ]] || { echo 'FADEGO_BRAND_PRIVATE_AUTH_REGRESSION'; exit 2; }
done
preview_body="$(curl -fsS --max-time 10 --resolve fadego.duckdns.org:443:127.0.0.1 \
  https://fadego.duckdns.org/experimentar)"
[[ "$preview_body" == *'data:image/webp;base64,'* ]] || { echo 'FADEGO_BRAND_PREVIEW_MARK_ABSENT'; exit 2; }
STAGING_GATE_USER=fadego-pilot STAGING_GATE_PASSWORD="$(cat "$VAULT")" \
  node "$ROOT/current/scripts/smoke-staging.mjs"
echo 'FADEGO_BRANDING_DEPLOY=SUCCESS'
echo 'FADEGO_DEMO=PUBLIC_200_NO_LOGIN'
echo 'FADEGO_APPLICATION_PRIVATE=401'
echo 'FADEGO_GMAIL_SEND=DISABLED'
