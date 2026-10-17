#!/usr/bin/env bash
# Deploy the Owner-approved INSTITUTIONAL homepage, public reading only.
# One isolated FADEGO vhost. Portal, tenant, bookings and APIs keep Basic Auth.
set -Eeuo pipefail
umask 077
NEW="0c01fcf625f491b40068cfc495ddbdb5962a6da7"
OLD="9243689cbb177ea814cf055ad18ea5d1967529e5"
ART_SHA256="8386058306f181827baa886e58262d2834044fa18a8e7bb2f488ce8b77f7c7c8"
ROOT="/srv/fadego-staging"
VHOST="/etc/nginx/sites-available/fadego-staging.conf"
PREVIEW="/var/www/fadego-preview/index.html"
ENV="/etc/fadego-staging/app.env"
MAIL_CLOSED="/etc/fadego-staging/send-closed.env"
BASIC_VAULT="/root/project-secrets/fadego-staging/basic-password"

if [[ "$(id -u)" != "0" || "${FADEGO_PUBLIC_WEBSITE_APPROVED:-}" != "1" ]]; then
  echo "FADEGO_PUBLIC_REFUSED_AUTHORITY"; exit 2
fi
exec 9>/run/fadego-staging-install.lock
flock -n 9 || { echo "FADEGO_PUBLIC_REFUSED_CONCURRENT_STAGING_UPDATE"; exit 2; }
for c in curl git nginx systemctl python3 runuser sha256sum corepack node; do
  command -v "$c" >/dev/null || { echo "FADEGO_PUBLIC_REFUSED_MISSING_TOOL=$c"; exit 2; }
done
[[ -L "$ROOT/current" && ! -L "$ROOT/releases" ]] || exit 2
[[ "$(readlink -f "$ROOT/current")" == "$ROOT/releases/$OLD" ]] || { echo "FADEGO_PUBLIC_REFUSED_WRONG_CURRENT_RELEASE"; exit 2; }
[[ "$(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD)" == "$OLD" ]] || exit 2
[[ ! -e "$ROOT/releases/$NEW" && ! -L "$ROOT/releases/$NEW" &&
   ! -e "$ROOT/current.next" && ! -L "$ROOT/current.next" ]] || exit 2
[[ -f "$VHOST" && ! -L "$VHOST" && -f "$PREVIEW" && ! -L "$PREVIEW" ]] || exit 2
[[ -s "$ENV" && -s "$MAIL_CLOSED" && -s "$BASIC_VAULT" ]] || exit 2
[[ "$(stat -c '%U' "$VHOST")" == "root" ]] || exit 2
grep -Fxq 'BOOKING_EMAIL_PROVIDER=disabled' "$MAIL_CLOSED"
grep -Fxq 'GMAIL_LIVE_SEND_ENABLED=false' "$MAIL_CLOSED"
grep -Fxq 'EnvironmentFile=/etc/fadego-staging/send-closed.env' /etc/systemd/system/fadego-staging.service
grep -Fq 'auth_basic "FADEGO - ambiente de testes";' "$VHOST"
grep -Fq 'auth_basic_user_file /etc/nginx/fadego-staging.htpasswd;' "$VHOST"
grep -Fq 'server_name fadego.duckdns.org;' "$VHOST"
grep -Fq 'proxy_pass http://127.0.0.1:3100;' "$VHOST"
[[ "$(grep -Fc 'FADEGO_PREVIEW_BEGIN' "$VHOST")" == "1" &&
   "$(grep -Fc 'FADEGO_PREVIEW_END' "$VHOST")" == "1" ]] || exit 2
if grep -Fq 'FADEGO_PUBLIC_WEBSITE_BEGIN' "$VHOST"; then
  echo "FADEGO_PUBLIC_REFUSED_ALREADY_MODIFIED"; exit 2
fi
grep -Fq 'data:image/webp;base64,' "$PREVIEW"
systemctl is-active --quiet fadego-staging.service
systemctl is-active --quiet nginx

prior_vhost="$(mktemp /etc/nginx/sites-available/.fadego-public-vhost.XXXXXXXX)"
cp -p "$VHOST" "$prior_vhost"
rollback() {
  local rc=$?
  trap - EXIT
  if [[ "$rc" != 0 ]]; then
    cp -p "$prior_vhost" "$VHOST"
    nginx -t -q && systemctl reload nginx || true
    if [[ "$(readlink -f "$ROOT/current" || true)" == "$ROOT/releases/$NEW" ]]; then
      ln -s "$ROOT/releases/$OLD" "$ROOT/current.public-revert"
      mv -Tf "$ROOT/current.public-revert" "$ROOT/current"
      systemctl restart fadego-staging.service || true
    fi
    echo "FADEGO_PUBLIC_ROLLBACK=PREVIOUS_VERSION_AND_AUTH_POLICY"
  fi
  rm -f "$prior_vhost"
  exit "$rc"
}
trap rollback EXIT

# Reuse the previously certified FADEGO staging release builder.
set -a
source "$ENV"
set +a
export BOOKING_EMAIL_PROVIDER=disabled GMAIL_LIVE_SEND_ENABLED=false
export FADEGO_STAGING_SUPERVISOR_APPROVED=1 FADEGO_STAGING_APPROVED_SHA="$NEW"
export HOME="$ROOT" COREPACK_HOME="$ROOT/.cache/corepack"
runuser -u fadego-staging -m -- bash "$ROOT/releases/$OLD/deploy/staging/native/build-release.sh"
[[ "$(readlink -f "$ROOT/current")" == "$ROOT/releases/$NEW" ]] || exit 2
[[ "$(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD)" == "$NEW" ]] || exit 2
[[ "$(sha256sum "$ROOT/current/public/fadego-mark.webp" | cut -d' ' -f1)" == "$ART_SHA256" ]] || exit 2

systemctl restart fadego-staging.service
ready=0
for attempt in $(seq 1 40); do
  if [[ "$(curl -sS --max-time 4 -o /dev/null -w '%{http_code}' http://127.0.0.1:3100/ 2>/dev/null || true)" == 200 ]]; then
    ready=1; break
  fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo "FADEGO_PUBLIC_REFUSED_NEW_APP_NOT_READY"; exit 2; }
local_home="$(curl -fsS --max-time 15 http://127.0.0.1:3100/)"
for marker in 'Como funciona' 'Portal FADEGO' 'Website FADEGO' 'Painel de cada barbearia' 'Página de reservas'; do
  [[ "$local_home" == *"$marker"* ]] || { echo "FADEGO_PUBLIC_REFUSED_MISSING_INSTITUTIONAL_CONTENT"; exit 2; }
done
[[ "$local_home" != *'href="/experimentar"'* ]] || { echo "FADEGO_PUBLIC_REFUSED_DEMO_LINK_ON_SITE"; exit 2; }
[[ "$local_home" == *'href="/login"'* ]] || { echo "FADEGO_PUBLIC_REFUSED_PORTAL_LINK_MISSING"; exit 2; }
[[ "$(curl -fsS --max-time 10 http://127.0.0.1:3100/fadego-mark.webp | sha256sum | cut -d' ' -f1)" == "$ART_SHA256" ]] || exit 2
echo 'FADEGO_PUBLIC_INSTITUTIONAL_APP=READY'

python3 - "$(systemctl show -p MainPID --value fadego-staging.service)" <<'PY_GATES'
import sys
pid=int(sys.argv[1])
if pid < 2: raise SystemExit("FADEGO_PUBLIC_REFUSED_SERVICE_PID")
with open(f"/proc/{pid}/environ","rb") as file:
    vals=dict(x.split(b"=",1) for x in file.read().split(b"\0") if b"=" in x)
if vals.get(b"BOOKING_EMAIL_PROVIDER") != b"disabled" or vals.get(b"GMAIL_LIVE_SEND_ENABLED") != b"false":
    raise SystemExit("FADEGO_PUBLIC_REFUSED_MAIL_GATES")
print("FADEGO_PUBLIC_MAIL_GATES=DISABLED")
PY_GATES

# Only permit the exact institutional "/" and its necessary immutable,
# public Next.js assets. The server-level Basic auth stays in force elsewhere.
python3 - "$VHOST" <<'PY_NGINX'
from pathlib import Path
import sys
path=Path(sys.argv[1])
source=path.read_text(encoding="utf-8")
anchor="    location / {\n"
if source.count(anchor)!=1 or source.count("    client_max_body_size 1m;\n")!=1:
    raise SystemExit("FADEGO_PUBLIC_REFUSED_UNEXPECTED_VHOST_LAYOUT")
if source.count('    auth_basic "FADEGO - ambiente de testes";')!=1:
    raise SystemExit("FADEGO_PUBLIC_REFUSED_WRONG_AUTH_BASELINE")
if "FADEGO_PUBLIC_WEBSITE_BEGIN" in source:
    raise SystemExit("FADEGO_PUBLIC_REFUSED_DUPLICATE_PUBLIC_BLOCK")

block="""
    # FADEGO_PUBLIC_WEBSITE_BEGIN: public reading only, never the portal or bookings.
    location = / {
        auth_basic off;
        proxy_pass http://127.0.0.1:3100;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Authorization "";
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }
    # Next.js compiled static CSS/JS used by the static institutional home.
    location ^~ /_next/static/ {
        auth_basic off;
        proxy_pass http://127.0.0.1:3100;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Authorization "";
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }
    location = /fadego-mark.webp {
        auth_basic off;
        proxy_pass http://127.0.0.1:3100;
        proxy_set_header Host $host;
        proxy_set_header Authorization "";
        proxy_set_header Connection "";
    }
    location = /fadego-atelier.svg {
        auth_basic off;
        proxy_pass http://127.0.0.1:3100;
        proxy_set_header Host $host;
        proxy_set_header Authorization "";
        proxy_set_header Connection "";
    }
    # FADEGO_PUBLIC_WEBSITE_END

"""
path.write_text(source.replace(anchor,block+anchor,1),encoding="utf-8")
print("FADEGO_PUBLIC_NGINX=EXACT_HOMEPAGE_AND_STATIC_ASSETS_ONLY")
PY_NGINX
nginx -t -q
systemctl reload nginx

home_status=000
for attempt in $(seq 1 20); do
  home_status="$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' --resolve fadego.duckdns.org:443:127.0.0.1 https://fadego.duckdns.org/ 2>/dev/null || true)"
  [[ "$home_status" == 200 ]] && break
  sleep 1
done
[[ "$home_status" == 200 ]] || { echo "FADEGO_PUBLIC_REFUSED_HOME_STILL_PRIVATE"; exit 2; }

for route in /login /admin /super-admin /api/auth/session /api/public/barbershops/example/availability /b/example /_next/image; do
  code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' --resolve fadego.duckdns.org:443:127.0.0.1 "https://fadego.duckdns.org$route")"
  [[ "$code" == 401 ]] || { echo "FADEGO_PUBLIC_REFUSED_PRIVATE_ROUTE_EXPOSED"; exit 2; }
done
for route in /fadego-mark.webp /fadego-atelier.svg /experimentar; do
  code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' --resolve fadego.duckdns.org:443:127.0.0.1 "https://fadego.duckdns.org$route")"
  [[ "$code" == 200 ]] || { echo "FADEGO_PUBLIC_REFUSED_PUBLIC_ASSET_OR_OWNER_PREVIEW"; exit 2; }
done

# Validate real CSS/JS paths from the actual HTML; no broad '/_next/' opening.
tmp_html="$(mktemp)"
tmp_assets="$(mktemp)"
curl -fsS --max-time 20 --resolve fadego.duckdns.org:443:127.0.0.1 https://fadego.duckdns.org/ > "$tmp_html"
python3 - "$tmp_html" "$tmp_assets" <<'PY_ASSETS'
import re,sys
from pathlib import Path
text=Path(sys.argv[1]).read_text(encoding="utf-8")
assets=sorted(set(re.findall(r'/_next/static/[A-Za-z0-9_.~!$&()+,;=@/%-]+\.(?:css|js)(?:\?[^"<> ]+)?',text)))
css=[v for v in assets if ".css" in v]
js=[v for v in assets if ".js" in v]
if not css or not js:
    raise SystemExit("FADEGO_PUBLIC_REFUSED_STATIC_BUNDLES_MISSING")
Path(sys.argv[2]).write_text(css[0]+"\n"+js[0]+"\n")
print("FADEGO_PUBLIC_HTML_ASSETS=CSS_AND_JS_REFERENCED")
PY_ASSETS
while IFS= read -r asset; do
  code="$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' --resolve fadego.duckdns.org:443:127.0.0.1 "https://fadego.duckdns.org$asset")"
  [[ "$code" == 200 ]] || { echo "FADEGO_PUBLIC_REFUSED_ASSET_BLOCKED"; exit 2; }
done < "$tmp_assets"
rm -f "$tmp_html" "$tmp_assets"

# Existing smoke-staging.mjs intentionally requires a private homepage, so
# use a narrower equivalent for the new public-home/private-portal contract.
STAGING_GATE_USER=fadego-pilot STAGING_GATE_PASSWORD="$(cat "$BASIC_VAULT")" node <<'PY_PORTAL'
const assert = require("node:assert/strict")
const host = "https://fadego.duckdns.org"
const auth = "Basic " + Buffer.from(
  process.env.STAGING_GATE_USER + ":" + process.env.STAGING_GATE_PASSWORD,
  "utf8",
).toString("base64")
const request = async (path, header) => fetch(host + path, {
  redirect: "manual",
  signal: AbortSignal.timeout(12000),
  headers: header ? { Authorization: header } : {},
})
;(async () => {
  const home = await request("/")
  assert.equal(home.status, 200)
  assert.equal(home.headers.get("www-authenticate"), null)
  assert.match(home.headers.get("x-robots-tag") || "", /noindex/i)
  assert.match(home.headers.get("referrer-policy") || "", /no-referrer/i)
  assert.match(await home.text(), /Website FADEGO/)
  const privateLogin = await request("/login")
  assert.equal(privateLogin.status, 401)
  assert.match(privateLogin.headers.get("www-authenticate") || "", /^Basic(?:\s|$)/i)
  await privateLogin.body?.cancel()
  // Encode a genuinely wrong password; appending bytes to a Basic base64 token
  // can be ignored by decoders and falsely appear authenticated.
  const incorrect = "Basic " + Buffer.from(
    process.env.STAGING_GATE_USER + ":" + process.env.STAGING_GATE_PASSWORD + "-incorrect",
    "utf8",
  ).toString("base64")
  const bad = await request("/login", incorrect)
  assert.equal(bad.status, 401, "Private login must reject an actually wrong password")
  await bad.body?.cancel()
  const login = await request("/login", auth)
  assert.equal(login.status, 200)
  assert.match(await login.text(), /FADEGO/)
  const admin = await request("/admin", auth)
  assert.ok([301,302,303,307,308].includes(admin.status))
  assert.equal(new URL(admin.headers.get("location"),host).pathname, "/login")
  await admin.body?.cancel()
  console.log("FADEGO_PUBLIC_HTTPS_AND_PRIVATE_PORTAL_SMOKE=PASS")
})().catch(error => { console.error(error.message); process.exitCode = 1 })
PY_PORTAL

echo "FADEGO_PUBLIC_WEBSITE=HTTPS_200_WITHOUT_PASSWORD"
echo "FADEGO_PUBLIC_PORTAL_AND_BOOKINGS=STILL_AUTHENTICATED"
echo "FADEGO_PUBLIC_BRANDING=OWNER_APPROVED"
echo "FADEGO_PUBLIC_GMAIL=DISABLED"
echo "FADEGO_PUBLIC_STAGING_DEPLOY=SUCCESS"
