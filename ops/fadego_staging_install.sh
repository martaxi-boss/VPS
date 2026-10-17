#!/usr/bin/env bash
# FADEGO staging installation: approved exact release, no other applications.
set -Eeuo pipefail
umask 077

SHA=7e2b6c0d00809eb65c800737daeb660c2869e077
DOMAIN=fadego.duckdns.org
IP=146.59.145.3
ROOT=/srv/fadego-staging
CONF=/etc/fadego-staging
VAULT=/root/project-secrets/fadego-staging
BASE=https://raw.githubusercontent.com/martaxi-boss/fadego/$SHA/deploy/staging/native

if [[ "$(id -u)" != 0 ]]; then echo 'STAGING_REFUSED_NOT_ROOT'; exit 2; fi
if [[ "${FADEGO_STAGING_TRANSITION_APPROVED:-}" != 1 ]]; then
  echo 'STAGING_REFUSED_WITHOUT_SUPERVISOR_TRANSITION'; exit 2
fi
if ! getent ahostsv4 "$DOMAIN" | awk -v ip="$IP" '$1==ip {ok=1} END{exit !ok}'; then
  echo 'STAGING_REFUSED_DNS_IP_MISMATCH'; exit 2
fi
if ! systemctl is-active --quiet nginx || ! systemctl is-active --quiet postgresql; then
  echo 'STAGING_REFUSED_SHARED_SERVICES_UNAVAILABLE'; exit 2
fi
for program in git node corepack nginx certbot openssl curl runuser psql flock; do
  if ! command -v "$program" >/dev/null 2>&1; then echo "STAGING_MISSING_TOOL=$program"; exit 2; fi
done
if ! node -p 'process.versions.node.split(".")[0]' | grep -qx 22; then
  echo 'STAGING_REFUSED_UNSUPPORTED_NODE_VERSION'; exit 2
fi
if [[ ( -e /etc/nginx/sites-enabled/fadego-staging.conf || -L /etc/nginx/sites-enabled/fadego-staging.conf ) &&
      "$(readlink /etc/nginx/sites-enabled/fadego-staging.conf || true)" != /etc/nginx/sites-available/fadego-staging.conf ]]; then
  echo 'STAGING_REFUSED_UNEXPECTED_HTTPS_VHOST'; exit 2
fi
if [[ ( -e /etc/nginx/sites-enabled/fadego-staging-acme.conf || -L /etc/nginx/sites-enabled/fadego-staging-acme.conf ) &&
      "$(readlink /etc/nginx/sites-enabled/fadego-staging-acme.conf || true)" != /etc/nginx/sites-available/fadego-staging-acme.conf ]]; then
  echo 'STAGING_REFUSED_UNEXPECTED_ACME_VHOST'; exit 2
fi
if grep -RiqE 'server_name[[:space:]]+fadego[.]duckdns[.]org' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null; then
  if [[ ! -L /etc/nginx/sites-enabled/fadego-staging.conf && ! -L /etc/nginx/sites-enabled/fadego-staging-acme.conf ]]; then
    echo 'STAGING_REFUSED_CONFLICTING_SHARED_VHOST'; exit 2
  fi
fi
if [[ -e "$ROOT" && ( -L "$ROOT" || ! -d "$ROOT" ) ]]; then
  echo 'STAGING_REFUSED_UNEXPECTED_ROOT'; exit 2
fi
if [[ -e "$CONF" && ( -L "$CONF" || ! -d "$CONF" ) ]]; then
  echo 'STAGING_REFUSED_UNEXPECTED_CONFIG'; exit 2
fi

exec 9>/run/fadego-staging-install.lock
flock -n 9 || { echo 'STAGING_ALREADY_INSTALLING'; exit 2; }

if ! id fadego-staging >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$ROOT" --shell /usr/sbin/nologin fadego-staging
fi
install -d -o fadego-staging -g fadego-staging -m 0750 "$ROOT" "$ROOT/releases"
install -d -o root -g root -m 0700 "$CONF" "$VAULT"

had_config=0
if [[ -e "$CONF/app.env" ]]; then had_config=1; fi
if [[ ! -e "$CONF/app.env" ]]; then
  db_pass="$(openssl rand -hex 32)"
  auth_secret="$(openssl rand -hex 32)"
  cat > "$CONF/app.env" <<EOF
DATABASE_URL=postgresql://fadego_staging:$db_pass@127.0.0.1:5432/fadego_staging?schema=public
NEXTAUTH_URL=https://fadego.duckdns.org
NEXTAUTH_SECRET=$auth_secret
FADEGO_TRUST_PROXY_HOPS=0
BOOKING_EMAIL_PROVIDER=disabled
GMAIL_LIVE_SEND_ENABLED=false
EOF
  chmod 0600 "$CONF/app.env"
fi
if [[ "$(stat -c %u "$CONF/app.env")" != 0 || "$(stat -c %a "$CONF/app.env")" != 600 ]]; then
  echo 'STAGING_REFUSED_UNSAFE_ENV_FILE'; exit 2
fi
if grep -Ev '^(DATABASE_URL=postgresql://fadego_staging:[a-f0-9]{64}@127[.]0[.]0[.]1:5432/fadego_staging[?]schema=public|NEXTAUTH_URL=https://fadego[.]duckdns[.]org|NEXTAUTH_SECRET=[a-f0-9]{64}|FADEGO_TRUST_PROXY_HOPS=0|BOOKING_EMAIL_PROVIDER=disabled|GMAIL_LIVE_SEND_ENABLED=false)$' "$CONF/app.env" | grep -q .; then
  echo 'STAGING_REFUSED_UNEXPECTED_ENV_CONTENT'; exit 2
fi
if [[ $(wc -l < "$CONF/app.env") -ne 6 ]]; then echo 'STAGING_REFUSED_ENV_LINES'; exit 2; fi
for key in DATABASE_URL NEXTAUTH_URL NEXTAUTH_SECRET FADEGO_TRUST_PROXY_HOPS BOOKING_EMAIL_PROVIDER GMAIL_LIVE_SEND_ENABLED; do
  if [[ $(grep -c "^$key=" "$CONF/app.env") -ne 1 ]]; then
    echo 'STAGING_REFUSED_ENV_DUPLICATE_OR_MISSING'; exit 2
  fi
done
set -a
source "$CONF/app.env"
set +a
db_pass="${DATABASE_URL#postgresql://fadego_staging:}"
db_pass="${db_pass%%@*}"

# The shared Gmail vault may include send flags. Never mutate it.
# The FADEGO-only unit gets its own FINAL EnvironmentFile forcing both gates
# closed, even when the existing OAuth vault defines different values.
echo 'FADEGO_SHARED_GMAIL_VAULT=UNCHANGED'

role_exists="$(runuser -u postgres -- psql -qAt -c "SELECT 1 FROM pg_roles WHERE rolname='fadego_staging'")"
db_exists="$(runuser -u postgres -- psql -qAt -c "SELECT 1 FROM pg_database WHERE datname='fadego_staging'")"
if [[ "$had_config" == 0 && ( -n "$role_exists" || -n "$db_exists" ) ]]; then
  echo 'STAGING_REFUSED_PREEXISTING_DATABASE_OBJECTS'; exit 2
fi
if [[ -z "$role_exists" ]]; then
  printf "CREATE ROLE fadego_staging LOGIN PASSWORD '%s';\n" "$db_pass" | runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q >/dev/null
else
  printf "ALTER ROLE fadego_staging PASSWORD '%s';\n" "$db_pass" | runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q >/dev/null
fi
if [[ -z "$db_exists" ]]; then
  runuser -u postgres -- createdb --owner=fadego_staging fadego_staging
else
  owner="$(runuser -u postgres -- psql -qAt -c "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='fadego_staging'")"
  if [[ "$owner" != fadego_staging ]]; then echo 'STAGING_REFUSED_OTHER_DATABASE_OWNER'; exit 2; fi
fi
echo 'FADEGO_STAGING_DB=ISOLATED'

# Test-only credentials remain in the root VPS vault. Never print them.
if [[ ! -e "$VAULT/admin-password" ]]; then
  openssl rand -hex 24 > "$VAULT/admin-password"
  chmod 0600 "$VAULT/admin-password"
fi
if [[ ! -e "$VAULT/basic-password" ]]; then
  openssl rand -hex 24 > "$VAULT/basic-password"
  chmod 0600 "$VAULT/basic-password"
fi
gate_user=fadego-pilot
gate_pass="$(cat "$VAULT/basic-password")"
if [[ ! "$gate_pass" =~ ^[a-f0-9]{48}$ ]]; then echo 'STAGING_REFUSED_GATE_SECRET'; exit 2; fi
printf '%s\n' "$gate_pass" | openssl passwd -6 -stdin | {
  IFS= read -r gate_hash
  printf '%s:%s\n' "$gate_user" "$gate_hash" > /etc/nginx/fadego-staging.htpasswd
}
if ! getent group www-data >/dev/null; then echo 'STAGING_REFUSED_NGINX_AUTH_GROUP'; exit 2; fi
chgrp www-data /etc/nginx/fadego-staging.htpasswd
chmod 0640 /etc/nginx/fadego-staging.htpasswd

download() {
  local name="$1" to="$2"
  curl -fsSL --retry 2 --connect-timeout 10 --max-time 40 "$BASE/$name" -o "$to"
}
install -d -m 0700 "$CONF/reviewed"
download build-release.sh "$CONF/reviewed/build-release.sh"
download fadego-staging.service "$CONF/reviewed/fadego-staging.service"
download nginx-acme.conf "$CONF/reviewed/nginx-acme.conf"
download nginx-https.conf "$CONF/reviewed/nginx-https.conf"
bash -n "$CONF/reviewed/build-release.sh"
if ! grep -q 'FADEGO_STAGING_SUPERVISOR_APPROVED' "$CONF/reviewed/build-release.sh"; then
  echo 'STAGING_REFUSED_MISSING_RELEASE_GUARD'; exit 2
fi

if [[ ! -L "$ROOT/current" || "$(readlink -f "$ROOT/current")" != "$ROOT/releases/$SHA" ]]; then
  export HOME="$ROOT"
  export COREPACK_HOME="$ROOT/.cache/corepack"
  export FADEGO_STAGING_SUPERVISOR_APPROVED=1
  export FADEGO_STAGING_APPROVED_SHA="$SHA"
  runuser -u fadego-staging -m -- bash -s < "$CONF/reviewed/build-release.sh"
fi
if [[ "$(readlink -f "$ROOT/current")" != "$ROOT/releases/$SHA" ]]; then
  echo 'STAGING_REFUSED_RELEASE_SHA'; exit 2
fi
echo 'FADEGO_RELEASE_SHA=VERIFIED'

if ! grep -Fxq 'EnvironmentFile=-/root/project-secrets/fadego-gmail/oauth.env' "$CONF/reviewed/fadego-staging.service"; then
  echo 'STAGING_REFUSED_UNEXPECTED_GMAIL_UNIT_ENV_ORDER'; exit 2
fi
printf '%s\n' 'BOOKING_EMAIL_PROVIDER=disabled' 'GMAIL_LIVE_SEND_ENABLED=false' > "$CONF/send-closed.env"
chmod 0600 "$CONF/send-closed.env"
install -o root -g root -m 0644 "$CONF/reviewed/fadego-staging.service" /etc/systemd/system/fadego-staging.service
sed -i '/^EnvironmentFile=-\/root\/project-secrets\/fadego-gmail\/oauth.env$/a EnvironmentFile=/etc/fadego-staging/send-closed.env' /etc/systemd/system/fadego-staging.service
if ! grep -Fxq 'EnvironmentFile=/etc/fadego-staging/send-closed.env' /etc/systemd/system/fadego-staging.service; then
  echo 'STAGING_REFUSED_MISSING_FINAL_SEND_GATE'; exit 2
fi
systemctl daemon-reload
systemctl enable --now fadego-staging.service >/dev/null
if ! systemctl is-active --quiet fadego-staging.service; then
  echo 'STAGING_REFUSED_APP_SERVICE'; exit 2
fi
ready=0
for i in $(seq 1 35); do
  status="$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:3100/ 2>/dev/null || true)"
  if [[ "$status" == 200 ]]; then ready=1; break; fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo 'STAGING_LOCAL_HTTP=FAILED'; exit 2; fi
echo 'STAGING_LOCAL_HTTP=200'
python3 - "$(systemctl show -p MainPID --value fadego-staging.service)" <<'PY_GATES'
import sys
pid = int(sys.argv[1])
if pid < 2:
    raise SystemExit('STAGING_REFUSED_NO_SERVICE_PID')
with open(f'/proc/{pid}/environ', 'rb') as stream:
    values = dict(part.split(b'=', 1) for part in stream.read().split(b'\0') if b'=' in part)
if values.get(b'BOOKING_EMAIL_PROVIDER') != b'disabled' or values.get(b'GMAIL_LIVE_SEND_ENABLED') != b'false':
    raise SystemExit('STAGING_REFUSED_UNSAFE_EFFECTIVE_MAIL_GATES')
print('STAGING_EFFECTIVE_MAIL_GATES=DISABLED')
PY_GATES

user_count="$(runuser -u postgres -- psql -qAt -d fadego_staging -c 'SELECT count(*) FROM "User"' 2>/dev/null || true)"
if [[ "$user_count" == 0 ]]; then
  export FADEGO_BOOTSTRAP_EMAIL=pilot-admin@fadego.invalid
  export FADEGO_BOOTSTRAP_PASSWORD="$(cat "$VAULT/admin-password")"
  export FADEGO_BOOTSTRAP_NAME='FADEGO Pilot Admin'
  ( cd "$ROOT/current" && runuser -u fadego-staging -m -- /usr/bin/node node_modules/tsx/dist/cli.mjs scripts/bootstrap-admin.ts ) >/dev/null
  unset FADEGO_BOOTSTRAP_PASSWORD
  echo 'STAGING_DEMO_ADMIN=CREATED'
fi

# Certbot is webroot-only: never let it edit another site's Nginx vhosts.
install -d -m 0755 /var/www/letsencrypt/.well-known/acme-challenge
install -o root -g root -m 0644 "$CONF/reviewed/nginx-acme.conf" /etc/nginx/sites-available/fadego-staging-acme.conf
ln -sfn /etc/nginx/sites-available/fadego-staging-acme.conf /etc/nginx/sites-enabled/fadego-staging-acme.conf
if ! nginx -t -q; then
  rm -f /etc/nginx/sites-enabled/fadego-staging-acme.conf
  echo 'STAGING_REFUSED_NGINX_ACME_CONFIG'; exit 2
fi
systemctl reload nginx

certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
  --webroot --webroot-path /var/www/letsencrypt \
  --cert-name "$DOMAIN" -d "$DOMAIN" --keep-until-expiring -q
if [[ ! -s /etc/letsencrypt/live/fadego.duckdns.org/fullchain.pem ]]; then
  echo 'STAGING_REFUSED_MISSING_CERTIFICATE'; exit 2
fi
install -o root -g root -m 0644 "$CONF/reviewed/nginx-https.conf" /etc/nginx/sites-available/fadego-staging.conf
ln -sfn /etc/nginx/sites-available/fadego-staging.conf /etc/nginx/sites-enabled/fadego-staging.conf
if ! nginx -t -q; then
  rm -f /etc/nginx/sites-enabled/fadego-staging.conf
  echo 'STAGING_REFUSED_NGINX_HTTPS_CONFIG'; exit 2
fi
systemctl reload nginx

STAGING_GATE_USER="$gate_user" STAGING_GATE_PASSWORD="$gate_pass" \
  node "$ROOT/current/scripts/smoke-staging.mjs"
if [[ -e /root/project-secrets/fadego-gmail/oauth.env ]]; then
  python3 "$ROOT/current/scripts/check-gmail-vault.py" || true
fi
if systemctl is-active --quiet fadego-booking-email.timer; then
  echo 'STAGING_REFUSED_UNAPPROVED_MAIL_WORKER'; exit 2
fi
printf '%s\n' 'FADEGO_STAGING_INSTALL=SUCCESS' 'GMAIL_LIVE_SEND=DISABLED' 'OTHER_SERVICES=UNTOUCHED'
