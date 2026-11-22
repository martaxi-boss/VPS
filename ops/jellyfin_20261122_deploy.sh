#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
DOMAIN=serveriptv.duckdns.org
IP=146.59.145.3
ROOT=/srv/projects/jellyfin-server
UNIT=/etc/systemd/system/jellyfin-pink.service
CONF=/etc/nginx/conf.d/jellyfin-serveriptv.conf
CERT=/etc/letsencrypt/live/$DOMAIN
USER_NAME=jellyfinpink
SERVER_URL=https://repo.jellyfin.org/files/server/linux/latest-stable/amd64/jellyfin_12.4-amd64.tar.gz
WEB_URL=https://repo.jellyfin.org/files/server/ubuntu/latest-stable/amd64/jellyfin-web_12.4+ubu2404_all.deb
CREATED_UNIT=0
CREATED_CONF=0
CHANGED_SITE=0
fail() { echo "JELLYFIN_DEPLOY_BLOCKED: $1" >&2; exit 1; }
restore() {
  rc=$?
  if ((rc != 0)); then
    echo "JELLYFIN_ROLLBACK=START status=$rc"
    if ((CREATED_CONF)); then rm -f "$CONF"; fi
    if ((CREATED_UNIT)); then
      systemctl disable --now jellyfin-pink.service >/dev/null 2>&1 || :
      rm -f "$UNIT"
      systemctl daemon-reload >/dev/null 2>&1 || :
    fi
    if ((CHANGED_SITE)); then nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || :; fi
    echo 'JELLYFIN_ROLLBACK=OWN_SERVICE_AND_NGINX_REMOVED;OWN_PROJECT_DATA_PRESERVED'
  fi
  exit "$rc"
}
trap restore EXIT
[[ $(id -u) -eq 0 ]] || fail 'sudo/root permission required'
[[ -d /srv/projects ]] || fail 'project root missing'
# Resume is permitted ONLY for the exact partial install left by the first guarded run.
if [[ -e "$ROOT" ]]; then
  [[ -d "$ROOT" && -L "$ROOT/current" && -x "$ROOT/current/jellyfin" ]] || fail 'unexpected existing Jellyfin root'
  [[ "$(readlink -f "$ROOT/current")" == "$ROOT/releases/12.4/jellyfin" ]] || fail 'unexpected Jellyfin release path'
  [[ ! -e "$ROOT/secrets/admin-initial.json" ]] || fail 'admin secret exists; refuse unsafe resume'
  if [[ -e "$ROOT/start.sh" ]]; then
    grep -Fq 'exec "$ROOT/current/jellyfin"' "$ROOT/start.sh" || fail 'unexpected existing start script'
  fi
fi
[[ ! -e "$UNIT" && ! -e "$CONF" && ! -e "$CERT" ]] || fail 'existing Jellyfin service or certificate; refuse overwrite'
systemctl is-active --quiet nginx || fail 'Nginx not active'
nginx -t >/dev/null 2>&1 || fail 'existing Nginx config invalid'
getent ahostsv4 "$DOMAIN" | awk '{print $1}' | grep -Fxq "$IP" || fail 'DuckDNS mismatch'
[[ $(df -PB1 /srv/projects | awk 'NR==2 {print $4}') -gt 8589934592 ]] || fail 'less than 8 GiB free'
if ss -lntH 'sport = :8096' | grep -q .; then fail 'port 8096 already occupied'; fi
for c in curl dpkg-deb certbot python3 tar nginx openssl; do command -v "$c" >/dev/null || fail "missing $c"; done
if pgrep -x certbot >/dev/null; then fail 'certbot busy'; fi
echo JELLYFIN_PREFLIGHT=PASS
install -d -m 0755 "$ROOT" "$ROOT/releases" "$ROOT/acme" "$ROOT/web"
install -d -m 0700 "$ROOT/secrets" "$ROOT/config" "$ROOT/cache" "$ROOT/data" "$ROOT/logs" "$ROOT/.install-tmp"
install -d -m 0755 "$ROOT/acme/.well-known/acme-challenge"
if [[ -x "$ROOT/current/jellyfin" && -s "$ROOT/web/index.html" ]]; then
  echo JELLYFIN_RESUME_ALREADY_DOWNLOADED=PASS
else
curl -fSLsS --retry 2 --connect-timeout 15 --max-time 300 "$SERVER_URL" -o "$ROOT/.install-tmp/jellyfin.tar.gz"
curl -fSLsS --retry 2 --connect-timeout 15 --max-time 300 "$WEB_URL" -o "$ROOT/.install-tmp/web.deb"
[[ $(stat -c%s "$ROOT/.install-tmp/jellyfin.tar.gz") -gt 70000000 ]] || fail 'server archive too small'
[[ $(stat -c%s "$ROOT/.install-tmp/web.deb") -gt 20000000 ]] || fail 'web archive too small'
install -d -m 0755 "$ROOT/releases/12.4"
tar -xzf "$ROOT/.install-tmp/jellyfin.tar.gz" -C "$ROOT/releases/12.4" --no-same-owner
bin="$(find "$ROOT/releases/12.4" -maxdepth 4 -type f -name jellyfin -perm /111 -print -quit)"
[[ -n "$bin" && -x "$bin" ]] || fail 'no Jellyfin executable'
ln -s "$(dirname "$bin")" "$ROOT/current"
install -d -m 0700 "$ROOT/.install-tmp/webextract"
dpkg-deb -x "$ROOT/.install-tmp/web.deb" "$ROOT/.install-tmp/webextract"
[[ -s "$ROOT/.install-tmp/webextract/usr/share/jellyfin/web/index.html" ]] || fail 'web missing from official package'
cp -a "$ROOT/.install-tmp/webextract/usr/share/jellyfin/web/." "$ROOT/web/"
fi
# Jellyfin 12.4 prints its version on stderr and intentionally exits code 1.
VERSION_OUTPUT="$("$ROOT/current/jellyfin" --version 2>&1 || true)"
[[ "$VERSION_OUTPUT" == *"Jellyfin.Server 12.4."* ]] || fail 'Jellyfin version mismatch'
echo JELLYFIN_VERIFIED_VERSION=12.4
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home-dir "$ROOT" --shell /usr/sbin/nologin --no-create-home "$USER_NAME"
fi
cat > "$ROOT/config/network.xml" <<'NETXML'
<?xml version="1.0" encoding="utf-8"?>
<NetworkConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
 <EnableIPV4>true</EnableIPV4><EnableIPV6>false</EnableIPV6>
 <LocalNetworkAddresses><string>127.0.0.1</string></LocalNetworkAddresses>
 <KnownProxies><string>127.0.0.1</string></KnownProxies>
 <EnableRemoteAccess>true</EnableRemoteAccess><EnableUPnP>false</EnableUPnP>
 <InternalHttpPort>8096</InternalHttpPort>
</NetworkConfiguration>
NETXML
cat > "$ROOT/start.sh" <<'START'
#!/bin/sh
set -eu
ROOT=/srv/projects/jellyfin-server
exec "$ROOT/current/jellyfin" --datadir "$ROOT/data" --cachedir "$ROOT/cache" --configdir "$ROOT/config" --logdir "$ROOT/logs" --webdir "$ROOT/web" --noautorunwebapp
START
chmod 0755 "$ROOT/start.sh"
chown -R "$USER_NAME:$USER_NAME" "$ROOT"
chmod 0700 "$ROOT/secrets" "$ROOT/config" "$ROOT/cache" "$ROOT/data" "$ROOT/logs"
cat > "$UNIT" <<'UNITCONTENT'
[Unit]
Description=Pink IPTV Jellyfin (no local video files)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=jellyfinpink
Group=jellyfinpink
WorkingDirectory=/srv/projects/jellyfin-server
ExecStart=/srv/projects/jellyfin-server/start.sh
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
# Never let Jellyfin fetch or relay external Mega OTT media; UI works through nginx loopback.
IPAddressDeny=any
IPAddressAllow=localhost
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/srv/projects/jellyfin-server
MemoryMax=1600M
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
UNITCONTENT
chmod 0644 "$UNIT"
CREATED_UNIT=1
systemctl daemon-reload
systemctl enable --now jellyfin-pink.service >/dev/null
for i in $(seq 1 18); do
  if curl -fsS --connect-timeout 2 --max-time 3 http://127.0.0.1:8096/System/Info/Public -o "$ROOT/.install-tmp/info.json" 2>/dev/null; then break; fi
  sleep 2
done
if [[ ! -s "$ROOT/.install-tmp/info.json" ]]; then
  echo JELLYFIN_STARTUP_DIAGNOSTIC=BEGIN >&2
  systemctl status jellyfin-pink.service --no-pager --full 2>&1 | tail -n 28 >&2 || :
  journalctl -u jellyfin-pink.service --since '-2 minutes' -n 65 --no-pager -o cat 2>&1 | tail -n 65 >&2 || :
  echo JELLYFIN_STARTUP_DIAGNOSTIC=END >&2
  fail 'Jellyfin did not start'
fi
python3 - "$ROOT/.install-tmp/info.json" <<'CHECK'
import json,sys
x=json.load(open(sys.argv[1]))
assert str(x.get('Version','')).startswith('12.4'), 'wrong version'
assert x.get('StartupWizardCompleted') is False, 'unexpected wizard'
CHECK
ss -lntH 'sport = :8096' | grep -F '127.0.0.1:8096' >/dev/null || fail 'port not restricted to loopback'
if ss -lntH 'sport = :8096' | grep -E '(0[.]0[.]0[.]0|\[::\])' >/dev/null; then fail 'port public'; fi
python3 - "$ROOT/secrets/admin-initial.json" <<'SECRET'
import json,secrets,os,sys
p=sys.argv[1]
with open(p,'x',encoding='utf-8') as f: json.dump({'username':'pink-admin','password':secrets.token_urlsafe(34)},f)
os.chmod(p,0o600)
SECRET
curl -fsS --max-time 10 http://127.0.0.1:8096/Startup/User -o /dev/null
python3 - "$ROOT/secrets/admin-initial.json" <<'BODY' | curl -fsS --max-time 15 -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8096/Startup/User -o /dev/null
import json,sys
with open(sys.argv[1],encoding='utf-8') as f:p=json.load(f)
print(json.dumps({'Name':p['username'],'Password':p['password']}))
BODY
curl -fsS --max-time 12 -X POST http://127.0.0.1:8096/Startup/Complete -o /dev/null
curl -fsS --max-time 12 http://127.0.0.1:8096/System/Info/Public -o "$ROOT/.install-tmp/info.json"
python3 - "$ROOT/.install-tmp/info.json" <<'DONE'
import json,sys
assert json.load(open(sys.argv[1])).get('StartupWizardCompleted') is True, 'wizard still open'
DONE
echo JELLYFIN_ADMIN_SECURE=PASS
cat > "$CONF" <<'HTTP'
server {
 listen 80;
 server_name serveriptv.duckdns.org;
 root /srv/projects/jellyfin-server/acme;
 location ^~ /.well-known/acme-challenge/ { try_files $uri =404; }
 location / { return 404; }
}
HTTP
chmod 0644 "$CONF"
CREATED_CONF=1
nginx -t >/dev/null
systemctl reload nginx
CHANGED_SITE=1
printf 'pink-acme-preflight-ok' > "$ROOT/acme/.well-known/acme-challenge/pink-probe"
chmod 0644 "$ROOT/acme/.well-known/acme-challenge/pink-probe"
actual="$(curl -fsS --connect-timeout 8 --max-time 15 --noproxy '*' "http://$DOMAIN/.well-known/acme-challenge/pink-probe")"
[[ "$actual" == pink-acme-preflight-ok ]] || fail 'ACME external path failed'
echo JELLYFIN_ACME_WEBROOT=PASS
certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --webroot --webroot-path "$ROOT/acme" --cert-name "$DOMAIN" -d "$DOMAIN" --keep-until-expiring >/dev/null
[[ -s "$CERT/fullchain.pem" && -s "$CERT/privkey.pem" ]] || fail 'certificate missing'
openssl x509 -in "$CERT/fullchain.pem" -noout -ext subjectAltName | grep -Fq "$DOMAIN" || fail 'certificate SAN mismatch'
cat > "$CONF" <<'HTTPS'
server {
 listen 80;
 server_name serveriptv.duckdns.org;
 root /srv/projects/jellyfin-server/acme;
 location ^~ /.well-known/acme-challenge/ { try_files $uri =404; }
 location / { return 301 https://serveriptv.duckdns.org$request_uri; }
}
server {
 listen 443 ssl;
 server_name serveriptv.duckdns.org;
 ssl_certificate /etc/letsencrypt/live/serveriptv.duckdns.org/fullchain.pem;
 ssl_certificate_key /etc/letsencrypt/live/serveriptv.duckdns.org/privkey.pem;
 server_tokens off;
 client_max_body_size 10m;
 location /socket {
  proxy_pass http://127.0.0.1:8096;
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_read_timeout 3600s;
  proxy_buffering off;
 }
 location / {
  proxy_pass http://127.0.0.1:8096;
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_read_timeout 3600s;
  proxy_buffering off;
  proxy_request_buffering off;
  proxy_max_temp_file_size 0;
 }
}
HTTPS
nginx -t >/dev/null
systemctl reload nginx
curl -fsS --connect-timeout 8 --max-time 15 --noproxy '*' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/System/Info/Public" -o "$ROOT/.install-tmp/public.json"
python3 - "$ROOT/.install-tmp/public.json" <<'FINAL'
import json,sys
x=json.load(open(sys.argv[1]))
assert str(x.get('Version','')).startswith('12.4'), 'wrong live version'
assert x.get('StartupWizardCompleted') is True, 'public wizard open'
FINAL
systemctl is-active --quiet jellyfin-pink.service || fail 'service stopped'
nginx -t >/dev/null
rm -rf "$ROOT/.install-tmp"
echo "JELLYFIN_DEPLOY=PASS disk_bytes=$(du -sB1 "$ROOT" | awk '{print $1}') free_bytes=$(df -PB1 /srv/projects | awk 'NR==2{print $4}')"
echo JELLYFIN_TLS=PASS
echo JELLYFIN_MEDIA_LIBRARIES=0
echo JELLYFIN_SECRET_LOCATION=VPS_ONLY
trap - EXIT
