#!/usr/bin/env bash
# Owner-approved scissors emblem only; isolated FADEGO staging.
set -Eeuo pipefail
umask 077
NEW=9243689cbb177ea814cf055ad18ea5d1967529e5
OLD=531cf2ffdbddb31c29a244bff81fc4468fc9fe35
DIGEST=8386058306f181827baa886e58262d2834044fa18a8e7bb2f488ce8b77f7c7c8
ROOT=/srv/fadego-staging
VHOST=/etc/nginx/sites-available/fadego-staging.conf
PREVIEW=/var/www/fadego-preview/index.html
ENV=/etc/fadego-staging/app.env
VAULT=/root/project-secrets/fadego-staging/basic-password
if [[ $(id -u) != 0 || "${FADEGO_MARKETING_DEPLOY_APPROVED:-}" != 1 ]]; then
  echo 'FADEGO_BRAND_REFUSED_NO_APPROVAL'; exit 2
fi
exec 9>/run/fadego-staging-install.lock
flock -n 9 || { echo 'FADEGO_BRAND_REFUSED_CONCURRENT_INSTALL'; exit 2; }
for c in git node corepack nginx curl python3 runuser systemctl sha256sum; do
  command -v "$c" >/dev/null || { echo "FADEGO_BRAND_MISSING_TOOL=$c"; exit 2; }
done
[[ -L "$ROOT/current" && ! -L "$ROOT/releases" ]] || exit 2
[[ $(readlink -f "$ROOT/current") == "$ROOT/releases/$OLD" ]] || { echo 'FADEGO_BRAND_REFUSED_WRONG_OLD_RELEASE'; exit 2; }
[[ $(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD) == "$OLD" ]] || exit 2
[[ ! -e "$ROOT/releases/$NEW" && ! -e "$ROOT/current.next" && ! -L "$ROOT/current.next" ]] || exit 2
[[ -f "$VHOST" && ! -L "$VHOST" && -f "$PREVIEW" && ! -L "$PREVIEW" ]] || exit 2
[[ -s "$ENV" && -s "$VAULT" && -s /etc/fadego-staging/send-closed.env ]] || exit 2
grep -Fxq 'BOOKING_EMAIL_PROVIDER=disabled' /etc/fadego-staging/send-closed.env
grep -Fxq 'GMAIL_LIVE_SEND_ENABLED=false' /etc/fadego-staging/send-closed.env
grep -Fxq 'EnvironmentFile=/etc/fadego-staging/send-closed.env' /etc/systemd/system/fadego-staging.service
grep -Fq 'data:image/webp;base64,' "$PREVIEW"
grep -Fq 'Uma agenda leve.' "$PREVIEW"
[[ $(grep -Fc 'FADEGO_PREVIEW_BEGIN' "$VHOST") == 1 && $(grep -Fc 'FADEGO_PREVIEW_END' "$VHOST") == 1 ]] || exit 2
systemctl is-active --quiet fadego-staging.service
systemctl is-active --quiet nginx

prior_preview="$(mktemp /var/www/fadego-preview/.fadego-brand.XXXXXXXX)"
cp -p "$PREVIEW" "$prior_preview"
recover() {
  local status=$?
  trap - EXIT
  if [[ "$status" != 0 ]]; then
    cp -p "$prior_preview" "$PREVIEW"
    if [[ "$(readlink -f "$ROOT/current" || true)" == "$ROOT/releases/$NEW" ]]; then
      ln -s "$ROOT/releases/$OLD" "$ROOT/current.brand-revert"
      mv -Tf "$ROOT/current.brand-revert" "$ROOT/current"
      systemctl restart fadego-staging.service || true
    fi
    echo 'FADEGO_MARKETING_RECOVERY=OLD_RELEASE_RESTORED'
  fi
  rm -f "$prior_preview"
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
[[ $(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD) == "$NEW" ]] || exit 2
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
landing_html="$(curl -fsS --max-time 15 http://127.0.0.1:3100/)"
[[ "$landing_html" == *"Menos confusão."* && "$landing_html" == *"Como funciona"* && "$landing_html" == *"Para o dono da barbearia"* ]] || { echo 'FADEGO_MARKETING_REAL_HOME_CONTENT_MISSING'; exit 2; }
echo 'FADEGO_MARKETING_REAL_HOME=EXPLANATION_VISIBLE'
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
echo 'FADEGO_MARKETING_APPLICATION=UPDATED_HOME_APPROVED_BRAND'

# Update only the browser-local preview's introduction; retain original functions and CSS.
python3 - "$PREVIEW" <<'PY_PREVIEW'
from pathlib import Path
import sys
path = Path(sys.argv[1])
html = path.read_text(encoding="utf-8")
start = "function inicio(){return "
end = "\nfunction plataforma()"
if html.count(start) != 1 or html.count(end) != 1:
    raise SystemExit("FADEGO_MARKETING_REFUSED_PREVIEW_LAYOUT")
before, rest = html.split(start, 1)
old, after = rest.split(end, 1)
if "Uma agenda leve." not in old or "A tua plataforma" not in old:
    raise SystemExit("FADEGO_MARKETING_REFUSED_OLD_INTRO")
if "data:image/webp;base64," not in html or "function cliente()" not in html:
    raise SystemExit("FADEGO_MARKETING_REFUSED_ICON_OR_CLIENT_FLOW")
new_intro = """function inicio(){return '<div class="hero"><div class="eyebrow">FADEGO · Barbearias em movimento</div><h1>Menos confusão.<br>Mais barbearia.</h1><p>O cliente marca online sem criar conta. A barbearia organiza os horários, as cadeiras, a equipa e as reservas num único painel.</p><div class="hero-actions"><button class="primary light" data-view="cliente">Fazer reserva de teste →</button><button class="secondary" data-view="barbearia">Explorar painel do barbeiro</button></div></div><div class="sp"></div><div class="panel"><h3>Como funciona em três passos?</h3><div class="flow"><div class="step"><b>1. A barbearia prepara</b><small>Define serviços, preços, profissionais, cadeiras e horários no seu painel.</small></div><div class="step"><b>2. O cliente reserva</b><small>Escolhe serviço, dia e hora; indica email sem criar conta.</small></div><div class="step"><b>3. A agenda acompanha</b><small>O negócio vê a marcação. Com Gmail autorizado, o cliente recebe o link privado para alterar ou cancelar.</small></div></div></div><div class="sp"></div><div class="grid">'+card("Painel da barbearia","Agenda, equipa, cadeiras, clientes e planos Club.","_barbearia")+card("Reserva do cliente","Marcar e alterar uma hora de exemplo, sem conta.","_cliente")+card("Gestão FADEGO","A plataforma é administrada separadamente de cada negócio.","_plataforma")+'</div><div class="callout">Demonstração com dados fictícios, sem reservas ou emails reais. Cada barbearia tem o seu próprio espaço. Pagamentos online ainda não estão disponíveis.</div>'}"""
path.write_text(before + new_intro + end + after, encoding="utf-8")
print("FADEGO_MARKETING_DEMO_INTRO=UPDATED")
PY_PREVIEW

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
[[ "$preview_body" == *'data:image/webp;base64,'* && "$preview_body" == *'Como funciona em três passos?'* ]] || { echo 'FADEGO_MARKETING_PREVIEW_MISSING'; exit 2; }
STAGING_GATE_USER=fadego-pilot STAGING_GATE_PASSWORD="$(cat "$VAULT")" \
  node "$ROOT/current/scripts/smoke-staging.mjs"
echo 'FADEGO_MARKETING_DEPLOY=SUCCESS'
echo 'FADEGO_MARKETING_DEMO=PUBLIC_200_NO_LOGIN'
echo 'FADEGO_MARKETING_PRIVATE=401'
echo 'FADEGO_MARKETING_GMAIL_SEND=DISABLED'
