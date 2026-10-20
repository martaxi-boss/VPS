#!/usr/bin/env bash
# FADEGO barber operations, schedule and invitation upgrade in the existing isolated staging.
# No credential reset, main merge, Gmail send, new public APIs, or Nginx edits.
set -Eeuo pipefail
umask 077

ROOT=/srv/fadego-staging
OLD=3ada51c477710a6ea1612492cfae82cdf23948f8
NEW=2b3554ec6e075e36041e44178f99535e00961b2f
DOMAIN=fadego.duckdns.org
ENV=/etc/fadego-staging/app.env
VHOST=/etc/nginx/sites-available/fadego-staging.conf
SEND_CLOSED=/etc/fadego-staging/send-closed.env
OWNER_PASSWORD=/root/project-secrets/fadego-staging/admin-password
LOGO_DIGEST=8386058306f181827baa886e58262d2834044fa18a8e7bb2f488ce8b77f7c7c8

if [[ "$(id -u)" != 0 || "${FADEGO_STAFF_OPERATIONS_STAGING_APPROVED:-}" != 1 ]]; then
  echo 'FADEGO_STAFF_OPERATIONS_REFUSED_NO_APPROVAL'; exit 2
fi
exec 9>/run/fadego-staging-install.lock
flock -n 9 || { echo 'FADEGO_STAFF_OPERATIONS_REFUSED_BUSY'; exit 2; }
for c in git node corepack curl nginx runuser systemctl sha256sum pg_dump pg_restore psql install mv; do
  command -v "$c" >/dev/null || { echo "FADEGO_STAFF_OPERATIONS_MISSING_TOOL=$c"; exit 2; }
done
[[ -L "$ROOT/current" && ! -L "$ROOT/releases" ]] || exit 2
[[ "$(readlink -f "$ROOT/current")" == "$ROOT/releases/$OLD" ]] || {
  echo 'FADEGO_STAFF_OPERATIONS_REFUSED_RELEASE_DRIFT'; exit 2;
}
[[ "$(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD)" == "$OLD" ]] || exit 2
[[ ! -L "$ROOT/releases/$NEW" ]] || exit 2
[[ ! -e "$ROOT/current.next" && ! -L "$ROOT/current.next" ]] || exit 2
[[ -s "$ENV" && -s "$SEND_CLOSED" && -s "$OWNER_PASSWORD" ]] || exit 2
[[ -f "$VHOST" && ! -L "$VHOST" ]] || exit 2
grep -Fxq 'BOOKING_EMAIL_PROVIDER=disabled' "$SEND_CLOSED"
grep -Fxq 'GMAIL_LIVE_SEND_ENABLED=false' "$SEND_CLOSED"
grep -Fq 'EnvironmentFile=/etc/fadego-staging/send-closed.env' /etc/systemd/system/fadego-staging.service
[[ "$(grep -Fc 'FADEGO_PORTAL_SINGLE_LOGIN_BEGIN' "$VHOST")" == 1 ]] || exit 2
[[ "$(grep -Fc 'FADEGO_PORTAL_SINGLE_LOGIN_END' "$VHOST")" == 1 ]] || exit 2
[[ "$(grep -Fc 'FADEGO_PUBLIC_WEBSITE_BEGIN' "$VHOST")" == 1 ]] || exit 2
[[ "$(grep -Fc 'FADEGO_PUBLIC_WEBSITE_END' "$VHOST")" == 1 ]] || exit 2
[[ "$(grep -Fc 'FADEGO_PREVIEW_BEGIN' "$VHOST")" == 1 ]] || exit 2
[[ "$(grep -Fc 'FADEGO_PREVIEW_END' "$VHOST")" == 1 ]] || exit 2
systemctl is-active --quiet nginx
systemctl is-active --quiet fadego-staging.service
nginx -t -q

local_http() {
  curl -sS --max-time 14 -o /dev/null -w '%{http_code}' \
    --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN$1"
}
[[ "$(local_http /)" == 200 && "$(local_http /login)" == 200 ]] || exit 2
[[ "$(local_http /b/example)" == 401 ]] || exit 2
[[ "$(local_http /api/public/barbershops/example/availability)" == 401 ]] || exit 2
prior_html="$(curl -fsS --max-time 14 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/login")"
[[ "$prior_html" == *'O meu Portal FADEGO'* ]] || {
  echo 'FADEGO_STAFF_OPERATIONS_REFUSED_UNEXPECTED_OLD_LOGIN'; exit 2;
}
unset prior_html
echo 'FADEGO_STAFF_OPERATIONS_BASELINE=VALID'

rollback() {
  result=$?
  trap - EXIT
  if [[ "$result" != 0 ]]; then
    if [[ "$(readlink -f "$ROOT/current" 2>/dev/null || true)" == "$ROOT/releases/$NEW" ]]; then
      ln -s "$ROOT/releases/$OLD" "$ROOT/current.owner-revert"
      mv -Tf "$ROOT/current.owner-revert" "$ROOT/current"
      systemctl restart fadego-staging.service || true
      echo 'FADEGO_STAFF_OPERATIONS_RECOVERY=OLD_RELEASE_RESTORED'
    else
      echo 'FADEGO_STAFF_OPERATIONS_RECOVERY=OLD_RELEASE_NOT_REPLACED'
    fi
  fi
  exit "$result"
}
trap rollback EXIT

# Canonical native builder clones one immutable SHA; prior commit has the
# vetted builder; the new additive migration is backed up and checked below.
set -a
source "$ENV"
set +a
export BOOKING_EMAIL_PROVIDER=disabled GMAIL_LIVE_SEND_ENABLED=false
[[ "${FADEGO_TENANT_SUBDOMAINS_READY:-false}" != true ]] || { echo 'FADEGO_STAFF_OPERATIONS_REFUSED_UNCERTIFIED_DNS'; exit 2; }
export FADEGO_STAGING_SUPERVISOR_APPROVED=1 FADEGO_STAGING_APPROVED_SHA="$NEW"
export COREPACK_HOME="$ROOT/.cache/corepack"

# The upgrade adds OwnerInvitation and the default-false onboarding marker.
# Root-only pre-migration backup is verified before the native builder runs.
# Neither rollback nor cleanup deletes this backup.
BACKUP_ROOT=/root/project-secrets/fadego-staging/backups
BACKUP="$BACKUP_ROOT/pre-consolidation-$NEW.dump"
install -d -m 0700 "$BACKUP_ROOT"
[[ ! -L "$BACKUP_ROOT" && ! -e "$BACKUP" && ! -e "$BACKUP.partial" ]] || {
  echo 'FADEGO_STAFF_OPERATIONS_REFUSED_BACKUP_COLLISION'; exit 2;
}
# DATABASE_URL is the pre-existing root-managed localhost connection; do not
# print it, argv it, or send credentials to GitHub/Telegram.
export PGPASSWORD="$(node -e 'process.stdout.write(decodeURIComponent(new URL(process.env.DATABASE_URL).password))')"
[[ -n "$PGPASSWORD" ]] || { echo 'FADEGO_STAFF_OPERATIONS_REFUSED_DB_CREDENTIAL'; exit 2; }
runuser -u fadego-staging -m -- pg_dump --format=custom --no-owner --no-privileges \
  --host=127.0.0.1 --port=5432 --username=fadego_staging --dbname=fadego_staging \
  > "$BACKUP.partial"
unset PGPASSWORD
[[ -s "$BACKUP.partial" ]] || { echo 'FADEGO_STAFF_OPERATIONS_BACKUP_EMPTY'; exit 2; }
pg_restore --list "$BACKUP.partial" >/dev/null
chmod 0600 "$BACKUP.partial"
mv -n "$BACKUP.partial" "$BACKUP"
[[ -s "$BACKUP" ]] || exit 2
echo 'FADEGO_STAFF_OPERATIONS_PRE_MIGRATION_BACKUP=VERIFIED'

if [[ -e "$ROOT/releases/$NEW" ]]; then
  # Previous installation was rolled back after fully compiling the immutable
  # release. Reuse only if the exact build, ownership and source are proven.
  [[ -d "$ROOT/releases/$NEW" && ! -L "$ROOT/releases/$NEW" ]] || exit 2
  [[ "$(stat -c %U "$ROOT/releases/$NEW")" == "fadego-staging" ]] || exit 2
  [[ "$(runuser -u fadego-staging -- git -C "$ROOT/releases/$NEW" rev-parse HEAD)" == "$NEW" ]] || exit 2
  [[ -s "$ROOT/releases/$NEW/.next/BUILD_ID" ]] || exit 2
  [[ -d "$ROOT/releases/$NEW/node_modules" ]] || exit 2
  [[ "$(sha256sum "$ROOT/releases/$NEW/public/fadego-mark.webp" | cut -d' ' -f1)" == "$LOGO_DIGEST" ]] || exit 2
  ln -s "$ROOT/releases/$NEW" "$ROOT/current.next"
  mv -Tf "$ROOT/current.next" "$ROOT/current"
  echo 'FADEGO_STAFF_OPERATIONS_REUSED_VERIFIED_PREBUILT_SHA'
else
  runuser -u fadego-staging --preserve-environment -- bash "$ROOT/releases/$OLD/deploy/staging/native/build-release.sh"
fi

[[ "$(readlink -f "$ROOT/current")" == "$ROOT/releases/$NEW" ]] || exit 2
[[ "$(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD)" == "$NEW" ]] || exit 2
# Migration must be committed and present in the isolated staging database.
[[ -s "$ROOT/current/prisma/migrations/20261020210000_owner_onboarding/migration.sql" ]] || exit 2
export PGPASSWORD="$(node -e 'process.stdout.write(decodeURIComponent(new URL(process.env.DATABASE_URL).password))')"
migration_count="$(runuser -u fadego-staging -m -- psql -X -q -t -A \
  --host=127.0.0.1 --port=5432 --username=fadego_staging --dbname=fadego_staging \
  -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('StaffWeeklyHour','StaffScheduleBlock','StaffInvitation','OwnerInvitation')" )"
unset PGPASSWORD
[[ "$migration_count" == 4 ]] || { echo 'FADEGO_STAFF_OPERATIONS_REFUSED_SCHEMA_INCOMPLETE'; exit 2; }
export PGPASSWORD="$(node -e 'process.stdout.write(decodeURIComponent(new URL(process.env.DATABASE_URL).password))')"
owner_schema="$(runuser -u fadego-staging -m -- psql -X -q -t -A \
  --host=127.0.0.1 --port=5432 --username=fadego_staging --dbname=fadego_staging \
  -c "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='User' AND column_name='onboardingPending' AND data_type='boolean' AND is_nullable='NO' AND column_default='false'" )"
applied="$(runuser -u fadego-staging -m -- psql -X -q -t -A \
  --host=127.0.0.1 --port=5432 --username=fadego_staging --dbname=fadego_staging \
  -c 'SELECT count(*) FROM "_prisma_migrations" WHERE migration_name = '\''20261020210000_owner_onboarding'\'' AND finished_at IS NOT NULL AND rolled_back_at IS NULL' )"
pilot="$(runuser -u fadego-staging -m -- psql -X -q -t -A \
  --host=127.0.0.1 --port=5432 --username=fadego_staging --dbname=fadego_staging \
  -c 'SELECT count(*) FROM "Barbershop" WHERE slug = '\''fadego-piloto-interno'\'' AND status = '\''SUSPENDED'\''' )"
unset PGPASSWORD
[[ "$owner_schema" == 1 && "$applied" == 1 && "$pilot" == 1 ]] || {
  echo 'FADEGO_STAFF_OPERATIONS_REFUSED_OWNER_SCHEMA_OR_PILOT'; exit 2;
}
# Sender scheduling is intentionally not activated by this deployment.
if systemctl is-active --quiet fadego-booking-email.timer; then
  echo 'FADEGO_STAFF_OPERATIONS_REFUSED_ACTIVE_EMAIL_TIMER'; exit 2
fi
echo 'FADEGO_STAFF_OPERATIONS_ADDITIVE_MIGRATION=VERIFIED'
[[ "$(sha256sum "$ROOT/current/public/fadego-mark.webp" | cut -d' ' -f1)" == "$LOGO_DIGEST" ]] || exit 2
systemctl restart fadego-staging.service

ready=0
for n in $(seq 1 45); do
  if [[ "$(curl -sS --max-time 4 -o /dev/null -w '%{http_code}' http://127.0.0.1:3100/login 2>/dev/null || true)" == 200 ]]; then
    ready=1; break
  fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo 'FADEGO_STAFF_OPERATIONS_NOT_READY'; exit 2; }

# These checks cover public/tenant boundaries and the *real* vault Owner
# authentication without disclosing a password, CSRF, session, or cookie.
node <<'JS_PORTAL'
const assert=require("node:assert/strict");
const fs=require("node:fs");
const origin="https://fadego.duckdns.org";
const req=async (path,init={})=>fetch(origin+path,{
  redirect:"manual",signal:AbortSignal.timeout(20000),...init,
});
;(async()=>{
  const home=await req("/");
  assert.equal(home.status,200,"Public informational website unchanged");
  assert.match(await home.text(),/Portal FADEGO/);
  const login=await req("/login");
  assert.equal(login.status,200,"Owner login must be accessible without HTTP Basic");
  assert.equal(login.headers.get("www-authenticate"),null);
  const body=await login.text();
  assert.match(body,/O meu Portal FADEGO/);
  assert.match(body,/A tua palavra-passe/);
  assert.match(body,/name="password"/);
  assert.doesNotMatch(body,/name="email"/);
  assert.doesNotMatch(body,/Entrar na plataforma/);
  const staff=await req("/login?acesso=equipa");
  assert.equal(staff.status,200);
  assert.match(await staff.text(),/name="email"/);
  for(const path of ["/admin","/super-admin"]){
    const result=await req(path);
    assert.ok([301,302,303,307,308].includes(result.status),"Unauthenticated portal redirect");
    assert.equal(new URL(result.headers.get("location"),origin).pathname,"/login");
    await result.body?.cancel();
  }
  // Next.js's private tenant layout first routes anonymous deep links to
  // /admin, whose verified authentication boundary routes to /login.
  const anonymousBarber=await req("/admin/fadego-piloto-interno/barbeiro");
  assert.ok([301,302,303,307,308].includes(anonymousBarber.status),
    "Barber dashboard must reject unauthenticated direct access");
  assert.equal(new URL(anonymousBarber.headers.get("location"),origin).pathname,
    "/admin","Private barber page must use the verified /admin auth gateway");
  await anonymousBarber.body?.cancel();
  for(const path of ["/b/example","/api/public/barbershops/example/availability",
      "/api/private/bookings/something/availability",
      "/api/integrations/gmail/callback"]){
    const result=await req(path);
    assert.equal(result.status,401,"Protected route must retain Basic auth: "+path);
    await result.body?.cancel();
  }
  const blocked=await req("/_next/image?url=%2Fapi%2Fauth%2Fsession&w=64&q=75");
  assert.equal(blocked.status,403);
  await blocked.body?.cancel();
  const providers=await req("/api/auth/providers");
  assert.equal(providers.status,200);
  const p=await providers.json();
  assert.ok(p["owner-password"],"Password-only provider must be registered");
  assert.ok(p.credentials,"Tenant staff credentials provider must remain");
  const session=await req("/api/auth/session");
  assert.equal(session.status,200);
  assert.ok(!(await session.json()).user);
  const missingTenant=await req("/espaco/negocio-inexistente");
  assert.ok([401,404].includes(missingTenant.status),
    "Unknown business portal must not expose a tenant through Nginx or Next.js");
  await missingTenant.body?.cancel();
  const demo=await req("/experimentar");
  assert.equal(demo.status,200);
  await demo.body?.cancel();
  console.log("FADEGO_STAFF_OPERATIONS_LOGIN=PASSWORD_ONLY_NO_USERNAME");
  console.log("FADEGO_STAFF_OPERATIONS_STAFF_LOGIN=SEPARATE");
  console.log("FADEGO_STAFF_OPERATIONS_TENANT_PRIVACY=PROTECTED");
})().catch(e=>{console.error("FADEGO_STAFF_OPERATIONS_NEGATIVE_FAILED",e.message);process.exitCode=1});
JS_PORTAL

node <<'JS_OWNER'
const assert=require("node:assert/strict");
const fs=require("node:fs");
const origin="https://fadego.duckdns.org";
const password=fs.readFileSync("/root/project-secrets/fadego-staging/admin-password","utf8").trim();
assert.ok(password.length>0 && password.length<=512);
const jar=new Map();
const remember=(r)=>{
  for(const v of (r.headers.getSetCookie?.()||[])){
    const [pair]=v.split(";",1); const i=pair.indexOf("=");
    if(i>0) jar.set(pair.slice(0,i),pair.slice(i+1));
  }
};
const req=async(path,init={})=>{
  const headers={...(init.headers||{})};
  if(jar.size) headers.cookie=Array.from(jar,([k,v])=>k+"="+v).join("; ");
  const r=await fetch(origin+path,{redirect:"manual",
    signal:AbortSignal.timeout(20000),...init,headers});
  remember(r);return r;
};
;(async()=>{
  const csrfRes=await req("/api/auth/csrf");
  assert.equal(csrfRes.status,200);
  const csrf=(await csrfRes.json()).csrfToken;
  assert.ok(csrf);
  const body=new URLSearchParams({
    csrfToken:csrf,password,callbackUrl:origin+"/super-admin",json:"true",
  });
  const auth=await req("/api/auth/callback/owner-password",{
    method:"POST",
    headers:{"content-type":"application/x-www-form-urlencoded"},
    body,
  });
  assert.ok([200,302,303].includes(auth.status),"Owner sign-in must respond");
  await auth.body?.cancel();
  const session=await req("/api/auth/session");
  assert.equal(session.status,200);
  assert.ok((await session.json()).user?.id,"Vault Owner password must authenticate");
  const admin=await req("/super-admin");
  assert.equal(admin.status,200,"Owner must reach protected platform portal");
  const adminHtml=await admin.text();
  assert.match(adminHtml,/O meu FADEGO/);
  assert.match(adminHtml,/Criar nova barbearia/);
  const barber=await req("/admin/fadego-piloto-interno/barbeiro");
  assert.equal(barber.status,200,"Owner preview of pilot barber panel must open");
  const personalHtml=await barber.text();
  assert.match(personalHtml,/Painel do barbeiro/);
  assert.match(personalHtml,/Escolher profissional/);
  const prefix="/admin/fadego-piloto-interno";
  for(const [path, pattern] of [
    [prefix,/FADEGO|Visão geral/],
    [prefix+"/agenda?view=day",/Calendário diário/],
    [prefix+"/agenda?view=week",/Calendário semanal/],
    [prefix+"/professionals/convites",/convite|Convite/],
  ]) {
    const result=await req(path);
    assert.equal(result.status,200,"Authenticated review page must open");
    assert.match(await result.text(),pattern);
  }
  const choice=personalHtml.match(/href="[^"\s]*barbeiro\?professional=([A-Za-z0-9_-]+)"/);
  assert.ok(choice,"Existing pilot must have a professional for preview");
  const professional=encodeURIComponent(choice[1]);
  for(const view of ["day","week"]) {
    const result=await req(prefix+"/barbeiro?professional="+professional+"&view="+view);
    assert.equal(result.status,200);
    assert.match(await result.text(),view==="week"?/Calendário semanal/:/Calendário diário/);
  }
  const planning=await req(prefix+"/barbeiro/planeamento?professional="+professional);
  assert.equal(planning.status,200);
  assert.match(await planning.text(),/pausa|Pausa|folga|Folga/);
  console.log("FADEGO_CONSOLIDATION_DAY_WEEK_MANAGER_AND_BARBER=HTTP_200");
  console.log("FADEGO_STAFF_OPERATIONS_OWNER_BARBER_PREVIEW=HTTP_200");
  const plannerFile=fs.readFileSync(
    "/srv/fadego-staging/current/app/(admin)/admin/[slug]/barbeiro/planeamento/page.tsx",
    "utf8");
  assert.match(plannerFile,/createBarberBookingAction/);
  assert.match(plannerFile,/addBarberBlockAction/);
  const invitationFile=fs.readFileSync(
    "/srv/fadego-staging/current/app/aceitar-equipa/[token]/page.tsx",
    "utf8");
  assert.match(invitationFile,/convite|Convite/i);
  const staffSignUp=await req("/aceitar-equipa/invalid-token");
  assert.ok([200,401,404].includes(staffSignUp.status),
    "Invalid invitation must not activate an account");
  await staffSignUp.body?.cancel();
  console.log("FADEGO_STAFF_OPERATIONS_PLANNING_AND_INVITES=CHECKED");
  console.log("FADEGO_STAFF_OPERATIONS_VAULT_LOGIN=AUTHORIZED_NO_USERNAME");
  console.log("FADEGO_STAFF_OPERATIONS_SUPERADMIN=HTTP_200");
})().catch(e=>{console.error("FADEGO_STAFF_OPERATIONS_POSITIVE_FAILED",e.message);process.exitCode=1});
JS_OWNER

# Fail closed if the running process has not kept the sender gates closed.
python3 - "$(systemctl show -p MainPID --value fadego-staging.service)" <<'PY_SENDER'
import sys
pid=int(sys.argv[1])
if pid < 2: raise SystemExit("FADEGO_STAFF_OPERATIONS_PROCESS_MISSING")
with open(f"/proc/{pid}/environ","rb") as stream:
    vals=dict(p.split(b"=",1) for p in stream.read().split(b"\0") if b"=" in p)
if vals.get(b"BOOKING_EMAIL_PROVIDER") != b"disabled" or vals.get(b"GMAIL_LIVE_SEND_ENABLED") != b"false":
    raise SystemExit("FADEGO_STAFF_OPERATIONS_UNSAFE_MAIL_ENV")
print("FADEGO_STAFF_OPERATIONS_GMAIL_SEND=DISABLED")
PY_SENDER
echo 'FADEGO_STAFF_OPERATIONS_RELEASE=SUCCESS'
echo 'FADEGO_STAFF_OPERATIONS_CREDENTIALS=UNCHANGED'

