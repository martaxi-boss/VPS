#!/usr/bin/env bash
# FADEGO tenant and Owner panel upgrade in the existing isolated staging.
# No credential reset, main merge, Gmail send, new public APIs, or Nginx edits.
set -Eeuo pipefail
umask 077

ROOT=/srv/fadego-staging
OLD=1d19279f834ba726c5fede3f164d537f1414d3ea
NEW=037fc4c5794bdde1177d6b086cf87710b4335483
DOMAIN=fadego.duckdns.org
ENV=/etc/fadego-staging/app.env
VHOST=/etc/nginx/sites-available/fadego-staging.conf
SEND_CLOSED=/etc/fadego-staging/send-closed.env
OWNER_PASSWORD=/root/project-secrets/fadego-staging/admin-password
LOGO_DIGEST=8386058306f181827baa886e58262d2834044fa18a8e7bb2f488ce8b77f7c7c8

if [[ "$(id -u)" != 0 || "${FADEGO_TENANT_PANELS_STAGING_APPROVED:-}" != 1 ]]; then
  echo 'FADEGO_TENANT_PANELS_REFUSED_NO_APPROVAL'; exit 2
fi
exec 9>/run/fadego-staging-install.lock
flock -n 9 || { echo 'FADEGO_TENANT_PANELS_REFUSED_BUSY'; exit 2; }
for c in git node corepack curl nginx runuser systemctl sha256sum; do
  command -v "$c" >/dev/null || { echo "FADEGO_TENANT_PANELS_MISSING_TOOL=$c"; exit 2; }
done
[[ -L "$ROOT/current" && ! -L "$ROOT/releases" ]] || exit 2
[[ "$(readlink -f "$ROOT/current")" == "$ROOT/releases/$OLD" ]] || {
  echo 'FADEGO_TENANT_PANELS_REFUSED_RELEASE_DRIFT'; exit 2;
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
  echo 'FADEGO_TENANT_PANELS_REFUSED_UNEXPECTED_OLD_LOGIN'; exit 2;
}
unset prior_html
echo 'FADEGO_TENANT_PANELS_BASELINE=VALID'

rollback() {
  result=$?
  trap - EXIT
  if [[ "$result" != 0 ]]; then
    if [[ "$(readlink -f "$ROOT/current" 2>/dev/null || true)" == "$ROOT/releases/$NEW" ]]; then
      ln -s "$ROOT/releases/$OLD" "$ROOT/current.owner-revert"
      mv -Tf "$ROOT/current.owner-revert" "$ROOT/current"
      systemctl restart fadego-staging.service || true
      echo 'FADEGO_TENANT_PANELS_RECOVERY=OLD_RELEASE_RESTORED'
    else
      echo 'FADEGO_TENANT_PANELS_RECOVERY=OLD_RELEASE_NOT_REPLACED'
    fi
  fi
  exit "$result"
}
trap rollback EXIT

# Canonical native builder clones one immutable SHA; prior commit has the
# vetted builder; migrations are unchanged between the two certified SHAs.
set -a
source "$ENV"
set +a
export BOOKING_EMAIL_PROVIDER=disabled GMAIL_LIVE_SEND_ENABLED=false
export FADEGO_STAGING_SUPERVISOR_APPROVED=1 FADEGO_STAGING_APPROVED_SHA="$NEW"
export HOME="$ROOT" COREPACK_HOME="$ROOT/.cache/corepack"
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
  echo 'FADEGO_TENANT_PANELS_REUSED_VERIFIED_PREBUILT_SHA'
else
  runuser -u fadego-staging -m -- bash "$ROOT/releases/$OLD/deploy/staging/native/build-release.sh"
fi

[[ "$(readlink -f "$ROOT/current")" == "$ROOT/releases/$NEW" ]] || exit 2
[[ "$(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD)" == "$NEW" ]] || exit 2
[[ "$(sha256sum "$ROOT/current/public/fadego-mark.webp" | cut -d' ' -f1)" == "$LOGO_DIGEST" ]] || exit 2
systemctl restart fadego-staging.service

ready=0
for n in $(seq 1 45); do
  if [[ "$(curl -sS --max-time 4 -o /dev/null -w '%{http_code}' http://127.0.0.1:3100/login 2>/dev/null || true)" == 200 ]]; then
    ready=1; break
  fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo 'FADEGO_TENANT_PANELS_NOT_READY'; exit 2; }

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
  console.log("FADEGO_TENANT_PANELS_LOGIN=PASSWORD_ONLY_NO_USERNAME");
  console.log("FADEGO_TENANT_PANELS_STAFF_LOGIN=SEPARATE");
  console.log("FADEGO_TENANT_PANELS_TENANT_PRIVACY=PROTECTED");
})().catch(e=>{console.error("FADEGO_TENANT_PANELS_NEGATIVE_FAILED",e.message);process.exitCode=1});
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
  console.log("FADEGO_TENANT_PANELS_VAULT_LOGIN=AUTHORIZED_NO_USERNAME");
  console.log("FADEGO_TENANT_PANELS_SUPERADMIN=HTTP_200");
})().catch(e=>{console.error("FADEGO_TENANT_PANELS_POSITIVE_FAILED",e.message);process.exitCode=1});
JS_OWNER

# Fail closed if the running process has not kept the sender gates closed.
python3 - "$(systemctl show -p MainPID --value fadego-staging.service)" <<'PY_SENDER'
import sys
pid=int(sys.argv[1])
if pid < 2: raise SystemExit("FADEGO_TENANT_PANELS_PROCESS_MISSING")
with open(f"/proc/{pid}/environ","rb") as stream:
    vals=dict(p.split(b"=",1) for p in stream.read().split(b"\0") if b"=" in p)
if vals.get(b"BOOKING_EMAIL_PROVIDER") != b"disabled" or vals.get(b"GMAIL_LIVE_SEND_ENABLED") != b"false":
    raise SystemExit("FADEGO_TENANT_PANELS_UNSAFE_MAIL_ENV")
print("FADEGO_TENANT_PANELS_GMAIL_SEND=DISABLED")
PY_SENDER
echo 'FADEGO_TENANT_PANELS_RELEASE=SUCCESS'
echo 'FADEGO_TENANT_PANELS_CREDENTIALS=UNCHANGED'
