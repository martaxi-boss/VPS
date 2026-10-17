#!/usr/bin/env bash
# FADEGO owner-authorized single application login, isolated staging vhost only.
# Never disable NextAuth sessions/tenant roles, change user credentials or expose booking APIs.
set -Eeuo pipefail
umask 077
DOMAIN=fadego.duckdns.org
EXPECTED_RELEASE=0c01fcf625f491b40068cfc495ddbdb5962a6da7
VHOST=/etc/nginx/sites-available/fadego-staging.conf
ROOT=/srv/fadego-staging
SEND_CLOSED=/etc/fadego-staging/send-closed.env
OWNER_PASSWORD=/root/project-secrets/fadego-staging/admin-password

if [[ "$(id -u)" != 0 || "${FADEGO_PORTAL_SINGLE_LOGIN_APPROVED:-}" != 1 ]]; then
  echo 'FADEGO_PORTAL_REFUSED_NO_AUTHORITY'; exit 2
fi
exec 9>/run/fadego-staging-install.lock
flock -n 9 || { echo 'FADEGO_PORTAL_REFUSED_STAGING_BUSY'; exit 2; }
for program in curl git grep mktemp nginx node python3 runuser systemctl; do
  command -v "$program" >/dev/null || { echo "FADEGO_PORTAL_REFUSED_MISSING=$program"; exit 2; }
done
[[ -f "$VHOST" && ! -L "$VHOST" && "$(stat -c '%U' "$VHOST")" == root ]] || exit 2
[[ -L "$ROOT/current" && "$(readlink -f "$ROOT/current")" == "$ROOT/releases/$EXPECTED_RELEASE" ]] || exit 2
[[ "$(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD)" == "$EXPECTED_RELEASE" ]] || exit 2
[[ -s "$OWNER_PASSWORD" && -s "$SEND_CLOSED" ]] || exit 2
grep -Fxq 'BOOKING_EMAIL_PROVIDER=disabled' "$SEND_CLOSED"
grep -Fxq 'GMAIL_LIVE_SEND_ENABLED=false' "$SEND_CLOSED"
grep -Fxq 'EnvironmentFile=/etc/fadego-staging/send-closed.env' /etc/systemd/system/fadego-staging.service
grep -Fq 'auth_basic "FADEGO - ambiente de testes";' "$VHOST"
grep -Fq 'auth_basic_user_file /etc/nginx/fadego-staging.htpasswd;' "$VHOST"
grep -Fq 'server_name fadego.duckdns.org;' "$VHOST"
[[ "$(grep -Fc 'FADEGO_PUBLIC_WEBSITE_BEGIN' "$VHOST")" == 1 ]] || exit 2
[[ "$(grep -Fc 'FADEGO_PUBLIC_WEBSITE_END' "$VHOST")" == 1 ]] || exit 2
[[ "$(grep -Fc 'FADEGO_PREVIEW_BEGIN' "$VHOST")" == 1 ]] || exit 2
[[ "$(grep -Fc 'FADEGO_PREVIEW_END' "$VHOST")" == 1 ]] || exit 2
if grep -Fq 'FADEGO_PORTAL_SINGLE_LOGIN_BEGIN' "$VHOST"; then
  echo 'FADEGO_PORTAL_REFUSED_ALREADY_PUBLISHED'; exit 2
fi
systemctl is-active --quiet nginx
systemctl is-active --quiet fadego-staging.service
nginx -t -q

for private_route in /login /admin /super-admin /api/auth/session /api/public/barbershops/example/availability; do
  http_code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN$private_route")"
  [[ "$http_code" == 401 ]] || { echo 'FADEGO_PORTAL_REFUSED_UNEXPECTED_BEFORE_GATE'; exit 2; }
done
for public_route in / /experimentar /fadego-mark.webp; do
  http_code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN$public_route")"
  [[ "$http_code" == 200 ]] || { echo 'FADEGO_PORTAL_REFUSED_WEBSITE_NOT_PUBLIC'; exit 2; }
done

backup="$(mktemp /etc/nginx/sites-available/.fadego-portal-backup.XXXXXXXX)"
cp -p "$VHOST" "$backup"
on_exit() {
  local exit_code=$?
  trap - EXIT
  if [[ "$exit_code" != 0 ]]; then
    cp -p "$backup" "$VHOST"
    if nginx -t -q; then systemctl reload nginx || true; fi
    echo 'FADEGO_PORTAL_RECOVERY=PRIOR_BASIC_AUTH_VHOST_RESTORED'
  fi
  rm -f "$backup"
  exit "$exit_code"
}
trap on_exit EXIT

python3 - "$VHOST" <<'PY_NGINX'
from pathlib import Path
import sys
path=Path(sys.argv[1])
source=path.read_text(encoding="utf-8")
anchor="    location / {\n"
if source.count(anchor)!=1:
    raise SystemExit("FADEGO_PORTAL_REFUSED_VHOST_LAYOUT")
if source.count('    auth_basic "FADEGO - ambiente de testes";')!=1:
    raise SystemExit("FADEGO_PORTAL_REFUSED_BASIC_AUTH_BASELINE")
if "FADEGO_PORTAL_SINGLE_LOGIN_BEGIN" in source:
    raise SystemExit("FADEGO_PORTAL_REFUSED_DUPLICATE_BLOCK")

# Server-level Basic authentication remains untouched. NextAuth protects
# /admin and /super-admin, with tenant membership checked in each layout.
proxy = """        auth_basic off;
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
"""
paths=[
    ("location = /login", ""),
    ("location = /admin", ""),
    ("location ^~ /admin/", ""),
    ("location = /super-admin", ""),
    ("location ^~ /super-admin/", ""),
    ("location ^~ /api/auth/", ""),
]
parts=["    # FADEGO_PORTAL_SINGLE_LOGIN_BEGIN: allow only NextAuth-controlled portal access.\n"]
for name, extra in paths:
    parts.append("    "+name+" {\n"+proxy+extra+"    }\n")
parts.append("""    # The logo in portal Next/Image must not re-trigger HTTP Basic prompts.
    # Strict single URL/width/quality query grammar prevents arbitrary image proxying.
    location = /_next/image {
        auth_basic off;
        if ($args !~* "^url=%2ffadego-mark[.]webp&w=(16|32|48|64|96|128|256|384|640|750|828|1080|1200|1920|2048|3840)&q=75$") {
            return 403;
        }
        proxy_pass http://127.0.0.1:3100;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Authorization "";
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }
    # FADEGO_PORTAL_SINGLE_LOGIN_END

""")
block="".join(parts)
if block.count("auth_basic off;")!=7:
    raise SystemExit("FADEGO_PORTAL_REFUSED_UNEXPECTED_PUBLIC_LOCATIONS")
path.write_text(source.replace(anchor, block+anchor, 1), encoding="utf-8")
print("FADEGO_PORTAL_NGINX=EXACT_LOGIN_AUTH_AND_APP_GUARDED_PANELS")
PY_NGINX
nginx -t -q
systemctl reload nginx

# Wait for Nginx workers to reload before testing, no weakening of checks.
ready=0
for n in $(seq 1 20); do
  code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/login" 2>/dev/null || true)"
  if [[ "$code" == 200 ]]; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo 'FADEGO_PORTAL_REFUSED_LOGIN_STILL_BASIC'; exit 2; }

node <<'PY_NEGATIVE'
const assert = require("node:assert/strict")
const origin = "https://fadego.duckdns.org"
const get = async (path, init={}) => fetch(origin+path, {
  redirect:"manual", signal:AbortSignal.timeout(12000), ...init,
})
;(async () => {
  const home = await get("/")
  assert.equal(home.status,200)
  assert.match(await home.text(),/Portal FADEGO/)
  const login=await get("/login")
  assert.equal(login.status,200)
  assert.equal(login.headers.get("www-authenticate"),null)
  const markup=await login.text()
  assert.match(markup,/Entrar na plataforma/)
  assert.match(markup,/Palavra-passe/)
  for (const route of ["/admin","/super-admin"]) {
    const res=await get(route)
    assert.ok([301,302,303,307,308].includes(res.status),"Expected app redirect for "+route)
    assert.equal(new URL(res.headers.get("location"),origin).pathname,"/login")
    await res.body?.cancel()
  }
  // Unknown barbershop slugs first redirect to /admin, which must itself
  // redirect unauthenticated users to /login. Neither hop may expose data.
  const tenant=await get("/admin/example/agenda")
  assert.ok([301,302,303,307,308].includes(tenant.status))
  const next=new URL(tenant.headers.get("location"),origin)
  assert.equal(next.origin,origin)
  assert.ok(["/admin","/login"].includes(next.pathname))
  await tenant.body?.cancel()
  if(next.pathname==="/admin"){
    const second=await get("/admin")
    assert.ok([301,302,303,307,308].includes(second.status))
    assert.equal(new URL(second.headers.get("location"),origin).pathname,"/login")
    await second.body?.cancel()
  }
  for (const route of ["/b/example","/api/public/barbershops/example/availability",
    "/api/private/bookings/something/availability","/api/integrations/gmail/callback"]) {
    const res=await get(route)
    assert.equal(res.status,401,"HTTP Basic must remain on "+route)
    assert.match(res.headers.get("www-authenticate") || "", /^Basic(?:\s|$)/i)
    await res.body?.cancel()
  }
  const providers=await get("/api/auth/providers")
  assert.equal(providers.status,200)
  const data=await providers.json()
  assert.ok(data.credentials)
  const csrf=await get("/api/auth/csrf")
  assert.equal(csrf.status,200)
  assert.ok((await csrf.json()).csrfToken)
  const publicSession=await get("/api/auth/session")
  assert.equal(publicSession.status,200)
  assert.ok(!(await publicSession.json()).user)
  const block=await get("/_next/image?url=%2Fapi%2Fauth%2Fsession&w=64&q=75")
  assert.equal(block.status,403)
  await block.body?.cancel()
  const image=await get("/_next/image?url=%2Ffadego-mark.webp&w=64&q=75")
  assert.equal(image.status,200,"Approved portal logo must be accessible")
  assert.match(image.headers.get("content-type") || "",/image\//)
  await image.body?.cancel()
  const demo=await get("/experimentar")
  assert.equal(demo.status,200)
  await demo.body?.cancel()
  console.log("FADEGO_PORTAL_ANONYMOUS_LOGIN=HTTP_200")
  console.log("FADEGO_PORTAL_APP_GUARDS=REDIRECT_LOGIN")
  console.log("FADEGO_PORTAL_PROTECTED_BOOKINGS_APIS=401")
  console.log("FADEGO_PORTAL_NEXTAUTH_CSRF_AND_PROVIDER=HEALTHY")
  console.log("FADEGO_PORTAL_OPTIMIZED_LOGO=WHITELISTED")
})().catch(error=>{ console.error(error.message);process.exitCode=1 })
PY_NEGATIVE

# Prove the seeded Owner's real login using the root-only vault, without
# revealing the password, cookie, CSRF token or session in logs.
node <<'PY_POSITIVE'
const assert=require("node:assert/strict")
const fs=require("node:fs")
const origin="https://fadego.duckdns.org"
const email="pilot-admin@fadego.invalid"
const password=fs.readFileSync("/root/project-secrets/fadego-staging/admin-password","utf8").trim()
assert.ok(password.length>10)
const jar=new Map()
const remember=(res)=>{
  const headers=res.headers.getSetCookie?.() || []
  for(const value of headers){
    const pair=value.split(";",1)[0]
    const i=pair.indexOf("=")
    if(i>0) jar.set(pair.slice(0,i),pair.slice(i+1))
  }
}
const cookie=()=>Array.from(jar,([k,v])=>k+"="+v).join("; ")
const req=async (path,init={})=>{
  const headers={...(init.headers||{})}
  if(jar.size) headers.cookie=cookie()
  const res=await fetch(origin+path,{
    redirect:"manual",signal:AbortSignal.timeout(12000),
    ...init,headers
  })
  remember(res)
  return res
}
;(async()=>{
  const csrfRes=await req("/api/auth/csrf")
  assert.equal(csrfRes.status,200)
  const csrf=(await csrfRes.json()).csrfToken
  assert.ok(csrf)
  const body=new URLSearchParams({
    csrfToken:csrf, email,password, callbackUrl:origin+"/admin", json:"true"
  })
  const login=await req("/api/auth/callback/credentials",{
    method:"POST",
    headers:{"content-type":"application/x-www-form-urlencoded"},
    body
  })
  assert.ok([200,302,303].includes(login.status),"Sign-in callback must respond")
  await login.body?.cancel()
  const session=await req("/api/auth/session")
  assert.equal(session.status,200)
  const data=await session.json()
  assert.ok(data.user?.id,"Seeded account must produce a valid user session")
  const admin=await req("/admin")
  assert.equal(admin.status,200,"Authenticated Owner must reach dashboard")
  assert.match(await admin.text(),/Administração FADEGO/)
  const owner=await req("/super-admin")
  assert.equal(owner.status,200,"Owner SUPER_ADMIN role must be enforced")
  assert.match(await owner.text(),/Visão geral FADEGO/)
  console.log("FADEGO_PORTAL_VAULT_OWNER_CREDENTIALS=AUTHENTICATED")
  console.log("FADEGO_PORTAL_OWNER_DASHBOARD=HTTP_200")
  console.log("FADEGO_PORTAL_SUPER_ADMIN=HTTP_200")
})().catch(error=>{console.error("FADEGO_PORTAL_SEEDED_LOGIN_TEST_FAILED",error.message);process.exitCode=1})
PY_POSITIVE

echo 'FADEGO_PORTAL_SINGLE_LOGIN_DEPLOY=SUCCESS'
echo 'FADEGO_PORTAL_WEBSITE=PUBLIC'
echo 'FADEGO_PORTAL_GMAIL_AND_BILLING=UNCHANGED'
