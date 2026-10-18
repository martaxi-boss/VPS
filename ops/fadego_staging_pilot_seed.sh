#!/usr/bin/env bash
# Synthetic pilot data, staging ONLY. Never changes credentials, network or email gates.
set -Eeuo pipefail
umask 077

ROOT=/srv/fadego-staging
SHA=037fc4c5794bdde1177d6b086cf87710b4335483
ENV=/etc/fadego-staging/app.env
SEND_CLOSED=/etc/fadego-staging/send-closed.env

if [[ "$(id -u)" != 0 || "${FADEGO_STAGING_PILOT_OPERATOR_APPROVED:-}" != 1 ]]; then
  echo 'FADEGO_PILOT_INSTALL=REFUSED_NO_SUPERVISOR_APPROVAL'; exit 2
fi
exec 9>/run/fadego-staging-pilot.lock
flock -n 9 || { echo 'FADEGO_PILOT_INSTALL=REFUSED_BUSY'; exit 2; }

[[ -L "$ROOT/current" && ! -L "$ROOT/releases" ]] || exit 2
[[ "$(readlink -f "$ROOT/current")" == "$ROOT/releases/$SHA" ]] || {
  echo 'FADEGO_PILOT_INSTALL=REFUSED_RELEASE_DRIFT'; exit 2;
}
[[ "$(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD)" == "$SHA" ]] || exit 2
[[ -f "$ENV" && ! -L "$ENV" && -s "$ENV" ]] || exit 2
[[ -f "$SEND_CLOSED" && ! -L "$SEND_CLOSED" && -s "$SEND_CLOSED" ]] || exit 2
grep -Fxq 'BOOKING_EMAIL_PROVIDER=disabled' "$SEND_CLOSED"
grep -Fxq 'GMAIL_LIVE_SEND_ENABLED=false' "$SEND_CLOSED"
[[ -x "$ROOT/current/node_modules/.bin/tsx" ]] || { echo 'FADEGO_PILOT_INSTALL=REFUSED_NO_TSX'; exit 2; }
systemctl is-active --quiet fadego-staging.service
systemctl is-active --quiet nginx

# Source the pre-existing root-managed credentials, never echo or transmit.
set -a
source "$ENV"
source "$SEND_CLOSED"
set +a
[[ "${BOOKING_EMAIL_PROVIDER:-}" == "disabled" &&
   "${GMAIL_LIVE_SEND_ENABLED:-}" == "false" ]] || exit 2
[[ "${NEXTAUTH_URL:-}" == "https://fadego.duckdns.org" ]] || exit 2
export FADEGO_STAGING_SUPERVISOR_APPROVED=1
export FADEGO_STAGING_PILOT_SEED_APPROVED=1
export HOME="$ROOT" COREPACK_HOME="$ROOT/.cache/corepack"

# SQL writes limited to one synthetic SUSPENDED tenant in one DB transaction.
# App policy rechecks exact database URL, root origin and cwd. Existing slug aborts.
cd "$ROOT/current"
runuser -u fadego-staging -m -- ./node_modules/.bin/tsx scripts/staging-pilot-seed.ts

# Independently verify only fake data and its intended state. No PII is logged.
runuser -u fadego-staging -m -- ./node_modules/.bin/tsx -e '
import { db, getPool } from "./lib/prisma";
async function main(){
  const pilot = await db.barbershop.findUnique({
    where: { slug: "fadego-piloto-interno" },
    select: {
      id: true, status: true,
      _count: { select: {
        staffMembers: true, chairs: true, services: true,
        customers: true, bookings: true, members: true, openingHours: true
      } }
    }
  });
  if (!pilot || pilot.status !== "SUSPENDED" ||
      pilot._count.staffMembers !== 2 ||
      pilot._count.chairs !== 3 ||
      pilot._count.services !== 3 ||
      pilot._count.customers !== 2 ||
      pilot._count.bookings !== 2 ||
      pilot._count.members !== 1 ||
      pilot._count.openingHours !== 7) throw Error("FADEGO_PILOT_VERIFICATION_FAILED");
  const owner = await db.user.findUnique({
    where: { email: "pilot-admin@fadego.invalid" },
    select: { id: true, active: true, platformRole: true }
  });
  if (!owner || !owner.active || owner.platformRole !== "SUPER_ADMIN") throw Error("FADEGO_PILOT_OWNER_NOT_ACTIVE");
  const member = await db.barbershopMember.findUnique({
    where: { barbershopId_userId: { barbershopId: pilot.id, userId: owner.id } },
    select: { role: true, active: true, revokedAt: true }
  });
  if (!member || member.role !== "OWNER" || !member.active || member.revokedAt)
    throw Error("FADEGO_PILOT_OWNER_ACCESS_INACTIVE");
  console.log("FADEGO_PILOT_OWNER_ACCESS=ACTIVE");
  console.log("FADEGO_PILOT_SYNTHETIC_DATA=VERIFIED");
  console.log("FADEGO_PILOT_STATUS=SUSPENDED");
}
main().catch(e=>{console.error(e.message);process.exitCode=1}).finally(async()=>{
  await db.$disconnect(); await getPool().end();
});
'
echo 'FADEGO_PILOT_STAGING=READY_FOR_OWNER_VISUAL_TEST'
echo 'FADEGO_PILOT_PRIVATE_PATH=/admin/fadego-piloto-interno'
echo 'FADEGO_PILOT_NO_REAL_EMAILS_PAYMENTS_OR_PUBLIC_BOOKING=PASS'
