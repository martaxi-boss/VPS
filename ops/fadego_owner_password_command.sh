#!/usr/bin/env bash
# FADEGO staging: set the only active platform-owner password privately.
# The password is never passed in shell arguments, logged, or sent to GitHub.
set +x
set -Eeuo pipefail
umask 077

ROOT=/srv/fadego-staging
SHA=1d19279f834ba726c5fede3f164d537f1414d3ea
VAULT=/root/project-secrets/fadego-staging/admin-password
ENV_FILE=/etc/fadego-staging/app.env
SEND_CLOSED=/etc/fadego-staging/send-closed.env

if [[ $(id -u) != 0 ]]; then
  echo 'Use sudo para executar este comando.' >&2
  exit 2
fi
for utility in flock node runuser git; do
  command -v "$utility" >/dev/null || { echo 'Falta uma dependencia do FADEGO.' >&2; exit 2; }
done
if [[ ! -c /dev/tty || ! -t 0 ]]; then
  echo 'Executa num terminal interativo, nao por GitHub Actions ou chat.' >&2
  exit 2
fi
exec 9>/run/fadego-staging-password.lock
flock -n 9 || { echo 'Ja existe outra configuracao de password em curso.' >&2; exit 2; }

[[ -L "$ROOT/current" ]] || { echo 'Release FADEGO indisponivel.' >&2; exit 2; }
[[ $(readlink -f "$ROOT/current") == "$ROOT/releases/$SHA" ]] || {
  echo 'Release FADEGO diferente da versao verificada. Operacao cancelada.' >&2
  exit 2
}
[[ $(runuser -u fadego-staging -- git -C "$ROOT/current" rev-parse HEAD) == "$SHA" ]] || exit 2
[[ -f "$VAULT" && ! -L "$VAULT" && -s "$VAULT" ]] || {
  echo 'Cofre FADEGO indisponivel ou nao seguro.' >&2
  exit 2
}
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" && -s "$ENV_FILE" ]] || exit 2
[[ -f "$SEND_CLOSED" && ! -L "$SEND_CLOSED" ]] || exit 2
grep -Fxq 'BOOKING_EMAIL_PROVIDER=disabled' "$SEND_CLOSED"
grep -Fxq 'GMAIL_LIVE_SEND_ENABLED=false' "$SEND_CLOSED"

# Existing root-owned app environment; never display any env secret.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
[[ -n ${DATABASE_URL:-} ]] || { echo 'Ligacao da base de dados indisponivel.' >&2; exit 2; }

new_password=''
confirm_password=''
cleanup() { unset new_password confirm_password; }
trap cleanup EXIT
printf '\nFADEGO - configurar palavra-passe do proprietario\n'
printf 'Escolhe a tua palavra-passe livremente.\n\n'
IFS= read -r -s -p 'Nova palavra-passe: ' new_password </dev/tty || exit 2
printf '\n' >/dev/tty
if [[ -z "$new_password" ]]; then
  echo 'O terminal nao recebeu nenhum caracter. Confirma o teclado do ConnectBot e tenta novamente.' >&2
  exit 2
fi
IFS= read -r -s -p 'Repetir palavra-passe: ' confirm_password </dev/tty || exit 2
printf '\n' >/dev/tty
if [[ "$new_password" != "$confirm_password" ]]; then
  echo 'As duas palavras-passe nao coincidem. Nao foi alterado nada.' >&2
  exit 2
fi
unset confirm_password

# Send the secret only on the private pipe to Node, not in argv/env/logs.
# Node uses the existing scrypt format and pg dependency of FADEGO.
printf '%s' "$new_password" | node -e "$(cat <<'JS_PASSWORD_ROTATION'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Client } = require('/srv/fadego-staging/current/node_modules/pg');
const vault = '/root/project-secrets/fadego-staging/admin-password';
const ownerEmail = 'pilot-admin@fadego.invalid';
const expectedUrl = {
  protocol: 'postgresql:', hostname: '127.0.0.1', port: '5432',
  username: 'fadego_staging', pathname: '/fadego_staging',
};
const readInput = async () => {
  let secret = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) secret += chunk;
  if (secret.length === 0) throw Error('Nenhuma palavra-passe recebida do terminal.');
  if (secret.length > 512 || /[\r\n\u0000]/.test(secret)) {
    throw Error('A palavra-passe contem caracteres nao suportados.');
  }
  return secret;
};
const requirePrivateFile = (file, isDirectory) => {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o077) !== 0 ||
      !(isDirectory ? stat.isDirectory() : stat.isFile())) {
    throw Error('As permissoes do cofre nao sao seguras.');
  }
};

async function main() {
  const password = await readInput();
  const url = new URL(process.env.DATABASE_URL || '');
  for (const [k, v] of Object.entries(expectedUrl)) {
    if (url[k] !== v) throw Error('Base de dados FADEGO inesperada.');
  }
  requirePrivateFile(path.dirname(vault), true);
  requirePrivateFile(vault, false);
  if (fs.statSync(vault).size === 0) throw Error('O cofre FADEGO esta vazio.');
  const salt = crypto.randomBytes(16);
  const derived = await new Promise((resolve, reject) => crypto.scrypt(
    password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
    (error, value) => error ? reject(error) : resolve(value),
  ));
  const encoded = ['scrypt', 16384, 8, 1, salt.toString('base64'),
    derived.toString('base64')].join('$');

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  const dir = path.dirname(vault);
  const suffix = crypto.randomBytes(8).toString('hex');
  const pending = `${vault}.pending-${suffix}`;
  const backup = `${vault}.previous-${suffix}`;
  let began = false, backupExists = false, committed = false;
  try {
    await client.connect();
    await client.query('BEGIN');
    began = true;
    const result = await client.query(
      'SELECT id, email FROM "User" WHERE "platformRole" = $1 AND active = true LIMIT 2 FOR UPDATE',
      ['SUPER_ADMIN'],
    );
    if (result.rows.length !== 1 || result.rows[0].email !== ownerEmail) {
      throw Error('Nao existe exatamente um proprietario FADEGO ativo esperado.');
    }
    await client.query('UPDATE "User" SET "passwordHash" = $1, "updatedAt" = NOW() WHERE id = $2',
      [encoded, result.rows[0].id]);

    const fd = fs.openSync(pending, 'wx', 0o600);
    try {
      fs.writeSync(fd, password + '\n', undefined, 'utf8');
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    fs.renameSync(vault, backup);
    backupExists = true;
    fs.renameSync(pending, vault);
    const dfd = fs.openSync(dir, 'r');
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    await client.query('COMMIT');
    began = false;
    committed = true;
    try { fs.unlinkSync(backup); backupExists = false; }
    catch { console.error('Aviso: existe uma copia de seguranca root para remover manualmente.'); }
    console.log('FADEGO_PASSWORD=CONFIGURADA');
    console.log('COFRE_FADEGO=ATUALIZADO');
    console.log('LOGIN=JA_PODE_SER_TESTADO');
  } catch (error) {
    if (began) {
      try { await client.query('ROLLBACK'); }
      catch { console.error('Atencao: confirma o estado da base de dados antes de repetir.'); }
    }
    if (!committed && backupExists) {
      try { fs.renameSync(backup, vault); backupExists = false; }
      catch { console.error('ATENCAO: recuperacao do cofre requer intervencao tecnica.'); }
    }
    if (fs.existsSync(pending)) fs.unlinkSync(pending);
    throw error;
  } finally {
    await client.end().catch(() => {});
  }
}
main().catch(error => {
  console.error('FADEGO_PASSWORD=NAO_ALTERADA:', error.message);
  process.exitCode = 1;
});
JS_PASSWORD_ROTATION
)"
unset new_password
