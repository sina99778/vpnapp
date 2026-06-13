#!/usr/bin/env bash
# =============================================================================
# Bootstrap (or repair) the first ADMIN account.
#
#   bash scripts/create-admin.sh
#   ADMIN_EMAIL=a@b.com ADMIN_PASSWORD='min-12-chars!' bash scripts/create-admin.sh
#
# Flow: register a user via the public API (argon2id hashing happens server-
# side), then promote it to role=admin with one SQL statement inside the
# postgres container. Safe to re-run: if the email is already registered the
# registration step is skipped and only the promotion runs.
# =============================================================================
set -euo pipefail

API_URL="${API_URL:-http://localhost:3000/api/v1}"

if [ -t 1 ]; then C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'; C_RED=$'\033[1;31m'; C_OFF=$'\033[0m'
else C_GREEN=''; C_YELLOW=''; C_RED=''; C_OFF=''; fi
ok()   { printf '%s\n' "${C_GREEN} ✓ ${C_OFF} $*"; }
warn() { printf '%s\n' "${C_YELLOW} ! ${C_OFF} $*"; }
die()  { printf '%s\n' "${C_RED} ✗ ${C_OFF} $*" >&2; exit 1; }

ask() { # ask <var> <prompt> [silent]
  local _var="$1" _prompt="$2" _silent="${3:-}" _val=""
  if [ -n "${!_var:-}" ]; then return 0; fi
  [ -r /dev/tty ] && [ -w /dev/tty ] || die "no TTY — set ${_var} via environment"
  if [ -n "$_silent" ]; then
    printf '%s' "$_prompt: " >/dev/tty; IFS= read -r -s _val </dev/tty; printf '\n' >/dev/tty
  else
    printf '%s' "$_prompt: " >/dev/tty; IFS= read -r _val </dev/tty
  fi
  [ -n "$_val" ] || die "${_var} must not be empty"
  printf -v "$_var" '%s' "$_val"
}

json_escape() { # minimal: backslash + double-quote (sufficient for credentials)
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

if docker compose version >/dev/null 2>&1; then compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then compose() { docker-compose "$@"; }
else die "docker compose is required (the promotion step runs psql in the postgres container)"; fi

# Compose-level DB credentials (fall back to the defaults in docker-compose.yml).
PGUSER="vpn"; PGDB="vpn"
if [ -f .env ]; then
  PGUSER="$(sed -n 's/^POSTGRES_USER=//p' .env | tail -1)"; PGUSER="${PGUSER:-vpn}"
  PGDB="$(sed -n 's/^POSTGRES_DB=//p' .env | tail -1)"; PGDB="${PGDB:-vpn}"
fi

ask ADMIN_EMAIL    "Admin email"
ask ADMIN_PASSWORD "Admin password (min 12 chars)" silent
[ "${#ADMIN_PASSWORD}" -ge 12 ] || die "password must be at least 12 characters"

EMAIL_JSON="$(json_escape "$ADMIN_EMAIL")"
PASS_JSON="$(json_escape "$ADMIN_PASSWORD")"

# 1) Anonymous identity (entry point of the public funnel).
anon_body="$(curl -fsS -X POST "$API_URL/auth/anon" \
  -H 'Content-Type: application/json' \
  -d "{\"platform\":\"android\",\"installId\":\"admin-bootstrap-$(date +%s)-$RANDOM\"}")" \
  || die "could not reach the API at $API_URL"
token="$(printf '%s' "$anon_body" | grep -o '"accessToken":"[^"]*"' | head -1 | cut -d'"' -f4)"
[ -n "$token" ] || die "unexpected /auth/anon response: $anon_body"

# 2) Claim it with email + password (argon2id server-side).
http_code="$(curl -sS -o /tmp/register_out.$$ -w '%{http_code}' -X POST "$API_URL/auth/register" \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL_JSON\",\"password\":\"$PASS_JSON\"}")"
if [ "$http_code" = "200" ]; then
  ok "account registered: $ADMIN_EMAIL"
else
  # Already registered is fine — we still promote below.
  warn "register returned HTTP $http_code ($(cat /tmp/register_out.$$ 2>/dev/null | head -c 200)) — continuing to promotion"
fi
rm -f /tmp/register_out.$$

# 3) Promote to admin (single SQL statement; '' escapes quotes for SQL).
# </dev/null: psql needs nothing on stdin, and `compose exec` would otherwise
# inherit-and-drain it — under `curl | bash` that stdin IS the installer script.
EMAIL_SQL="$(printf '%s' "$ADMIN_EMAIL" | sed "s/'/''/g")"
out="$(compose exec -T postgres psql -U "$PGUSER" -d "$PGDB" -v ON_ERROR_STOP=1 \
  -c "update users set role='admin', updated_at=now() where email='${EMAIL_SQL}';" </dev/null)"
case "$out" in
  *"UPDATE 1"*) ok "promoted to admin" ;;
  *"UPDATE 0"*) die "no user with email $ADMIN_EMAIL exists — registration must have failed (see above)" ;;
  *)            die "unexpected psql output: $out" ;;
esac

ok "Done. Sign in at the dashboard with $ADMIN_EMAIL"
