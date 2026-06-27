#!/usr/bin/env bash
# =============================================================================
# SecureVPN middleware — one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/sina99778/securevpn/main/install.sh | bash
#
# Also works from inside a checkout:   ./install.sh
#
# What it does:
#   1. Verifies docker + compose (and git when cloning).
#   2. Clones the repo (unless already inside one).
#   3. Generates strong secrets (JWT, Postgres) and writes .env files
#      — NEVER overwriting ones that already exist.
#   4. Stages attestation files under ./secrets/.
#   5. Builds + starts the stack (postgres, redis, migrator, api, web).
#   6. Waits for the API to become healthy, then bootstraps your admin account.
#
# Non-interactive use — set any of these env vars to skip the prompt:
#   INSTALL_DIR PUBLIC_API_URL PANEL_BASE_URL PANEL_ADMIN_USER PANEL_ADMIN_PASS
#   ADMIN_EMAIL ADMIN_PASSWORD NO_START=1 NO_ADMIN=1
# =============================================================================
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/sina99778/securevpn.git}"
INSTALL_DIR="${INSTALL_DIR:-securevpn}"

# ── pretty output ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'; C_RED=$'\033[1;31m'; C_BLUE=$'\033[1;34m'; C_OFF=$'\033[0m'
else
  C_GREEN=''; C_YELLOW=''; C_RED=''; C_BLUE=''; C_OFF=''
fi
say()  { printf '%s\n' "${C_BLUE}==>${C_OFF} $*"; }
ok()   { printf '%s\n' "${C_GREEN} ✓ ${C_OFF} $*"; }
warn() { printf '%s\n' "${C_YELLOW} ! ${C_OFF} $*"; }
die()  { printf '%s\n' "${C_RED} ✗ ${C_OFF} $*" >&2; exit 1; }

# Prompt that survives `curl | bash` (stdin is the script there, so read from
# the terminal directly). Falls back to the default when there is no TTY.
ask() { # ask <var> <prompt> <default> [silent]
  local _var="$1" _prompt="$2" _default="$3" _silent="${4:-}" _val=""
  # Env override wins (enables fully unattended installs).
  if [ -n "${!_var:-}" ]; then return 0; fi
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    if [ -n "$_silent" ]; then
      printf '%s' "$_prompt [${_default:+hidden default}] : " >/dev/tty
      IFS= read -r -s _val </dev/tty || _val=""
      printf '\n' >/dev/tty
    else
      printf '%s' "$_prompt [${_default}] : " >/dev/tty
      IFS= read -r _val </dev/tty || _val=""
    fi
  fi
  printf -v "$_var" '%s' "${_val:-$_default}"
}

rand_hex() { # rand_hex <bytes>
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# ── flags ────────────────────────────────────────────────────────────────────
usage() {
  cat <<'EOF'
SecureVPN middleware — one-line installer.

usage: install.sh [--no-start] [--no-admin] [-h|--help]

  --no-start   prepare config/secrets only; skip `docker compose up`
  --no-admin   skip the admin-account bootstrap

Non-interactive use — set env vars to skip the prompts:
  INSTALL_DIR PUBLIC_API_URL PANEL_BASE_URL PANEL_ADMIN_USER PANEL_ADMIN_PASS
  ADMIN_EMAIL ADMIN_PASSWORD NO_START=1 NO_ADMIN=1
EOF
}
for arg in "$@"; do
  case "$arg" in
    --no-start) NO_START=1 ;;
    --no-admin) NO_ADMIN=1 ;;
    -h|--help)  usage; exit 0 ;;
    *) die "unknown flag: $arg (try --help)" ;;
  esac
done

# ── prerequisites ────────────────────────────────────────────────────────────
say "Checking prerequisites"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    die "You must run this script as root or have sudo installed to install missing prerequisites."
  fi
fi

if ! command -v curl >/dev/null 2>&1; then
  say "Installing curl..."
  $SUDO apt-get update -y && $SUDO apt-get install -y curl || die "Please install curl manually."
fi

if ! command -v git >/dev/null 2>&1; then
  say "Installing git..."
  $SUDO apt-get update -y && $SUDO apt-get install -y git || die "Please install git manually."
fi

if ! command -v docker >/dev/null 2>&1; then
  say "Docker is missing. Installing Docker automatically..."
  curl -fsSL https://get.docker.com | $SUDO sh || die "Failed to install Docker."
fi

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  say "Installing docker-compose plugin..."
  $SUDO apt-get update -y && $SUDO apt-get install -y docker-compose-plugin || {
    $SUDO curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    $SUDO chmod +x /usr/local/bin/docker-compose
  }
  if docker compose version >/dev/null 2>&1; then
    compose() { docker compose "$@"; }
  elif command -v docker-compose >/dev/null 2>&1; then
    compose() { docker-compose "$@"; }
  else
    die "Failed to install docker compose."
  fi
fi

docker info >/dev/null 2>&1 || {
  say "Starting docker service..."
  $SUDO systemctl enable docker || true
  $SUDO systemctl start docker || true
  sleep 3
  docker info >/dev/null 2>&1 || die "docker daemon is not running (start Docker first)"
}
ok "docker + compose + git + curl found"

# ── locate / clone the repo ──────────────────────────────────────────────────
if [ -f docker-compose.yml ] && [ -f db/migrate.sh ]; then
  ok "Running inside an existing checkout: $(pwd)"
else
  command -v git >/dev/null 2>&1 || die "git is required to clone the repo"
  if [ -d "$INSTALL_DIR/.git" ]; then
    ok "Reusing existing clone at $INSTALL_DIR"
  else
    say "Cloning $REPO_URL → $INSTALL_DIR"
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  fi
  cd "$INSTALL_DIR"
fi

# ── gather config ────────────────────────────────────────────────────────────
say "Configuration (Enter accepts the default)"
ask PUBLIC_API_URL  "Public URL of this server (what the admin's browser will call)" "http://localhost:3000"
ask PANEL_PROVIDER  "Panel Provider (rebecca | remnawave)" "rebecca"

if [ "$PANEL_PROVIDER" = "rebecca" ]; then
  ask PANEL_BASE_URL  "Rebecca panel base URL (private network)" "https://panel.internal:8000"
  ask PANEL_ADMIN_USER "Rebecca panel admin username" "change-me"
  ask PANEL_ADMIN_PASS "Rebecca panel admin password" "change-me" silent
  REMNAWAVE_BASE_URL="${REMNAWAVE_BASE_URL:-}"
  REMNAWAVE_TOKEN="${REMNAWAVE_TOKEN:-}"
  REMNAWAVE_SQUAD_UUIDS="${REMNAWAVE_SQUAD_UUIDS:-}"
  REMNAWAVE_CADDY_TOKEN="${REMNAWAVE_CADDY_TOKEN:-}"
else
  ask REMNAWAVE_BASE_URL  "Remnawave panel base URL" "https://panel.example.com"
  ask REMNAWAVE_TOKEN "Remnawave API token (Bearer)" "" silent
  ask REMNAWAVE_SQUAD_UUIDS "Remnawave squad UUIDs (comma-separated)" ""
  PANEL_BASE_URL="${PANEL_BASE_URL:-}"
  PANEL_ADMIN_USER="${PANEL_ADMIN_USER:-}"
  PANEL_ADMIN_PASS="${PANEL_ADMIN_PASS:-}"
fi
PUBLIC_API_URL="${PUBLIC_API_URL%/}"

# ── root .env (compose interpolation) ────────────────────────────────────────
if [ -f .env ]; then
  warn ".env already exists — keeping it untouched"
else
  say "Writing .env (compose-level config)"
  PG_PASS="$(rand_hex 24)"
  cat > .env <<EOF
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Safe to edit.
POSTGRES_USER=vpn
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_DB=vpn
# Baked into the dashboard at BUILD time; rebuild web after changing:
#   docker compose up -d --build web
NEXT_PUBLIC_API_URL=${PUBLIC_API_URL}/api/v1
TRUST_PROXY_HOPS=1
EOF
  ok ".env written (Postgres password generated)"
fi

# ── backend/.env (API secrets) ───────────────────────────────────────────────
if [ -f backend/.env ]; then
  warn "backend/.env already exists — keeping it untouched"
else
  say "Writing backend/.env (JWT secret generated)"
  JWT="$(rand_hex 48)"
  cat > backend/.env <<EOF
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Safe to edit.
# NOTE: inside docker compose, DATABASE_URL/REDIS_URL are injected by the
# compose file and override anything set here.

# ── Server ──
PORT=3000

# ── Auth ──
JWT_SECRET=${JWT}
JWT_ISSUER=securevpn
JWT_AUDIENCE=securevpn-clients
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL_MS=2592000000
LOGIN_MAX_FAILED=5
LOGIN_LOCKOUT_MS=900000
ARGON_MEMORY_MIB=64
ARGON_TIME_COST=3
ARGON_PARALLELISM=4

# ── Admin / Ops ──
ADMIN_GRANT_DAYS=30
# TELEGRAM_BOT_TOKEN=            # set to enable the Telegram ops bot
ADMIN_TELEGRAM_IDS=              # comma-separated numeric Telegram IDs

# ── Panel selection ──
# "rebecca" (Marzban-family) or "remnawave" (https://docs.rw).
PANEL_PROVIDER=${PANEL_PROVIDER}
PANEL_TIMEOUT_MS=8000

# ── Rebecca panel (used when PANEL_PROVIDER=rebecca; private network only) ──
PANEL_BASE_URL=${PANEL_BASE_URL}
PANEL_ADMIN_USER=${PANEL_ADMIN_USER}
PANEL_ADMIN_PASS=${PANEL_ADMIN_PASS}

# ── Remnawave panel (used when PANEL_PROVIDER=remnawave) ──
REMNAWAVE_BASE_URL=${REMNAWAVE_BASE_URL}
REMNAWAVE_TOKEN=${REMNAWAVE_TOKEN}
REMNAWAVE_CADDY_TOKEN=${REMNAWAVE_CADDY_TOKEN:-}
# Comma-separated internal-squad UUID(s); REQUIRED for remnawave (fail-closed).
REMNAWAVE_SQUAD_UUIDS=${REMNAWAVE_SQUAD_UUIDS}

# ── Connection / tiers ──
FREE_MAX_SESSIONS=1
PREMIUM_MAX_SESSIONS=3
FREE_PROVISIONING_TTL_MS=300000
PREMIUM_FALLBACK_TTL_MS=2592000000
CONNECT_REQUIRED_ADS=2
CONNECT_GRANT_MINUTES=60
VLESS_FLOW=xtls-rprx-vision

# ── Ads / reward ──
AD_TOKEN_WINDOW_MIN=15
MAX_SESSION_MINUTES=1440

# ── Workers ──
OUTBOX_BATCH=20
OUTBOX_TICK_MS=5000
OUTBOX_LEASE_MIN=2
OUTBOX_MAX_ATTEMPTS=12
REAPER_BATCH=500

# ── Attestation: Android / Play Integrity ──
# Replace with YOUR app's package name + a real service-account JSON before
# shipping the mobile app. The API boots fine with these placeholders.
ANDROID_PACKAGE_NAME=app.securevpn
GOOGLE_APPLICATION_CREDENTIALS=/secrets/play-integrity-sa.json
ANDROID_CERT_SHA256_B64=
ANDROID_TOKEN_MAX_AGE_MS=300000

# ── Attestation: iOS / App Attest ──
APPLE_TEAM_ID=__TEAMID__
APPLE_BUNDLE_ID=app.securevpn
APPLE_ATTEST_ENV=production
APPLE_APPATTEST_ROOT_CA_PEM=/secrets/Apple_App_Attestation_Root_CA.pem

# ── Attestation: common ──
ATTEST_CHALLENGE_TTL_MS=300000
ATTEST_TTL_MS=86400000
EOF
  ok "backend/.env written"
fi

# ── secrets dir (mounted read-only into the api container) ──────────────────
say "Staging ./secrets"
mkdir -p secrets
if [ ! -f secrets/Apple_App_Attestation_Root_CA.pem ]; then
  # Vendored copy of Apple's PUBLIC App Attest root CA (trust anchor).
  cp certs/Apple_App_Attestation_Root_CA.pem secrets/
  ok "Apple App Attest root CA staged"
fi
if [ ! -f secrets/play-integrity-sa.json ]; then
  printf '{ "_comment": "REPLACE ME with your Google Play Integrity service-account JSON" }\n' \
    > secrets/play-integrity-sa.json
  warn "secrets/play-integrity-sa.json is a placeholder — replace it before shipping the Android app"
fi

# ── bring the stack up ───────────────────────────────────────────────────────
if [ "${NO_START:-0}" = "1" ]; then
  ok "Prepared (NO_START=1). Start later with: docker compose up -d --build"
  exit 0
fi

say "Building images + starting the stack (first run takes a few minutes)"
compose up -d --build

say "Waiting for the API to become healthy"
tries=0
until curl -fsS -o /dev/null --max-time 3 "http://localhost:3000/api/v1/health"; do
  tries=$((tries + 1))
  if [ "$tries" -ge 60 ]; then
    compose logs --tail 50 api || true
    die "API did not become healthy after 3 minutes — see logs above (docker compose logs api)"
  fi
  sleep 3
done
ok "API is healthy"

# ── bootstrap the first admin ────────────────────────────────────────────────
if [ "${NO_ADMIN:-0}" != "1" ]; then
  say "Creating your admin account"
  # </dev/null: the child must never read OUR stdin — under `curl | bash` that
  # stdin is the not-yet-executed tail of this script. Prompts use /dev/tty.
  if API_URL="http://localhost:3000/api/v1" bash scripts/create-admin.sh </dev/null; then
    :
  else
    warn "Admin bootstrap skipped/failed — run it any time:  bash scripts/create-admin.sh"
  fi
fi

# ── done ─────────────────────────────────────────────────────────────────────
printf '\n'
ok  "Install complete."
printf '%s\n' "    Dashboard : ${C_GREEN}http://localhost:3001${C_OFF}  (or port 3001 behind your reverse proxy)"
printf '%s\n' "    API       : ${PUBLIC_API_URL}/api/v1  (health: /api/v1/health)"
printf '%s\n' "    Logs      : docker compose logs -f api"
printf '%s\n' "    Stop      : docker compose down        (add -v to wipe the DB)"
printf '\n'
warn "Production checklist: put a TLS reverse proxy in front, point PANEL_BASE_URL"
warn "at your real Rebecca panel, and replace the attestation placeholders in"
warn "backend/.env + secrets/ before shipping the mobile apps."
