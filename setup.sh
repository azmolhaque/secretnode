#!/usr/bin/env bash
# ============================================================
# SecretNode — Bootstrap Script
# Raspberry Pi 5 / Linux ARM64 (works on any Linux with Python 3.11+)
# Usage: chmod +x setup.sh && ./setup.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${CYAN}[SETUP]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo -e "${RED}[ERR]${NC}   $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Single source of truth for the version — read from pyproject.toml so this
# script can never drift out of sync with the app again.
VERSION="$(grep -m1 -E '^version[[:space:]]*=' "$SCRIPT_DIR/pyproject.toml" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/' || true)"
VERSION="${VERSION:-2.5.0}"

# Read a KEY=value from a .env-style file without tripping `set -e` on no-match.
get_env() { grep -E "^$1=" "$2" 2>/dev/null | tail -n1 | cut -d= -f2- || true; }

# True (exit 0) if something is already listening on the given TCP port.
port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$" && return 0
    elif command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    fi
    return 1
}

# ── 1. Check Python ──────────────────────────────────────────────────────────
log "Checking Python version..."
PYTHON=$(command -v python3 || die "python3 not found. Install it: sudo apt install python3")
PY_VER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log "Found Python $PY_VER"
# Numeric comparison via the interpreter itself — string comparison ("3.9" < "3.11")
# is wrong and would let Python 3.9/3.10 through.
[[ "$("$PYTHON" -c 'import sys; print(int(sys.version_info >= (3, 11)))')" == "1" ]] \
    || die "Python 3.11+ required. Got $PY_VER"
ok "Python $PY_VER"

# ── 2. System deps for lxml / ARM64 ─────────────────────────────────────────
log "Installing system dependencies (lxml, build tools)..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    python3-venv python3-pip \
    libxml2-dev libxslt1-dev \
    build-essential libffi-dev \
    libssl-dev curl 2>/dev/null || warn "apt-get failed — skipping system deps (may still work)"
ok "System deps done"

# ── 3. Create directory structure ────────────────────────────────────────────
log "Creating project directories..."
mkdir -p "$SCRIPT_DIR/backend/data"
mkdir -p "$SCRIPT_DIR/frontend/static"
ok "Directories ready"

# ── 4. Virtual environment ───────────────────────────────────────────────────
VENV="$SCRIPT_DIR/.venv"
if [[ ! -d "$VENV" ]]; then
    log "Creating virtual environment at $VENV..."
    "$PYTHON" -m venv "$VENV"
    ok "venv created"
else
    log "Virtual environment already exists — skipping creation"
fi

PIP="$VENV/bin/pip"

# ── 5. Install requirements ──────────────────────────────────────────────────
# The Pi's piwheels mirror can be slow/flaky — give pip generous timeouts and
# retries, and prefer prebuilt wheels so ARM64 doesn't compile from source.
PIP_NET_OPTS=(--timeout 120 --retries 8 --prefer-binary)

log "Upgrading pip..."
"$PIP" install --upgrade pip "${PIP_NET_OPTS[@]}" --quiet \
    || warn "pip self-upgrade failed (network?) — continuing with the existing pip"

_install_reqs() {  # extra args (e.g. an alternate index) are appended
    "$PIP" install --upgrade -r "$SCRIPT_DIR/requirements.txt" "${PIP_NET_OPTS[@]}" --quiet "$@"
}

log "Installing Python requirements (this may take a few minutes on ARM64)..."
if ! _install_reqs; then
    # The Pi's default index is piwheels, which is frequently slow/flaky. Fall back
    # to PyPI directly before giving up — often the difference between a failed and a
    # clean install on a shaky connection.
    warn "First attempt failed (piwheels flaky?). Retrying against PyPI directly…"
    if ! _install_reqs --index-url https://pypi.org/simple; then
        die "Requirements install failed on both piwheels and PyPI — almost always a flaky
             network (see the WARNINGs above). Nothing is broken; just re-run ./setup.sh once
             connectivity is stable."
    fi
fi
# Fail loudly and early if the app cannot actually start, rather than at first
# request (a flaky piwheels install can leave a single dep — e.g. the uvloop
# C-extension — missing, which crashes the service silently). Importing the real
# app module exercises the whole dependency graph the server needs.
IMPORT_CHECK=$(cd "$SCRIPT_DIR/backend" && SECRETNODE_API_KEY=setup-probe "$VENV/bin/python" -c "
import importlib.util, sys  # note: importlib.util must be imported explicitly
mods = ('fastapi','uvicorn','httpx','websockets','bs4','lxml','aiosqlite','pydantic','google.genai')
missing = []
for m in mods:
    try:
        if importlib.util.find_spec(m) is None:
            missing.append(m)
    except Exception:
        missing.append(m)
if missing:
    print('MISSING: ' + ', '.join(missing)); sys.exit(1)
import main  # noqa: F401 — importing the app surfaces any startup/import error
print('OK')
" 2>&1) || {
    die "The app failed to import after install — the server would not start. Detail:
         ${IMPORT_CHECK}
         This is usually one dependency left half-installed by a flaky network. Fix with:
         $PIP install -r requirements.txt ${PIP_NET_OPTS[*]}   (then re-run ./setup.sh)"
}
ok "Requirements installed & app import-verified"

# ── 6. .env file ────────────────────────────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    log "Generating .env with a fresh API key..."
    GENERATED_KEY=$(openssl rand -hex 24 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(24))")
    cat > "$ENV_FILE" <<ENVEOF
# ── SecretNode v${VERSION} Environment Configuration ──
# A random SECRETNODE_API_KEY was generated below — the dashboard will ask
# for it on first load. Fill in GEMINI_API_KEY and DISCORD_WEBHOOK_URL
# before starting.

SECRETNODE_API_KEY=${GENERATED_KEY}

GEMINI_API_KEY=your_gemini_api_key_here
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_TOKEN

# Two-tier Gemini validation engine (google-genai SDK). Tier 1 pre-filters
# noise cheaply; Tier 2 deep-validates real / critical findings. All overridable.
GEMINI_TIER1_MODEL=gemini-3.1-flash-lite
GEMINI_TIER2_MODEL=gemini-3.5-flash
GEMINI_TIER1_THINKING=minimal
GEMINI_TIER2_THINKING=high
GEMINI_ESCALATE_SEVERITIES=CRITICAL

# Comma-separated list of browser origins allowed to call the API (CORS).
# Leave empty for same-origin dashboard use (default).
ALLOWED_ORIGINS=

# Refuses to scan private/loopback/link-local targets unless "true".
# Only set true for testing your own internal lab infrastructure.
ALLOW_PRIVATE_TARGETS=false

# Keeps JS-asset discovery inside the target's own domain.
SCOPE_SAME_DOMAIN=true

# Max scans running at once (protects the Pi from resource exhaustion).
MAX_CONCURRENT_SCANS=3

LOG_LEVEL=INFO
HOST=0.0.0.0
PORT=8000
ENVEOF
    chmod 600 "$ENV_FILE"
    ok ".env created at $ENV_FILE (permissions set to 600 — owner read/write only)"
    warn "Your dashboard API key: ${GENERATED_KEY}"
    warn "IMPORTANT: Edit $ENV_FILE and add your GEMINI_API_KEY and DISCORD_WEBHOOK_URL before starting."
else
    log ".env already exists — skipping"
    if ! grep -q "^SECRETNODE_API_KEY=.\+" "$ENV_FILE"; then
        die "Existing .env has no SECRETNODE_API_KEY set — the server will refuse to start. Add one (e.g. \`openssl rand -hex 24\`) to $ENV_FILE and re-run."
    fi
fi

# Resolve the host/port the server will bind to (from .env, with defaults).
HOST=$(get_env HOST "$ENV_FILE"); HOST="${HOST:-0.0.0.0}"
PORT=$(get_env PORT "$ENV_FILE"); PORT="${PORT:-8000}"
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; LAN_IP="${LAN_IP:-127.0.0.1}"

# ── 7. Systemd service (optional, for auto-start on boot) ───────────────────
SERVICE_FILE="/etc/systemd/system/secretnode.service"
SERVICE_INSTALLED=0
read -rp "$(echo -e "${CYAN}[SETUP]${NC} Install as systemd service for auto-start? [y/N] ")" INSTALL_SERVICE
if [[ "${INSTALL_SERVICE,,}" == "y" ]]; then
    log "Installing systemd service..."
    sudo tee "$SERVICE_FILE" > /dev/null <<SERVICEEOF
[Unit]
Description=SecretNode v${VERSION} ASM Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$SCRIPT_DIR/backend
EnvironmentFile=$ENV_FILE
ExecStart=$VENV/bin/uvicorn main:app --host $HOST --port $PORT --loop auto --log-level info
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICEEOF
    sudo systemctl daemon-reload
    sudo systemctl enable secretnode >/dev/null 2>&1 || true
    SERVICE_INSTALLED=1
    ok "Systemd service installed (enabled on boot)."
fi

# ── 8. Launch ────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   SecretNode v${VERSION} — Setup Complete${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Edit .env:${NC}   nano $ENV_FILE"
if [[ "$SERVICE_INSTALLED" == "1" ]]; then
    echo -e "  ${CYAN}Service:${NC}     sudo systemctl {start|stop|restart|status} secretnode"
    echo -e "  ${CYAN}Logs:${NC}        journalctl -u secretnode -f"
else
    echo -e "  ${CYAN}Start:${NC}       cd backend && $VENV/bin/uvicorn main:app --host $HOST --port $PORT --loop auto"
fi
echo -e "  ${CYAN}Dashboard:${NC}   http://${LAN_IP}:${PORT}"
echo ""

read -rp "$(echo -e "${CYAN}[SETUP]${NC} Start the server now? [Y/n] ")" START_NOW
[[ "${START_NOW,,}" == "n" ]] && { log "Not starting. You can start it any time (see above)."; exit 0; }

if [[ "$SERVICE_INSTALLED" == "1" ]]; then
    # Start via systemd so we don't spawn a second process fighting for the port.
    # `restart` is idempotent — it cleanly handles an already-running instance.
    log "Starting SecretNode via systemd (systemctl restart secretnode)..."
    sudo systemctl restart secretnode
    sleep 2
    if ! systemctl is-active --quiet secretnode; then
        warn "Service failed to become active. Inspect: journalctl -u secretnode -n 50 --no-pager"
        exit 1
    fi
    # 'active' only means the process launched — probe the HTTP endpoint so a server
    # that started then crashed (or never bound the port) is caught here, not by a
    # blank page in the browser.
    HEALTH_OK=0
    for _ in 1 2 3 4 5 6; do
        if curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/api/health" 2>/dev/null; then HEALTH_OK=1; break; fi
        sleep 1
    done
    if [[ "$HEALTH_OK" == "1" ]]; then
        ok "SecretNode is running and serving → http://${LAN_IP}:${PORT}"
        echo -e "  ${CYAN}Follow logs:${NC} journalctl -u secretnode -f"
    else
        warn "Service is 'active' but not answering on http://127.0.0.1:${PORT} — it likely"
        warn "crashed after start (a missing/broken dependency is the usual cause)."
        warn "See the reason with:  journalctl -u secretnode -n 60 --no-pager"
        exit 1
    fi
    exit 0
fi

# No service: run in the foreground — but first make sure the port is free, so we
# never crash with a raw 'Errno 98 Address already in use'.
if port_in_use "$PORT"; then
    warn "Port ${PORT} is already in use — something is already listening (a previous SecretNode"
    warn "instance, the systemd service, or another app). Not starting a second one."
    warn "  • If it's SecretNode already, just open  http://${LAN_IP}:${PORT}"
    warn "  • To restart a service instance:          sudo systemctl restart secretnode"
    warn "  • To find what holds the port:            sudo ss -ltnp | grep :${PORT}"
    exit 0
fi

log "Starting SecretNode v${VERSION} (foreground; Ctrl-C to stop)..."
cd "$SCRIPT_DIR/backend"
# No --reload in a real deploy: it is a development-only file watcher.
exec "$VENV/bin/uvicorn" main:app \
    --host "$HOST" \
    --port "$PORT" \
    --loop auto \
    --log-level info
