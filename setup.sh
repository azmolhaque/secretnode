#!/usr/bin/env bash
# ============================================================
# SecretNode v2.0 — Bootstrap Script
# Raspberry Pi 5 / Linux ARM64
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

# ── 1. Check Python ──────────────────────────────────────────────────────────
log "Checking Python version..."
PYTHON=$(command -v python3 || die "python3 not found. Install it: sudo apt install python3")
PY_VER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log "Found Python $PY_VER"
[[ "$PY_VER" < "3.11" ]] && die "Python 3.11+ required. Got $PY_VER"
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
PYTHON_VENV="$VENV/bin/python"

# ── 5. Install requirements ──────────────────────────────────────────────────
log "Upgrading pip..."
"$PIP" install --upgrade pip --quiet

log "Installing Python requirements (this may take a few minutes on ARM64)..."
"$PIP" install --upgrade -r "$SCRIPT_DIR/requirements.txt" --quiet
ok "Requirements installed"

# ── 6. .env file ────────────────────────────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    log "Generating .env with a fresh API key..."
    GENERATED_KEY=$(openssl rand -hex 24 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(24))")
    cat > "$ENV_FILE" <<ENVEOF
# ── SecretNode v2.0 Environment Configuration ──
# A random SECRETNODE_API_KEY was generated below — the dashboard will ask
# for it on first load. Fill in GEMINI_API_KEY and DISCORD_WEBHOOK_URL
# before starting.

SECRETNODE_API_KEY=${GENERATED_KEY}

GEMINI_API_KEY=your_gemini_api_key_here
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_TOKEN
GEMINI_MODEL=gemini-1.5-flash

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

# ── 7. Systemd service (optional, for auto-start on boot) ───────────────────
SERVICE_FILE="/etc/systemd/system/secretnode.service"
read -rp "$(echo -e "${CYAN}[SETUP]${NC} Install as systemd service for auto-start? [y/N] ")" INSTALL_SERVICE
if [[ "${INSTALL_SERVICE,,}" == "y" ]]; then
    log "Installing systemd service..."
    sudo tee "$SERVICE_FILE" > /dev/null <<SERVICEEOF
[Unit]
Description=SecretNode v2.0 ASM Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$SCRIPT_DIR/backend
EnvironmentFile=$ENV_FILE
ExecStart=$VENV/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --loop uvloop --log-level info
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICEEOF
    sudo systemctl daemon-reload
    sudo systemctl enable secretnode
    ok "Systemd service installed: sudo systemctl start secretnode"
fi

# ── 8. Launch ────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   SecretNode v2.0 — Setup Complete           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Edit .env:${NC}  nano $ENV_FILE"
echo -e "  ${CYAN}Start:${NC}      cd backend && $VENV/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --loop uvloop"
echo -e "  ${CYAN}Dashboard:${NC}  http://$(hostname -I | awk '{print $1}'):8000"
echo ""

read -rp "$(echo -e "${CYAN}[SETUP]${NC} Start the server now? [Y/n] ")" START_NOW
if [[ "${START_NOW,,}" != "n" ]]; then
    log "Starting SecretNode v2.0..."
    cd "$SCRIPT_DIR/backend"
    exec "$VENV/bin/uvicorn" main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --loop uvloop \
        --log-level info \
        --reload
fi
