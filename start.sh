#!/bin/bash
# ═════════════════════════════════════════════════════════════════════════════
#  MISTRAL Defense Agent — Unified Start Script for Ubuntu/Debian Server
#  Запускает: Server REST+WSS, Telegram Bot, Lua Monitors
# ═════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ═══ Configuration ═════════════════════════════════════════════════════════
LOG_DIR="$SCRIPT_DIR/logs"
PID_DIR="$SCRIPT_DIR/.pids"
NODE_BIN="$(which node)"
LUA_BIN="$(which lua || which lua5.3 || which lua5.4 || true)"

mkdir -p "$LOG_DIR" "$PID_DIR"

# ═══ Helper Functions ══════════════════════════════════════════════════════
log_info()  { echo -e "${BLUE}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}   $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

save_pid() {
    echo $2 > "$PID_DIR/$1.pid"
}

kill_proc() {
    local name=$1
    local pidfile="$PID_DIR/${name}.pid"
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log_warn "Stopping $name (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$pidfile"
    fi
}

stop_all() {
    log_warn "Shutting down MISTRAL services..."
    kill_proc "server"
    kill_proc "telegram-bot"
    kill_proc "monitors"
    log_ok "All services stopped"
    exit 0
}

trap stop_all SIGINT SIGTERM

# ═══ Check Dependencies ════════════════════════════════════════════════════
log_info "Checking dependencies..."

if [ ! -f ".env" ]; then
    log_warn ".env not found! Copying from .env.example..."
    cp .env.example .env
    log_warn "Please edit .env and set your API keys before restarting!"
    exit 1
fi

if ! command -v npm &> /dev/null; then
    log_error "npm не найден! Установите Node.js и npm."
    log_info "Команда для установки: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs"
    exit 1
fi

if [ ! -d "node_modules" ]; then
    log_info "Installing Node.js dependencies..."
    npm install
fi

if [ -z "$LUA_BIN" ] || [ ! -x "$LUA_BIN" ]; then
    log_warn "Lua not found. Lua monitors will not start."
    log_warn "Install: sudo apt install lua5.3 lua-socket lua-cjson"
    LUA_BIN=""
else
    if ! $LUA_BIN -e "require('socket')" 2>/dev/null; then
        log_warn "LuaSocket not found. Install: sudo apt install lua-socket"
    fi
    if ! $LUA_BIN -e "require('cjson')" 2>/dev/null; then
        log_warn "lua-cjson not found. Install: sudo apt install lua-cjson"
    fi
fi

log_ok "Dependencies OK"

# ═══ Start Services ════════════════════════════════════════════════════════
log_info "═══════════════════════════════════════════"
log_info "  MISTRAL Defense Agent — Server Startup"
log_info "═══════════════════════════════════════════"

# 1. Start Main Server (REST API + WSS)
log_info "[1/3] Starting MISTRAL Server (REST API + WebSocket)..."
$NODE_BIN server.js > "$LOG_DIR/server.log" 2>&1 &
save_pid "server" $!
sleep 2
if kill -0 $(cat "$PID_DIR/server.pid") 2>/dev/null; then
    API_PORT=$(grep '^API_PORT=' .env | cut -d= -f2 || echo 8080)
    WSS_PORT=$(grep '^WSS_PORT=' .env | cut -d= -f2 || echo 8443)
    log_ok "Server running on port ${WSS_PORT} (WSS) and ${API_PORT} (REST)"
else
    log_error "Server failed to start! Check logs/server.log"
    exit 1
fi

# 2. Start Telegram Bot (after server is confirmed running)
log_info "[2/3] Starting Telegram Bot..."
sleep 2
$NODE_BIN telegram-bot.js > "$LOG_DIR/telegram-bot.log" 2>&1 &
save_pid "telegram-bot" $!
sleep 1
if kill -0 $(cat "$PID_DIR/telegram-bot.pid") 2>/dev/null; then
    log_ok "Telegram bot polling started"
else
    log_warn "Telegram bot may have failed. Check logs/telegram-bot.log"
fi

# 3. Start Lua Monitors
log_info "[3/3] Starting Lua System Monitors..."
if [ -n "$LUA_BIN" ] && [ -x "$LUA_BIN" ]; then
    cd monitors
    bash run-monitors.sh start > "$LOG_DIR/monitors.log" 2>&1 &
    cd "$SCRIPT_DIR"
    save_pid "monitors" $!
    sleep 1
    if kill -0 $(cat "$PID_DIR/monitors.pid") 2>/dev/null; then
        log_ok "Lua monitors running (A: System, B: Auth, C: Network, D: Integrity)"
    else
        log_warn "Monitors may have failed. Check logs/monitors.log"
    fi
else
    log_warn "Skipping Lua monitors — Lua not available"
fi

# ═══ Status ════════════════════════════════════════════════════════════════
echo ""
log_info "═══════════════════════════════════════════"
log_ok  "  ALL SERVICES STARTED SUCCESSFULLY"
log_info "═══════════════════════════════════════════"
echo ""
API_PORT=$(grep '^API_PORT=' .env | cut -d= -f2 || echo 8080)
WSS_PORT=$(grep '^WSS_PORT=' .env | cut -d= -f2 || echo 8443)
  # Determine public IP for client connection string
SERVER_IP=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo -e "  ${BLUE}Server REST API:${NC}    http://localhost:${API_PORT}"
echo -e "  ${BLUE}Server WebSocket:${NC}   wss://localhost:${WSS_PORT}/ws"
echo -e "  ${BLUE}Telegram Bot:${NC}       Polling mode"
echo -e "  ${BLUE}Monitors:${NC}           Lua watchers active"
echo -e "  ${BLUE}Logs:${NC}               $LOG_DIR/"
echo -e "  ${BLUE}PID files:${NC}          $PID_DIR/"
echo ""
echo -e "  ┌─────────────────────────────────────────────┐"
echo -e "  │  ${GREEN}CLIENT CONNECTION — вставь в приложение:${NC}    │"
echo -e "  │  ${YELLOW}SERVER URL: http://${SERVER_IP}:${API_PORT}${NC}           │"
echo -e "  └─────────────────────────────────────────────┘"
echo ""
echo -e "  ${YELLOW}Для остановки: bash stop.sh${NC}"
echo ""

# Detach — script exits, services keep running in background
exit 0
