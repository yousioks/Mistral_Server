#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/.pids"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

kill_proc() {
    local name=$1
    local pidfile="$PID_DIR/${name}.pid"
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo -e "${YELLOW}[STOP]${NC} Stopping $name (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -9 "$pid" 2>/dev/null || true
            echo -e "${GREEN}[OK]${NC}   $name stopped"
        else
            echo -e "${YELLOW}[WARN]${NC} $name not running"
        fi
        rm -f "$pidfile"
    else
        echo -e "${YELLOW}[WARN]${NC} No PID file for $name"
    fi
}

echo -e "${RED}[MISTRAL]${NC} Stopping all services..."
kill_proc "server"
kill_proc "telegram-bot"
kill_proc "monitors"
echo -e "${GREEN}[OK]${NC}   All services stopped"
