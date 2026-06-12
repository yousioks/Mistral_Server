#!/usr/bin/env bash
# MISTRAL Defense - Lua Monitor Launcher
# Starts all Lua monitors in background, logs to files, supports graceful stop

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUA_DIR="${SCRIPT_DIR}/lua"
LOG_DIR="${SCRIPT_DIR}/../logs"
PID_DIR="${SCRIPT_DIR}/pids"

mkdir -p "$LOG_DIR" "$PID_DIR"

MONITORS=(
    "monitor_system.lua"
    "monitor_auth.lua"
    "monitor_network.lua"
    "monitor_integrity.lua"
    "monitor_sec_tools.lua"
)

start_all() {
    echo "[Launcher] Starting MISTRAL Lua monitors..."
    for script in "${MONITORS[@]}"; do
        local name="${script%.lua}"
        local logfile="${LOG_DIR}/${name}.log"
        local pidfile="${PID_DIR}/${name}.pid"

        if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            echo "[Launcher] ${name} already running (PID $(cat "$pidfile"))"
            continue
        fi

        nohup lua "${LUA_DIR}/${script}" >> "$logfile" 2>&1 &
        local pid=$!
        echo $pid > "$pidfile"
        echo "[Launcher] ${name} started (PID ${pid}) -> ${logfile}"
    done
    echo "[Launcher] All monitors started. Use '$0 stop' to stop."
}

stop_all() {
    echo "[Launcher] Stopping MISTRAL Lua monitors..."
    for script in "${MONITORS[@]}"; do
        local name="${script%.lua}"
        local pidfile="${PID_DIR}/${name}.pid"
        if [[ -f "$pidfile" ]]; then
            local pid=$(cat "$pidfile")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                sleep 1
                if kill -0 "$pid" 2>/dev/null; then
                    kill -9 "$pid" 2>/dev/null || true
                fi
                echo "[Launcher] ${name} stopped"
            else
                echo "[Launcher] ${name} not running"
            fi
            rm -f "$pidfile"
        fi
    done
    echo "[Launcher] All monitors stopped."
}

status_all() {
    echo "[Launcher] Monitor status:"
    for script in "${MONITORS[@]}"; do
        local name="${script%.lua}"
        local pidfile="${PID_DIR}/${name}.pid"
        if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            echo "  ${name}: RUNNING (PID $(cat "$pidfile"))"
        else
            echo "  ${name}: STOPPED"
        fi
    done
}

case "${1:-start}" in
    start) start_all ;;
    stop) stop_all ;;
    restart) stop_all; sleep 1; start_all ;;
    status) status_all ;;
    *) echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
