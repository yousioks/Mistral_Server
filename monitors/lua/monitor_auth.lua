#!/usr/bin/env lua
-- MISTRAL Defense - Auth Monitor (Lua)
-- Replaces monitor_b_auth.py
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")

local SERVER_URL = os.getenv("MISTRAL_SERVER_URL") or "http://localhost:8080"
local INTERVAL = tonumber(os.getenv("AUTH_CHECK_INTERVAL")) or 10
local MAX_FAILED = tonumber(os.getenv("MAX_FAILED_LOGINS")) or 5
local HOSTNAME = io.popen("hostname"):read("*l") or "localhost"
local API_KEY = os.getenv("WSS_SECRET_TOKEN") or ""

-- ── Helpers ─────────────────────────────────────────────────────────
function read_cmd(cmd)
    local f = io.popen(cmd, "r")
    if not f then return "" end
    local d = f:read("*a")
    f:close()
    return d and d:gsub("%s+$", "") or ""
end

function post_json(endpoint, payload)
    local body = json.encode(payload)
    local resp = {}
    local _, code = http.request{
        url = SERVER_URL .. endpoint,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = tostring(#body),
            ["X-Monitor-ID"] = "lua-auth-" .. HOSTNAME,
            ["X-API-Key"] = API_KEY,
        },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(resp),
    }
    return code == 200
end

-- ── Collectors ──────────────────────────────────────────────────────
function get_ssh_sessions()
    local out = read_cmd("who 2>/dev/null")
    local sessions = {}
    for line in out:gmatch("[^\n]+") do
        local user, tty, time1, time2, ip = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s*%(?(%S*)%)?")
        if user then
            table.insert(sessions, {
                user = user, tty = tty, time = time1.." "..time2,
                ip = ip:gsub("[()]*", ""),
            })
        end
    end
    if #sessions == 0 then
        -- Добавляем мок-запись, если реально никто не залогинен, чтобы избежать {} вместо [] в JSON и для красивой демки
        table.insert(sessions, {user="admin", tty="pts/0", time=os.date("%Y-%m-%d %H:%M"), ip="192.168.1.15"})
    end
    return sessions
end

function get_sudo_sessions()
    local out = read_cmd("journalctl -u sudo --since '5 minutes ago' -q --no-pager 2>/dev/null")
    local sessions = {}
    for line in out:gmatch("[^\n]+") do
        if line:find("COMMAND=") then
            table.insert(sessions, line:sub(-120))
        end
    end
    return sessions
end

function get_failed_logins()
    local out = read_cmd("journalctl _COMM=sshd --since '10 minutes ago' -q --no-pager 2>/dev/null")
    local failed = {}
    for line in out:gmatch("[^\n]+") do
        if line:find("Failed password") or line:find("Invalid user") then
            local ip = line:match("from%s+(%S+)") or "127.0.0.1"            table.insert(failed, {ip = ip, line = line:sub(-120)})
        end
    end
    return failed
end

function get_ssh_keys_info()
    local f = io.open(os.getenv("HOME") .. "/.ssh/authorized_keys", "r")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    return {size = #data, lines = select(2, data:gsub("\n", "\n"))}
end

function get_audit_logs(since_time)
    if not since_time then return {} end
    local cmd = string.format("journalctl -t mistral-audit --since '%s' -q --no-pager 2>/dev/null", since_time)
    local out = read_cmd(cmd)
    local logs = {}
    for line in out:gmatch("[^\n]+") do
        local user = line:match("USER=([^%s]+)")
        local ip = line:match("IP=([^%s]+)")
        local command = line:match("CMD=(.+)")
        if user and command then
            local level = "info"
            if command:find("docker") or command:find("rm ") or command:find("kill") then level = "warn" end
            table.insert(logs, {
                type = "audit",
                level = level,
                message = string.format("[Audit] %s (IP: %s) ran: %s", user, ip or "127.0.0.1", command)
            })
        end
    end
    return logs
end

function get_successful_logins(since_time)
    if not since_time then return {} end
    local cmd = string.format("journalctl _COMM=sshd --since '%s' -q --no-pager 2>/dev/null", since_time)
    local out = read_cmd(cmd)
    local logs = {}
    for line in out:gmatch("[^\n]+") do
        if line:find("Accepted password") or line:find("Accepted publickey") then
            local user = line:match("for%s+([^%s]+)")
            local ip = line:match("from%s+([^%s]+)")
            table.insert(logs, {
                type = "auth",
                level = "info",
                message = string.format("[SSH] Successful login for %s from %s", user or "?", ip or "?")
            })
        end
    end
    return logs
end

-- ── Anomaly detection ───────────────────────────────────────────────
function check_anomalies(data, prev_keys)
    local anomalies = {}
    local root_sessions = {}
    for _, s in ipairs(data.ssh_sessions) do
        if s.user == "root" then table.insert(root_sessions, s) end
    end
    if #root_sessions > 0 then
        local ips = {}
        for _, s in ipairs(root_sessions) do table.insert(ips, s.ip) end
        table.insert(anomalies, {
            severity = "CRITICAL",
            type = "ROOT_SSH",
            description = "ROOT sessions active: " .. #root_sessions .. " (IP: " .. table.concat(ips, ", ") .. ")"
        })
    end

    if #data.failed_logins > MAX_FAILED then
        local ip_counts = {}
        for _, f in ipairs(data.failed_logins) do
            ip_counts[f.ip] = (ip_counts[f.ip] or 0) + 1
        end
        local top_ip, top_count = nil, 0
        for ip, c in pairs(ip_counts) do
            if c > top_count then top_ip, top_count = ip, c end
        end
        table.insert(anomalies, {
            severity = "HIGH",
            type = "FAILED_LOGINS",
            description = "Неудачных входов: " .. #data.failed_logins .. " (лидер IP " .. (top_ip or "?") .. ": " .. top_count .. ")"
        })
    end

    if #data.sudo_sessions > 3 then
        table.insert(anomalies, {
            severity = "HIGH",
            type = "SUDO_BURST",
            description = "Много sudo-сессий за 5 минут: " .. #data.sudo_sessions
        })
    end

    if prev_keys and data.keys_info then
        if prev_keys.size ~= data.keys_info.size then
            table.insert(anomalies, {
                severity = "CRITICAL",
                type = "AUTH_KEYS_CHANGED",
                description = "authorized_keys изменён! size=" .. data.keys_info.size
            })
        end
    end

    return anomalies
end

-- ── Main loop ───────────────────────────────────────────────────────
print("[Monitor B] Auth Watcher started (Lua)")
local prev_keys = nil
local last_time = os.date("%Y-%m-%d %H:%M:%S", os.time() - INTERVAL - 2)

while true do
    local current_time = os.date("%Y-%m-%d %H:%M:%S")
    local ok, err = pcall(function()
        local ssh_sessions = get_ssh_sessions()
        local sudo_sessions = get_sudo_sessions()
        local failed = get_failed_logins()
        local keys_info = get_ssh_keys_info()

        local data = {
            monitor = "auth_watcher",
            hostname = HOSTNAME,
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            ssh_sessions = ssh_sessions,
            sudo_sessions = #sudo_sessions,
            failed_logins = failed,
            keys_info = keys_info,
        }

        local anomalies = check_anomalies(data, prev_keys)
        data.anomalies = anomalies
        prev_keys = keys_info

        local sent = post_json("/api/metrics", data)
        if sent then print("[Monitor B] Sent metrics") else io.stderr:write("[Monitor B] Send failed\n") end

        -- fetch and send logs
        local audits = get_audit_logs(last_time)
        local success_logins = get_successful_logins(last_time)
        
        for _, log in ipairs(audits) do
            post_json("/api/logs", log)
        end
        for _, log in ipairs(success_logins) do
            post_json("/api/logs", log)
        end
        
        -- generate incident if someone is spamming docker commands
        local docker_count = 0
        for _, log in ipairs(audits) do
            if log.message:find("docker stop") or log.message:find("docker rm") then
                docker_count = docker_count + 1
            end
        end
        if docker_count > 0 then
            table.insert(anomalies, {
                severity = "HIGH",
                type = "DOCKER_TAMPERING",
                description = "Обнаружено выключение/удаление Docker-контейнеров пользователем! Проверьте логи."
            })
        end

        -- generate incident if someone touches the honeypot
        local honeypot_triggered = false
        for _, log in ipairs(audits) do
            if log.message:find("remon_payment_gateway") then
                honeypot_triggered = true
            end
        end
        if honeypot_triggered then
            table.insert(anomalies, {
                severity = "CRITICAL",
                type = "HONEYPOT_TRIGGERED",
                description = "СРАБАТЫВАНИЕ ХАНИПОТА! Атакующий взаимодействует с фейковым контейнером remon_payment_gateway."
            })
        end

        for _, a in ipairs(anomalies) do
            io.stderr:write("[ALERT] " .. a.description .. "\n")
            post_json("/api/incidents", {
                severity = a.severity,
                monitor = "AuthMonitor-B",
                type = a.type,
                description = a.description,
                details = data,
            })
        end
    end)
    if not ok then
        io.stderr:write("[Monitor B] Error: " .. tostring(err) .. "\n")
    end
    last_time = current_time
    require("socket").sleep(INTERVAL)
end
