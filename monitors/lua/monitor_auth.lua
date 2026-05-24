#!/usr/bin/env lua
-- MISTRAL Defense - Auth Monitor (Lua)
-- Replaces monitor_b_auth.py
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")

local SERVER_URL = os.getenv("MISTRAL_SERVER_URL") or "http://localhost:8080"
local INTERVAL = tonumber(os.getenv("AUTH_CHECK_INTERVAL")) or 10
local MAX_FAILED = tonumber(os.getenv("MAX_FAILED_LOGINS")) or 5
local HOSTNAME = io.popen("hostname"):read("*l") or "unknown"
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
            local ip = line:match("from%s+(%S+)") or "unknown"            table.insert(failed, {ip = ip, line = line:sub(-120)})
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
while true do
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
        if sent then print("[Monitor B] Sent") else io.stderr:write("[Monitor B] Send failed\n") end

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
    require("socket").sleep(INTERVAL)
end
