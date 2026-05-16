#!/usr/bin/env lua
-- MISTRAL Defense - Network Monitor (Lua)
-- Replaces monitor_c_network.py
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")

local SERVER_URL = os.getenv("MISTRAL_SERVER_URL") or "http://localhost:8080"
local INTERVAL = tonumber(os.getenv("NETWORK_CHECK_INTERVAL")) or 8
local HOSTNAME = io.popen("hostname"):read("*l") or "unknown"
local API_KEY = os.getenv("WSS_SECRET_TOKEN") or ""

local PORT_WHITELIST = {22, 80, 443, 5000, 3000, 5432}
local PROCESS_WHITELIST = {"nginx", "node", "postgres", "dockerd", "sshd", "systemd"}

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
            ["X-Monitor-ID"] = "lua-net-" .. HOSTNAME,
            ["X-API-Key"] = API_KEY,
        },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(resp),
    }
    return code == 200
end

function in_list(val, list)
    for _, v in ipairs(list) do if v == val then return true end end
    return false
end

function in_whitelist(cmd)
    local lc = cmd:lower()
    for _, w in ipairs(PROCESS_WHITELIST) do
        if lc:find(w, 1, true) then return true end
    end
    return false
end

-- ── Collectors ──────────────────────────────────────────────────────
function get_tcp_connections()
    local out = read_cmd("ss -tan --processes 2>/dev/null")
    local conns = {}
    local first = true
    for line in out:gmatch("[^\n]+") do
        if first then first = false
        else
            local state, local_, remote, process = line:match("^%S+%s+(%S+)%s+%S+%s+(%S+)%s+(%S+)%s+(.-)$")
            if state then
                table.insert(conns, {state = state, local_ = local_, remote = remote, process = process:gsub("%s+$", "")})
            end
        end
    end
    return conns
end

function get_listening_ports(conns)
    local ports = {}
    local seen = {}
    for _, c in ipairs(conns) do
        if c.state == "LISTEN" then
            local port = c.local_:match(":(%d+)$")
            if port then
                port = tonumber(port)
                if not seen[port] then
                    seen[port] = true
                    table.insert(ports, port)
                end
            end
        end
    end
    return ports
end

function get_unknown_processes()
    local out = read_cmd("ps aux 2>/dev/null")
    local unknown = {}
    local first = true
    for line in out:gmatch("[^\n]+") do
        if first then first = false
        else
            local parts = {}
            for p in line:gmatch("%S+") do table.insert(parts, p) end
            if #parts >= 11 then
                local pid, cpu, mem = parts[2], parts[3], parts[4]
                local cmd = table.concat(parts, " ", 11)
                if not in_whitelist(cmd) then
                    table.insert(unknown, {pid = pid, cpu = cpu, mem = mem, cmd = cmd:sub(1,80)})
                end
            end
        end
    end
    return unknown
end

function get_ddos_indicators(conns)
    local syn_recv, established = 0, 0
    local ip_counts = {}
    for _, c in ipairs(conns) do
        if c.state == "SYN-RECV" then syn_recv = syn_recv + 1 end
        if c.state == "ESTAB" then established = established + 1 end
        local ip = c.remote:match("^([^:]+)")
        if ip and ip ~= "0.0.0.0" then
            ip_counts[ip] = (ip_counts[ip] or 0) + 1
        end
    end
    local top_ips = {}
    for ip, count in pairs(ip_counts) do
        table.insert(top_ips, {ip = ip, count = count})
    end
    table.sort(top_ips, function(a,b) return a.count > b.count end)
    while #top_ips > 5 do table.remove(top_ips) end
    return {syn_recv = syn_recv, established = established, top_ips = top_ips}
end

-- ── Anomaly detection ───────────────────────────────────────────────
function check_anomalies(data)
    local anomalies = {}
    for _, p in ipairs(data.ports) do
        if not in_list(p, PORT_WHITELIST) then
            table.insert(anomalies, {
                severity = "HIGH",
                type = "UNKNOWN_PORT",
                description = "Подозрительный порт LISTEN: " .. p
            })
        end
    end
    if #data.unknown_processes > 0 then
        local cmds = {}
        for i = 1, math.min(3, #data.unknown_processes) do
            table.insert(cmds, data.unknown_processes[i].cmd:sub(1,30))
        end
        table.insert(anomalies, {
            severity = "MEDIUM",
            type = "UNKNOWN_PROCESSES",
            description = "Неизвестные процессы: " .. #data.unknown_processes .. " (первые: " .. table.concat(cmds, ", ") .. ")"
        })
    end
    if data.ddos.syn_recv > 100 then
        table.insert(anomalies, {
            severity = "HIGH",
            type = "DDOS_SYN",
            description = "DDoS: много SYN-RECV: " .. data.ddos.syn_recv
        })
    end
    if data.ddos.established > 3000 then
        table.insert(anomalies, {
            severity = "HIGH",
            type = "DDOS_ESTAB",
            description = "DDoS: много ESTABLISHED: " .. data.ddos.established
        })
    end
    for _, ip_info in ipairs(data.ddos.top_ips) do
        if ip_info.count > 200 then
            table.insert(anomalies, {
                severity = "HIGH",
                type = "DDOS_IP",
                description = "DDoS: IP " .. ip_info.ip .. " имеет " .. ip_info.count .. " соединений"
            })
        end
    end
    return anomalies
end

-- ── Main loop ───────────────────────────────────────────────────────
print("[Monitor C] Network & Process Watcher started (Lua)")
while true do
    local ok, err = pcall(function()
        local conns = get_tcp_connections()
        local ports = get_listening_ports(conns)
        local unknown = get_unknown_processes()
        local ddos = get_ddos_indicators(conns)

        local data = {
            monitor = "network_watcher",
            hostname = HOSTNAME,
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            ports = ports,
            unknown_processes = unknown,
            ddos = ddos,
        }

        local anomalies = check_anomalies(data)
        data.anomalies = anomalies

        local sent = post_json("/api/metrics", data)
        if sent then print("[Monitor C] Sent") else io.stderr:write("[Monitor C] Send failed\n") end

        for _, a in ipairs(anomalies) do
            io.stderr:write("[ALERT] " .. a.description .. "\n")
            post_json("/api/incidents", {
                severity = a.severity,
                monitor = "NetworkMonitor-C",
                type = a.type,
                description = a.description,
                details = data,
            })
        end
    end)
    if not ok then
        io.stderr:write("[Monitor C] Error: " .. tostring(err) .. "\n")
    end
    require("socket").sleep(INTERVAL)
end
