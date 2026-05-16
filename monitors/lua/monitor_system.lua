#!/usr/bin/env lua
-- MISTRAL Defense - System Monitor (Lua)
-- Replaces monitor_a_system.py
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")

local SERVER_URL = os.getenv("MISTRAL_SERVER_URL") or "http://localhost:8080"
local INTERVAL = tonumber(os.getenv("MONITOR_INTERVAL")) or 5
local HOSTNAME = io.popen("hostname"):read("*l") or "unknown"
local API_KEY = os.getenv("WSS_SECRET_TOKEN") or ""

-- ── Helpers ─────────────────────────────────────────────────────────
function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local d = f:read("*a")
    f:close()
    return d
end

function read_cmd(cmd)
    local f = io.popen(cmd, "r")
    if not f then return nil end
    local d = f:read("*a")
    f:close()
    return d and d:gsub("%s+$", "")
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
            ["X-Monitor-ID"] = "lua-system-" .. HOSTNAME,
            ["X-API-Key"] = API_KEY,
        },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(resp),
    }
    return code == 200
end

-- ── Metric collectors ───────────────────────────────────────────────
local prev_cpu = nil

function get_cpu()
    local data = read_file("/proc/stat")
    if not data then return nil end
    local user, nice, system, idle = data:match("cpu%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)")
    if not user then return nil end
    local total = tonumber(user) + tonumber(nice) + tonumber(system) + tonumber(idle)
    local busy  = tonumber(user) + tonumber(nice) + tonumber(system)
    if not prev_cpu then
        prev_cpu = {total = total, busy = busy}
        return nil
    end
    local dtotal = total - prev_cpu.total
    local dbusy  = busy  - prev_cpu.busy
    prev_cpu = {total = total, busy = busy}
    if dtotal <= 0 then return nil end
    return math.floor((dbusy / dtotal) * 1000) / 10
end

function get_ram()
    local data = read_file("/proc/meminfo")
    if not data then return nil end
    local total = data:match("MemTotal:%s+(%d+)")
    local avail = data:match("MemAvailable:%s+(%d+)")
    if not total or not avail then return nil end
    return {
        percent = math.floor(((tonumber(total) - tonumber(avail)) / tonumber(total)) * 1000) / 10,
        used_mb = math.floor((tonumber(total) - tonumber(avail)) / 1024),
        total_mb = math.floor(tonumber(total) / 1024),
    }
end

function get_disk()
    local data = read_cmd("df / | tail -1 | awk '{print $2\" \"$3\" \"$5}'")
    if not data then return nil end
    local total, used, pct = data:match("(%d+)%s+(%d+)%s+(%d+)")
    if not total then return nil end
    return {
        percent = tonumber(pct),
        used_gb = math.floor(tonumber(used) / 1024 / 1024 * 10) / 10,
        total_gb = math.floor(tonumber(total) / 1024 / 1024 * 10) / 10,
    }
end

function get_temp()
    local paths = {
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/hwmon/hwmon0/temp1_input",
    }
    for _, p in ipairs(paths) do
        local d = read_file(p)
        if d then return math.floor(tonumber(d) / 1000) end
    end
    return nil
end

function get_connections()
    local data = read_cmd("ss -t | wc -l")
    return tonumber(data) or 0
end

function get_docker()
    local healthy = false
    local containers = {}
    local data = read_cmd("docker ps --format '{{.ID}}|{{.Image}}|{{.Status}}|{{.Names}}' 2>/dev/null")
    if data then
        healthy = true
        for line in data:gmatch("[^\n]+") do
            local parts = {}
            for p in line:gmatch("[^|]+") do table.insert(parts, p) end
            if #parts >= 4 then
                table.insert(containers, {id=parts[1], image=parts[2], status=parts[3], name=parts[4]})
            end
        end
    end
    return {healthy = healthy, containers = containers, count = #containers}
end

function get_systemd()
    local failed = {}
    local data = read_cmd("systemctl --failed --plain --no-legend 2>/dev/null")
    if data then
        for line in data:gmatch("[^\n]+") do
            local unit = line:match("^%s*(%S+)")
            if unit then table.insert(failed, unit) end
        end
    end
    return {failed_units = failed, failed_count = #failed}
end

function get_nginx()
    local data = read_cmd("systemctl is-active nginx 2>/dev/null")
    return {active = data == "active"}
end

-- ── Anomaly detection ───────────────────────────────────────────────
local CPU_THRESHOLD = tonumber(os.getenv("CPU_THRESHOLD")) or 85
local RAM_THRESHOLD = tonumber(os.getenv("RAM_THRESHOLD")) or 90
local DISK_THRESHOLD = tonumber(os.getenv("DISK_THRESHOLD")) or 90
local CONN_THRESHOLD = tonumber(os.getenv("CONN_THRESHOLD")) or 1000

function check_anomalies(metrics)
    local a = {}
    if metrics.cpu and metrics.cpu > CPU_THRESHOLD then
        table.insert(a, {type="HIGH_CPU", value=metrics.cpu, severity="HIGH", description="CPU высокая загрузка: "..metrics.cpu.."%"})
    end
    if metrics.ram and metrics.ram.percent > RAM_THRESHOLD then
        table.insert(a, {type="HIGH_RAM", value=metrics.ram.percent, severity="HIGH", description="RAM высокая загрузка: "..metrics.ram.percent.."%"})
    end
    if metrics.disk and metrics.disk.percent > DISK_THRESHOLD then
        table.insert(a, {type="HIGH_DISK", value=metrics.disk.percent, severity="HIGH", description="Диск заполнен на "..metrics.disk.percent.."%"})
    end
    if metrics.connections and metrics.connections > CONN_THRESHOLD then
        table.insert(a, {type="HIGH_CONNS", value=metrics.connections, severity="HIGH", description="Много соединений: "..metrics.connections})
    end
    if metrics.systemd and metrics.systemd.failed_count > 0 then
        table.insert(a, {type="SYSTEMD_FAILED", value=metrics.systemd.failed_count, severity="CRITICAL", description="Failed systemd: "..table.concat(metrics.systemd.failed_units, ", ")})
    end
    if metrics.nginx and not metrics.nginx.active then
        table.insert(a, {type="NGINX_DOWN", severity="CRITICAL", description="nginx неактивен!"})
    end
    if metrics.docker and not metrics.docker.healthy then
        table.insert(a, {type="DOCKER_DOWN", severity="HIGH", description="Docker daemon недоступен"})
    end
    return a
end

-- ── Main loop ───────────────────────────────────────────────────────
print("[Monitor A] System Anomaly Watcher started (Lua)")
while true do
    local ok, err = pcall(function()
        local cpu = get_cpu()
        local ram = get_ram()
        local disk = get_disk()
        local temp = get_temp()
        local conns = get_connections()
        local docker = get_docker()
        local systemd = get_systemd()
        local nginx = get_nginx()

        local metrics = {
            monitor = "system_anomaly_watcher",
            hostname = HOSTNAME,
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            cpu = cpu,
            ram = ram,
            disk = disk,
            temp = temp,
            connections = conns,
            docker = docker,
            systemd = systemd,
            nginx = nginx,
        }

        local anomalies = check_anomalies(metrics)
        metrics.anomalies = anomalies

        local sent = post_json("/api/metrics", metrics)
        if sent then
            print("[Monitor A] Metrics sent")
        else
            io.stderr:write("[Monitor A] Failed to send metrics\n")
        end

        for _, anom in ipairs(anomalies) do
            io.stderr:write("[ALERT] " .. anom.description .. "\n")
            post_json("/api/incidents", {
                severity = anom.severity,
                monitor = "SystemMonitor-A",
                type = anom.type,
                description = anom.description,
                details = metrics,
            })
        end
    end)
    if not ok then
        io.stderr:write("[Monitor A] Error: " .. tostring(err) .. "\n")
    end
    require("socket").sleep(INTERVAL)
end
