#!/usr/bin/env lua
-- MISTRAL Defense - Integrity Monitor (Lua)
-- Replaces monitor_d_integrity.py
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")

local SERVER_URL = os.getenv("MISTRAL_SERVER_URL") or "http://localhost:8080"
local INTERVAL = tonumber(os.getenv("INTEGRITY_CHECK_INTERVAL")) or 30
local HOSTNAME = io.popen("hostname"):read("*l") or "localhost"
local API_KEY = os.getenv("WSS_SECRET_TOKEN") or ""

local WATCH_PATHS_STR = os.getenv("WATCH_PATHS") or "/root/.ssh/authorized_keys,/etc/hosts"
local DOCKER_COMPOSE_PATH = os.getenv("DOCKER_COMPOSE_PATH") or "/opt/remon/docker-compose.yml"

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
            ["X-Monitor-ID"] = "lua-integ-" .. HOSTNAME,
            ["X-API-Key"] = API_KEY,
        },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(resp),
    }
    return code == 200
end

function sha256_file(path)
    local data = read_cmd("sha256sum \"" .. path .. "\" 2>/dev/null | awk '{print $1}'")
    if data and #data == 64 then return data end
    -- fallback to openssl if sha256sum absent
    data = read_cmd("openssl dgst -sha256 \"" .. path .. "\" 2>/dev/null | awk '{print $NF}'")
    if data and #data == 64 then return data end
    return nil
end

-- ── Baseline management ───────────────────────────────────────────
local baseline = {}

function build_baseline()
    baseline = {}
    for path in WATCH_PATHS_STR:gmatch("[^,]+") do
        path = path:gsub("^%s+", ""):gsub("%s+$", "")
        local f = io.open(path, "rb")
        if f then
            f:close()
            local h = sha256_file(path)
            if h then baseline[path] = h end
        end
    end
end

function check_file(path)
    local f = io.open(path, "rb")
    if not f then return {exists = false, changed = true, hash = nil} end
    f:close()
    local h = sha256_file(path)
    if not h then return {exists = true, changed = false, hash = nil} end
    local old = baseline[path]
    return {exists = true, changed = old ~= nil and old ~= h, hash = h, old_hash = old}
end

function check_docker_images()
    local out = read_cmd("docker images --format '{{.Repository}}:{{.Tag}}|{{.ID}}|{{.CreatedAt}}' 2>/dev/null")
    local images = {}
    for line in out:gmatch("[^\n]+") do
        local parts = {}
        for p in line:gmatch("[^|]+") do table.insert(parts, p) end
        if #parts >= 3 then
            table.insert(images, {name = parts[1], id = parts[2], created = parts[3]})
        end
    end
    return images
end

function check_git_changes(repo_path)
    local out = read_cmd("git -C " .. repo_path .. " status --short 2>/dev/null")
    local changes = {}
    for line in out:gmatch("[^\n]+") do
        if line:match("^%S") then table.insert(changes, line) end
    end
    return changes
end

-- ── Anomaly detection ───────────────────────────────────────────────
function check_anomalies(files, git_changes)
    local anomalies = {}
    for path, info in pairs(files) do
        if info.changed then
            table.insert(anomalies, {
                severity = "CRITICAL",
                type = "FILE_CHANGED",
                description = "Файл изменён: " .. path
            })
        end
        if not info.exists then
            table.insert(anomalies, {
                severity = "CRITICAL",
                type = "FILE_DELETED",
                description = "Файл удалён: " .. path
            })
        end
    end
    if #git_changes > 0 then
        table.insert(anomalies, {
            severity = "HIGH",
            type = "GIT_CHANGES",
            description = "Git изменения: " .. #git_changes .. " файлов"
        })
    end
    return anomalies
end

-- ── Main loop ───────────────────────────────────────────────────────
print("[Monitor D] File Integrity Watcher started (Lua)")
build_baseline()
while true do
    local ok, err = pcall(function()
        local files = {}
        for path in WATCH_PATHS_STR:gmatch("[^,]+") do
            path = path:gsub("^%s+", ""):gsub("%s+$", "")
            files[path] = check_file(path)
        end

        local images = check_docker_images()
        local git_changes = check_git_changes("/opt/remon")

        local data = {
            monitor = "file_integrity_watcher",
            hostname = HOSTNAME,
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            files = files,
            docker_images = images,
            git_changes = git_changes,
        }

        local anomalies = check_anomalies(files, git_changes)
        data.anomalies = anomalies

        local sent = post_json("/api/metrics", data)
        if sent then print("[Monitor D] Sent") else io.stderr:write("[Monitor D] Send failed\n") end

        for _, a in ipairs(anomalies) do
            io.stderr:write("[ALERT] " .. a.description .. "\n")
            post_json("/api/incidents", {
                severity = a.severity,
                monitor = "IntegrityMonitor-D",
                type = a.type,
                description = a.description,
                details = data,
            })
        end

        -- Update baseline after anomalies so next check is against current state
        if #anomalies > 0 then
            build_baseline()
        end
    end)
    if not ok then
        io.stderr:write("[Monitor D] Error: " .. tostring(err) .. "\n")
    end
    require("socket").sleep(INTERVAL)
end
