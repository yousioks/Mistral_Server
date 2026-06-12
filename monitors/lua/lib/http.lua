-- MISTRAL Defense - Shared HTTP library for Lua monitors
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")

local M = {}

M.SERVER_URL = os.getenv("MISTRAL_SERVER_URL") or "http://localhost:8080"
M.HOSTNAME = io.popen("hostname"):read("*l") or "localhost"
M.API_KEY = os.getenv("WSS_SECRET_TOKEN") or ""

function M.read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    return data
end

function M.read_cmd(cmd)
    local f = io.popen(cmd, "r")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    return data and data:gsub("%s+$", "")
end

function M.post_json(endpoint, payload)
    local body = json.encode(payload)
    local resp = {}
    local _, code = http.request{
        url = M.SERVER_URL .. endpoint,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = tostring(#body),
            ["X-Monitor-ID"] = "lua-" .. M.HOSTNAME,
            ["X-API-Key"] = M.API_KEY,
        },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(resp),
    }
    if code ~= 200 then
        io.stderr:write("[HTTP] Failed " .. endpoint .. ": HTTP " .. tostring(code) .. "\n")
        return false, code
    end
    return true, 200
end

function M.send_metrics(payload)
    payload.hostname = payload.hostname or M.HOSTNAME
    payload.timestamp = payload.timestamp or os.date("!%Y-%m-%dT%H:%M:%SZ")
    return M.post_json("/api/metrics", payload)
end

function M.send_incident(severity, monitor, type, description, details)
    return M.post_json("/api/incidents", {
        severity = severity,
        monitor = monitor,
        type = type,
        description = description,
        details = details or {},
    })
end

return M
