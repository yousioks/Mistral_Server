#!/usr/bin/env lua
-- MISTRAL Defense - Security Tools Installer & Auditor Monitor (Lua)
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")

local SERVER_URL = os.getenv("MISTRAL_SERVER_URL") or "http://localhost:8080"
local INTERVAL = tonumber(os.getenv("SECTOOLS_CHECK_INTERVAL")) or 10
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

function is_installed(cmd)
    local res = os.execute("command -v " .. cmd .. " >/dev/null 2>&1")
    return res == 0 or res == true
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
            ["X-Monitor-ID"] = "lua-sectools-" .. HOSTNAME,
            ["X-API-Key"] = API_KEY,
        },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(resp),
    }
    return code == 200
end

-- ── Dependency Installer ─────────────────────────────────────────────
function check_and_install_dependencies()
    local tools = {
        { name = "ufw", check_cmd = "ufw" },
        { name = "fail2ban", check_cmd = "fail2ban-client" },
        { name = "trivy", check_cmd = "trivy" },
        { name = "semgrep", check_cmd = "semgrep" }
    }

    for _, t in ipairs(tools) do
        if not is_installed(t.check_cmd) then
            print("[SecTools] Missing tool: " .. t.name .. ". Running installer...")
            post_json("/api/logs", {
                type = "server",
                level = "info",
                message = "[SecTools Monitor] Обнаружено отсутствие утилиты '" .. t.name .. "'. Запуск автоматической установки..."
            })

            local cmd = ""
            if t.name == "ufw" then
                cmd = "sudo apt-get update -y && sudo apt-get install -y ufw"
            elseif t.name == "fail2ban" then
                cmd = "sudo apt-get update -y && sudo apt-get install -y fail2ban && sudo systemctl enable --now fail2ban"
            elseif t.name == "trivy" then
                cmd = "sudo apt-get update -y && sudo apt-get install -y wget apt-transport-https gnupg lsb-release && " ..
                      "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null && " ..
                      "echo \"deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main\" | sudo tee /etc/apt/sources.list.d/trivy.list > /dev/null && " ..
                      "sudo apt-get update -y && sudo apt-get install -y trivy"
            elseif t.name == "semgrep" then
                cmd = "sudo apt-get update -y && sudo apt-get install -y python3-pip python3-venv && " ..
                      "python3 -m pip install semgrep --break-system-packages"
            end

            local ok = os.execute(cmd)
            if ok == 0 or ok == true then
                print("[SecTools] Tool '" .. t.name .. "' installed successfully!")
                post_json("/api/logs", {
                    type = "server",
                    level = "info",
                    message = "[SecTools Monitor] Утилита '" .. t.name .. "' успешно установлена."
                })
            else
                print("[SecTools] Failed to install '" .. t.name .. "'.")
                post_json("/api/logs", {
                    type = "server",
                    level = "error",
                    message = "[SecTools Monitor] Не удалось установить утилиту '" .. t.name .. "' автоматически."
                })
            end
        end
    end
end

-- ── Status Gathering ──────────────────────────────────────────────────
function get_ufw_info()
    local info = { installed = false, status = "inactive", rules = {} }
    if is_installed("ufw") then
        info.installed = true
        local out = read_cmd("sudo ufw status")
        if out:match("Status: active") then
            info.status = "active"
            for line in out:gmatch("[^\n]+") do
                if not line:match("Status:") and not line:match("To%s+Action") and not line:match("%-%-%s+%-%-%s+") and #line > 0 then
                    table.insert(info.rules, (line:gsub("^%s+", ""):gsub("%s+$", "")))
                end
            end
        end
    end
    return info
end

function get_fail2ban_info()
    local info = { installed = false, status = "inactive", banned_ips = {} }
    if is_installed("fail2ban-client") then
        info.installed = true
        local ping = read_cmd("sudo fail2ban-client ping 2>/dev/null")
        if ping:match("Server replied: pong") then
            info.status = "active"
            local out = read_cmd("sudo fail2ban-client status sshd 2>/dev/null")
            local ip_list = out:match("Banned IP list:%s*(.*)")
            if ip_list then
                for ip in ip_list:gmatch("%S+") do
                    table.insert(info.banned_ips, ip)
                end
            end
        end
    end
    return info
end

function get_trivy_info()
    local info = { installed = false, version = "" }
    if is_installed("trivy") then
        info.installed = true
        local out = read_cmd("trivy --version 2>/dev/null | head -n 1")
        info.version = out or "installed"
    end
    return info
end

function get_semgrep_info()
    local info = { installed = false, version = "" }
    if is_installed("semgrep") then
        info.installed = true
        local out = read_cmd("semgrep --version 2>/dev/null")
        info.version = out or "installed"
    end
    return info
end

-- ── Command Processing ───────────────────────────────────────────────
function post_command_result(command_id, success, results, err)
    local payload = {
        commandId = command_id,
        success = success,
        results = results,
        error = err
    }
    post_json("/api/monitors/command-results", payload)
end

function process_scan_command(cmd_data)
    local command_id = cmd_data.id
    local cmd_type = cmd_data.type
    local target = cmd_data.target or "."
    target = target:gsub("\"", ""):gsub("'", "") -- sanitize target path

    print("[SecTools] Received scan command: " .. cmd_type .. " on target: " .. target)
    post_json("/api/logs", {
        type = "server",
        level = "info",
        message = "[SecTools Monitor] Запуск фонового сканирования '" .. cmd_type .. "' на цели: " .. target
    })

    if cmd_type == "trivy_scan" then
        if not is_installed("trivy") then
            post_command_result(command_id, false, nil, "Trivy is not installed on this monitor agent.")
            return
        end
        local outfile = "/tmp/trivy-scan-" .. command_id .. ".json"
        local sys_cmd = "trivy fs \"" .. target .. "\" --format json -o " .. outfile .. " --quiet"
        local res = os.execute(sys_cmd)
        
        local f = io.open(outfile, "r")
        if f then
            local raw = f:read("*a")
            f:close()
            os.remove(outfile)

            local ok, parsed = pcall(json.decode, raw)
            if ok then
                local findings = {}
                if parsed.Results then
                    for _, r_item in ipairs(parsed.Results) do
                        if r_item.Vulnerabilities then
                            for _, v in ipairs(r_item.Vulnerabilities) do
                                table.insert(findings, {
                                    target = r_item.Target,
                                    pkg = v.PkgName,
                                    vulnId = v.VulnerabilityID,
                                    severity = v.Severity,
                                    title = v.Title,
                                    fixedVersion = v.FixedVersion
                                })
                            end
                        end
                    end
                end
                post_command_result(command_id, true, { findings = findings })
            else
                post_command_result(command_id, false, nil, "Failed to parse Trivy output JSON")
            end
        else
            post_command_result(command_id, false, nil, "Trivy scan failed or did not produce output file")
        end

    elseif cmd_type == "semgrep_scan" then
        if not is_installed("semgrep") then
            post_command_result(command_id, false, nil, "Semgrep is not installed on this monitor agent.")
            return
        end
        local outfile = "/tmp/semgrep-scan-" .. command_id .. ".json"
        local sys_cmd = "semgrep --config=p/security-audit \"" .. target .. "\" --json -o " .. outfile .. " --quiet"
        local res = os.execute(sys_cmd)

        local f = io.open(outfile, "r")
        if f then
            local raw = f:read("*a")
            f:close()
            os.remove(outfile)

            local ok, parsed = pcall(json.decode, raw)
            if ok then
                local findings = {}
                if parsed.results then
                    for _, r_item in ipairs(parsed.results) do
                        local start_line = r_item.start and r_item.start.line or 0
                        local msg = r_item.extra and r_item.extra.message or ""
                        local sev = r_item.extra and r_item.extra.metadata and r_item.extra.metadata.severity or "MEDIUM"
                        table.insert(findings, {
                            path = r_item.path,
                            line = start_line,
                            message = msg,
                            severity = sev,
                            rule = r_item.check_id
                        })
                    end
                end
                post_command_result(command_id, true, { findings = findings })
            else
                post_command_result(command_id, false, nil, "Failed to parse Semgrep output JSON")
            end
        else
            post_command_result(command_id, false, nil, "Semgrep scan failed or did not produce output file")
        end
    else
        post_command_result(command_id, false, nil, "Unsupported command type: " .. cmd_type)
    end
end

function poll_commands()
    local resp = {}
    local _, code = http.request{
        url = SERVER_URL .. "/api/monitors/commands",
        method = "GET",
        headers = {
            ["X-Monitor-ID"] = "lua-sectools-" .. HOSTNAME,
            ["X-API-Key"] = API_KEY,
        },
        sink = ltn12.sink.table(resp),
    }

    if code == 200 then
        local response_body = table.concat(resp)
        if #response_body > 0 and response_body ~= "null" then
            local ok, cmd_data = pcall(json.decode, response_body)
            if ok and cmd_data and cmd_data.id then
                process_scan_command(cmd_data)
            end
        end
    end
end

-- ── Main Loop ───────────────────────────────────────────────────────
print("[SecTools] MISTRAL Security Tools Monitor & Installer started (Lua)")
post_json("/api/logs", {
    type = "server",
    level = "info",
    message = "[SecTools Monitor] Служба аудита средств безопасности успешно запущена."
})

-- Run initial check & install dependencies at startup
pcall(check_and_install_dependencies)

while true do
    local ok, err = pcall(function()
        -- 1. Gather status info
        local ufw_info = get_ufw_info()
        local fail2ban_info = get_fail2ban_info()
        local trivy_info = get_trivy_info()
        local semgrep_info = get_semgrep_info()

        local payload = {
            monitor = "sec_tools_monitor",
            hostname = HOSTNAME,
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            ufw = ufw_info,
            fail2ban = fail2ban_info,
            trivy = trivy_info,
            semgrep = semgrep_info
        }

        -- 2. Send metrics
        post_json("/api/metrics", payload)

        -- 3. Poll pending commands
        poll_commands()
    end)

    if not ok then
        io.stderr:write("[SecTools] Error in loop: " .. tostring(err) .. "\n")
    end
    require("socket").sleep(INTERVAL)
end
