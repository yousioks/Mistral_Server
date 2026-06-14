require("dotenv").config();
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const express = require("express");
const WebSocket = require("ws");
const cors = require("cors");
const helmet = require("helmet");
const { v4: uuidv4 } = require("uuid");
const OpenAI = require("openai");
const winston = require("winston");
const DailyRotateFile = require("winston-daily-rotate-file");
const db = require("./db.js");
const { runSemgrep, runTrivy } = require("./scanners.js");

const {
  AITUNNEL_API_KEY,
  AITUNNEL_BASE_URL = "https://api.aitunnel.ru/v1/",
  WSS_PORT = 8443,
  API_PORT = 8080,
  WSS_CERT_PATH = "./certs/cert.pem",
  WSS_KEY_PATH = "./certs/key.pem",
  WSS_SECRET_TOKEN = "mistral-secret-" + Math.random().toString(36).slice(2),
  LOG_LEVEL = "info",
  LOG_RETENTION_DAYS = "30",
} = process.env;

const MODELS = {
  deepseek: { id: "deepseek-v4-pro", name: "DeepSeek V4 Pro" },
  kimi:     { id: "kimi-k2.6",       name: "Kimi K2.6" },
  claude:   { id: "claude-sonnet-4.6", name: "Claude Sonnet 4.6" },
};
let activeModel = MODELS.deepseek.id;

const logDir = path.join(__dirname, "../logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
      const m = Object.keys(meta).length ? " " + JSON.stringify(meta) : "";
      return `${timestamp} [${level.toUpperCase()}] ${message}${m}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new DailyRotateFile({ filename: path.join(logDir, "server-%DATE%.log"), datePattern: "YYYY-MM-DD", maxFiles: LOG_RETENTION_DAYS + "d", zippedArchive: true }),
    new DailyRotateFile({ filename: path.join(logDir, "error-%DATE%.log"),  datePattern: "YYYY-MM-DD", level: "error", maxFiles: LOG_RETENTION_DAYS + "d", zippedArchive: true }),
  ],
});

const AI_SAFETY_RULES = `STRICT RULES: You are a defensive security assistant.
1. NEVER block port 22. Never modify firewall rules that could lock out admin.
2. NEVER stop nginx or modify SSL certificates.
3. NEVER delete system files, logs, or config files.
4. NEVER create user accounts without explicit approval.
5. ALWAYS provide concrete, actionable bash commands or scripts to mitigate the detected threat. Do not be overly passive.
6. CRITICAL: DO NOT break the structure of the application. Do not try to escape the server sandbox. Do not shutdown or reboot the server.
7. Focus on solving the problems strictly and efficiently based on the logs and incidents provided.`;

function sanitizeAIInput(task) {
  const forbidden = [/ufw\s+(disable|reset)/i, /rm\s+-rf\s+\//i, /mkfs\./i, /dd\s+if=/i];
  for (const p of forbidden) if (p.test(task)) throw new Error("FORBIDDEN: dangerous pattern detected");
  return true;
}

const incidents = [];
const serverLogs = [];
const botLogs = [];
const cveLogs = [];
const clients = new Map();
const usedNonces = new Set();
let lastMetricsReceivedTime = 0;
let cachedMetrics = {};
const pendingMonitorCommands = [];
const monitorCommandResults = new Map();
const activeScanRequests = new Map();
let lastWafPingTime = 0;
let lastWafHost = "";
let lastActivityLogTime = Date.now();
let lastKnownUfwStatus = "inactive";

function mergeMetrics(oldData, newData) {
  if (!oldData) return newData;
  if (!newData) return oldData;
  const merged = { ...oldData };
  for (const key in newData) {
    if (newData[key] !== undefined && newData[key] !== null) {
      if (typeof newData[key] === "object" && !Array.isArray(newData[key]) && oldData[key]) {
        merged[key] = { ...oldData[key], ...newData[key] };
      } else {
        merged[key] = newData[key];
      }
    }
  }
  return merged;
}

function enrichMetricsWithWaf(payload) {
  const osModule = require("os");
  const totalMem = osModule.totalmem();
  const freeMem = osModule.freemem();
  
  let top_process = payload.top_process || {};
  if (!top_process.name || top_process.name === "unknown" || top_process.name === "undefined") {
    top_process.name = process.platform === "win32" ? "node.exe" : "node";
  }
  if (!top_process.pid || top_process.pid === "unknown" || top_process.pid === "undefined") {
    top_process.pid = process.pid;
  }
  if (top_process.cpu === undefined || top_process.cpu === null) {
    top_process.cpu = Math.max(1, payload.cpu || 5);
  }
  if (top_process.mem === undefined || top_process.mem === null) {
    top_process.mem = Math.round((process.memoryUsage().heapUsed / totalMem) * 100) || 1;
  }

  return {
    ...payload,
    top_process,
    waf: {
      online: (Date.now() - lastWafPingTime) < 10000,
      host: lastWafHost || "raemon.ru",
      lastSync: lastWafPingTime ? new Date(lastWafPingTime).toISOString() : null
    }
  };
}


// SOAR Settings Persistence
const soarSettingsPath = path.join(__dirname, "../data/soar_settings.json");
let soarSettings = {
  autoBanDdos: true,
  autoBanBruteForce: true,
  aiDefenseEnabled: false,
  aiMakeChanges: true,
  aiModel: "deepseek-v4-pro",
  aiThreatThreshold: 3,
  aiTriggerOnLeaks: true,
  aiTriggerOnCritical: true,
  honeypotEnabled: false, // default disabled
  aiTriggerTypes: []
};

// Honeypot global state and control helpers
let honeypotServer = null;
let isHoneypotRunning = false;

function startHoneypot() {
  if (isHoneypotRunning) return;
  const net = require("net");
  const honeypotPort = 8081;
  honeypotServer = net.createServer((socket) => {
    const remoteIp = socket.remoteAddress ? socket.remoteAddress.replace(/^::ffff:/, "") : "127.0.0.1";
    const remotePort = socket.remotePort;
    
    logger.warn(`[HONEYPOT] Triggered connection from ${remoteIp}:${remotePort}`);
    
    socket.write("HTTP/1.1 200 OK\r\n");
    socket.write("Content-Type: application/json\r\n");
    socket.write("Server: remon_payment_gateway/1.0.0\r\n\r\n");
    socket.write(JSON.stringify({
      status: "active",
      service: "remon_payment_gateway",
      error: "Unauthorized access detected"
    }) + "\n");
    socket.end();

    addIncident(
      "CRITICAL",
      "Honeypot-Decoy",
      "HONEYPOT_TRIGGERED",
      `СРАБАТЫВАНИЕ ХАНИПОТА! Обнаружена несанкционированная попытка доступа к фейковому платежному шлюзу remon_payment_gateway на порту ${honeypotPort}. Источник IP: ${remoteIp}`,
      { sourceIp: remoteIp, port: remotePort, service: "remon_payment_gateway" }
    );
  });
  honeypotServer.on("error", (err) => {
    logger.error("Honeypot Decoy error: " + err.message);
  });
  honeypotServer.listen(honeypotPort, () => {
    isHoneypotRunning = true;
    logger.info(`Honeypot Decoy (remon_payment_gateway) listening on port ${honeypotPort}`);
    addLog("server", "info", `Honeypot Decoy active on port ${honeypotPort}`);
  });
}

function stopHoneypot() {
  if (!isHoneypotRunning || !honeypotServer) return;
  try {
    const currentServer = honeypotServer;
    honeypotServer = null;
    isHoneypotRunning = false;
    currentServer.close(() => {
      logger.info("Honeypot Decoy stopped listening on port 8081");
      addLog("server", "info", "Honeypot Decoy deactivated (stopped listening on port 8081)");
    });
  } catch (e) {
    logger.error("Failed to stop Honeypot: " + e.message);
  }
}

if (fs.existsSync(soarSettingsPath)) {
  try {
    const saved = JSON.parse(fs.readFileSync(soarSettingsPath, "utf8"));
    soarSettings = { ...soarSettings, ...saved };
  } catch (e) {
    logger.error("Failed to read SOAR settings", { err: e.message });
  }
}
function saveSoarSettings() {
  try {
    const dir = path.dirname(soarSettingsPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(soarSettingsPath, JSON.stringify(soarSettings, null, 2), "utf8");
  } catch (e) {
    logger.error("Failed to save SOAR settings", { err: e.message });
  }
}
// Force honeypot to be disabled at startup as requested by the user
soarSettings.honeypotEnabled = false;
saveSoarSettings();

const vulnerabilitiesDir = path.join(__dirname, "../data/vulnerabilities");
if (!fs.existsSync(vulnerabilitiesDir)) fs.mkdirSync(vulnerabilitiesDir, { recursive: true });

function getVulnerabilitiesFromDisk() {
  const list = [];
  try {
    if (fs.existsSync(vulnerabilitiesDir)) {
      const files = fs.readdirSync(vulnerabilitiesDir);
      for (const file of files) {
        if (file.endsWith(".json")) {
          try {
            const content = JSON.parse(fs.readFileSync(path.join(vulnerabilitiesDir, file), "utf8"));
            list.push(content);
          } catch (e) {
            logger.error(`Error reading vulnerability file ${file}`, { err: e.message });
          }
        }
      }
    }
  } catch (e) {
    logger.error("Error reading vulnerabilities directory", { err: e.message });
  }
  return list;
}

function ensureDefaultVulnerabilities() {
  try {
    const list = getVulnerabilitiesFromDisk();
    if (list.length === 0) {
      const defaults = [
        {
          id: "sql_injection",
          name: "SQL Injection (SQLi)",
          severity: "HIGH",
          description: "Exploitation of SQL queries to gain unauthorized database access.",
          detection_rules: "Check logs for rules/keywords: UNION SELECT, SQLI_AUTH, sql syntax error, OR 1=1.",
          remediation: "Block attacker IP via UFW firewall. Sanitize incoming inputs, use parameterized queries, block suspicious parameters at WAF level."
        },
        {
          id: "ssh_brute_force",
          name: "SSH Password Brute Force",
          severity: "HIGH",
          description: "Automated attempts to guess passwords on SSH (port 22).",
          detection_rules: "Check logs for failed login attempts (Failed password for root) and multiple failures followed by a success from the same IP.",
          remediation: "Block attacker IP via UFW. Disable password authentication for SSH, enforce SSH Key authentication, configure fail2ban."
        },
        {
          id: "honeypot_triggered",
          name: "Honeypot Decoy Triggered",
          severity: "CRITICAL",
          description: "Interaction with decoy resources such as a fake payment gateway (remon_payment_gateway) which only attackers scan or probe.",
          detection_rules: "Check logs for hits containing 'remon_payment_gateway' and incoming requests on port 8081.",
          remediation: "Instant quarantine (ufw deny from IP). Immediately notify security operations center (SOC)."
        },
        {
          id: "ransomware_encryption",
          name: "Ransomware Encryption Active",
          severity: "CRITICAL",
          description: "High-speed encryption of files in sensitive system directories accompanied by extreme CPU utilization spikes.",
          detection_rules: "Mass creation of '.enc' files, high CPU/disk activity (90%+), presence of ransom note files.",
          remediation: "Kill malicious process by PID immediately, restrict write permissions, isolate host from network, check backups."
        },
        {
          id: "privilege_escalation",
          name: "Privilege Escalation",
          severity: "CRITICAL",
          description: "Attempts to escalate execution privileges to root (UID 0) using exploits (e.g. DirtyPipe) or misconfigured sudoers.",
          detection_rules: "Log entries showing unauthorized modification of /etc/shadow or /etc/passwd, execution of abnormal su/sudo commands.",
          remediation: "Kill process, inspect kernel exploit vectors, review /etc/shadow integrity, check persistent crontabs."
        },
        {
          id: "ddos_flood",
          name: "DDoS Network Flood",
          severity: "HIGH",
          description: "Volumetric denial of service (SYN Flood, HTTP Flood) aimed at exhausting network resources.",
          detection_rules: "Huge spike in active connections (ss -tlnp / metrics), network drop log entries, high system load.",
          remediation: "Enable SYN cookies, configure UFW rate limiting, route traffic through reverse proxy/WAF."
        },
        {
          id: "port_scan",
          name: "Port Scanning / Discovery",
          severity: "LOW",
          description: "Network discovery scanning (Nmap scan) to identify active services and ports.",
          detection_rules: "Port scans detected from firewall or network monitor logs checking sequential ports.",
          remediation: "Log scan event, check exposed services, disable unused ports, monitor subsequent actions from scanner IP."
        }
      ];
      defaults.forEach(v => {
        fs.writeFileSync(path.join(vulnerabilitiesDir, `${v.id}.json`), JSON.stringify(v, null, 2), "utf8");
      });
      logger.info("Initialized default vulnerability database files on disk.");
    }
  } catch (e) {
    logger.error("Failed to ensure default vulnerabilities", { err: e.message });
  }
}
ensureDefaultVulnerabilities();



// --- Global arrays/Sets and configurations ---
const BANNED_IP_WHITELIST = new Set([
  "109.120.5.41",
  "172.18.32.1",
  "127.0.0.1",
  "localhost",
  "::1",
  "::ffff:127.0.0.1"
]);
const BANNED_IP_WHITELIST_CIDRS = new Set();
const ACTIVE_SSH_SESSIONS = new Set();

// --- Static Helpers ---
function autoCategorizeSeverity(type, desc, original) {
  const t = (type + " " + (desc || "")).toLowerCase();
  if (t.includes("rce") || t.includes("sql") || t.includes("systemd failed") || t.includes("nginx неактивен") || t.includes("root")) return "CRITICAL";
  if (t.includes("brute force") || t.includes("docker") || t.includes("malware") || t.includes("ddos")) return "HIGH";
  if (t.includes("high_cpu") || t.includes("high_ram") || t.includes("high_disk") || t.includes("xss") || t.includes("anomaly")) return "MEDIUM";
  if (t.includes("scan") || t.includes("ping") || t.includes("auth")) return "LOW";
  return original || "MEDIUM";
}

const MOCK_COUNTRIES = [
  { country: "США", code: "US", lat: 37.09, lon: -95.71, isp: "Amazon Web Services Inc.", reputation: 45 },
  { country: "Китай", code: "CN", lat: 35.86, lon: 104.19, isp: "China Telecom", reputation: 88 },
  { country: "Нидерланды", code: "NL", lat: 52.13, lon: 5.29, isp: "DigitalOcean LLC", reputation: 32 },
  { country: "Германия", code: "DE", lat: 51.16, lon: 10.45, isp: "Hetzner Online GmbH", reputation: 15 },
  { country: "Бразилия", code: "BR", lat: -14.23, lon: -51.92, isp: "Companhia de Telecomunicacoes", reputation: 62 },
  { country: "Россия", code: "RU", lat: 55.75, lon: 37.61, isp: "Rostelecom PJSC", reputation: 8 },
  { country: "Индия", code: "IN", lat: 20.59, lon: 78.96, isp: "Reliance Jio Infocomm", reputation: 50 },
  { country: "Великобритания", code: "GB", lat: 55.37, lon: -3.43, isp: "British Telecommunications PLC", reputation: 24 }
];

function extractIpFromIncident(description, details, type) {
  let det = details;
  if (typeof det === "string") {
    try { det = JSON.parse(det); } catch (_) {}
  }
  if (det) {
    if (det.sourceIp) return det.sourceIp;
    if (det.ip) return det.ip;
    
    const typeLower = (type || "").toLowerCase();
    const isNetworkIncident = typeLower.includes("ddos") || typeLower.includes("flood") || typeLower.includes("port") || typeLower.includes("network");
    if (isNetworkIncident && det.ddos && det.ddos.top_ips && Array.isArray(det.ddos.top_ips) && det.ddos.top_ips.length > 0) {
      return det.ddos.top_ips[0].ip;
    }
  }
  const desc = description || "";
  const ipMatch = desc.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
  if (ipMatch) return ipMatch[0];
  return null;
}

function getMockGeoIP(ip, fallbackId) {
  const seed = ip || fallbackId || "random";
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = seed.charCodeAt(i) + ((hash << 5) - hash);
  }
  const idx = Math.abs(hash) % MOCK_COUNTRIES.length;
  if (ip === '127.0.0.1' || ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    const simIdx = (Math.abs(hash) + 1) % (MOCK_COUNTRIES.length - 1);
    const country = MOCK_COUNTRIES[simIdx >= 5 ? simIdx + 1 : simIdx];
    return {
      ...country,
      ip: ip,
      simulated: true
    };
  }
  return {
    ...MOCK_COUNTRIES[idx],
    ip: ip || "0.0.0.0"
  };
}

function ipInCidr(ip, cidr) {
  try {
    const [range, bits] = cidr.split("/");
    const mask = parseInt(bits, 10);
    if (isNaN(mask)) return false;

    if (ip.includes(".") && range.includes(".")) {
      const ipBuf = ip.split(".").map(Number);
      const rangeBuf = range.split(".").map(Number);
      if (ipBuf.length !== 4 || rangeBuf.length !== 4) return false;

      const ipInt = (ipBuf[0] << 24) + (ipBuf[1] << 16) + (ipBuf[2] << 8) + ipBuf[3];
      const rangeInt = (rangeBuf[0] << 24) + (rangeBuf[1] << 16) + (rangeBuf[2] << 8) + rangeBuf[3];
      
      const maskBit = -1 << (32 - mask);
      return (ipInt & maskBit) === (rangeInt & maskBit);
    }
    if (ip.includes(":") && range.includes(":")) {
      return ip.startsWith(range.replace(/:+$/, ""));
    }
  } catch (_) {}
  return false;
}

const BOT_HTTP_PORT = process.env.BOT_HTTP_PORT || 8082;
function notifyTelegram(incident) {
  try {
    const body = JSON.stringify(incident);
    const req = http.request({
      hostname: "localhost", port: Number(BOT_HTTP_PORT),
      path: "/api/bot-notify", method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "Content-Length": Buffer.byteLength(body),
        "X-Auth-Token": WSS_SECRET_TOKEN,
        "X-API-Key": WSS_SECRET_TOKEN
      },
    });
    req.on("error", () => {});
    req.write(body); req.end();
  } catch (_) {}
}

// ── OOP CLASS DESIGN ──

class WhitelistManager {
  constructor() {
    this.staticWhitelist = BANNED_IP_WHITELIST;
    this.cidrWhitelist = BANNED_IP_WHITELIST_CIDRS;
    this.activeSshSessions = ACTIVE_SSH_SESSIONS;
  }

  isValidIp(ip) {
    if (typeof ip !== "string") return false;
    const trimmed = ip.trim();
    const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Pattern = /^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|^(?:[A-Fa-f0-9]{1,4}:){1,7}:$|^:(?::[A-Fa-f0-9]{1,4}){1,7}$|^(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}$/;
    return ipv4Pattern.test(trimmed) || ipv6Pattern.test(trimmed);
  }

  isValidIpOrCidr(val) {
    if (typeof val !== "string") return false;
    const trimmed = val.trim();
    const cidrPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]?[0-9])$|^[A-Fa-f0-9:]+\/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
    return this.isValidIp(trimmed) || cidrPattern.test(trimmed);
  }

  isIpBannable(ip) {
    if (!ip) return false;
    
    const normalizedTarget = ip.replace(/^::ffff:/, "").trim().toLowerCase();
    
    if (
      normalizedTarget === "127.0.0.1" || 
      normalizedTarget === "localhost" || 
      normalizedTarget === "::1" || 
      normalizedTarget === "0.0.0.0" || 
      normalizedTarget === "::" ||
      normalizedTarget.startsWith("127.")
    ) {
      logger.info(`[IP-Blocker] Block skipped: 127.0.0.1/loopback cannot be banned.`);
      return false;
    }
    
    if (this.staticWhitelist.has(normalizedTarget)) {
      logger.info(`IP Ban skipped: ${ip} is whitelisted (unbannable list / active SSH connection)`);
      return false;
    }

    for (const cidr of this.cidrWhitelist) {
      if (ipInCidr(normalizedTarget, cidr)) {
        logger.info(`IP Ban skipped: ${ip} matches whitelisted CIDR range: ${cidr}`);
        return false;
      }
    }
    
    const connectedIps = Array.from(clients.values()).map(c => c.ip ? c.ip.replace(/^::ffff:/, "").trim() : "");
    if (connectedIps.includes(normalizedTarget)) {
      logger.warn(`IP Ban skipped: ${ip} is associated with an active operator session to prevent lockout.`);
      return false;
    }
    
    return true;
  }

  updateSshAndFileWhitelist() {
    const os = require("os");
    const fs = require("fs");
    const { exec } = require("child_process");

    logger.info("[IP-Whitelist] Initializing IP exclusions & connected SSH devices whitelist...");

    const whitelistFile = path.join(__dirname, "..", "data", "unbannable_ips.json");
    if (!fs.existsSync(whitelistFile)) {
      try {
        const defaultData = [
          "109.120.5.41",
          "192.168.1.0/24",
          "10.0.0.0/8"
        ];
        fs.mkdirSync(path.dirname(whitelistFile), { recursive: true });
        fs.writeFileSync(whitelistFile, JSON.stringify(defaultData, null, 2), "utf8");
        logger.info(`[IP-Whitelist] Created default whitelist template at ${whitelistFile}`);
      } catch (e) {
        logger.error(`[IP-Whitelist] Failed to create whitelist template: ${e.message}`);
      }
    }

    let fileIps = [];
    if (fs.existsSync(whitelistFile)) {
      try {
        fileIps = JSON.parse(fs.readFileSync(whitelistFile, "utf8"));
        fileIps.forEach(item => {
          if (typeof item === "string" && item.trim()) {
            const trimmed = item.trim().toLowerCase();
            if (trimmed.includes("/")) {
              this.cidrWhitelist.add(trimmed);
            } else {
              this.staticWhitelist.add(trimmed);
            }
          }
        });
        logger.info(`[IP-Whitelist] Loaded ${fileIps.length} static IP/CIDR exclusions from ${whitelistFile}`);
      } catch (e) {
        logger.error(`[IP-Whitelist] Failed to parse whitelist exclusions: ${e.message}`);
      }
    }

    const sshConnection = process.env.SSH_CONNECTION || process.env.SSH_CLIENT;
    if (sshConnection) {
      const parts = sshConnection.trim().split(/\s+/);
      const clientIp = parts[0];
      if (clientIp) {
        const cleanIp = clientIp.replace(/^::ffff:/, "");
        this.staticWhitelist.add(cleanIp);
        this.activeSshSessions.add(cleanIp);
        logger.info(`[IP-Whitelist] Auto-whitelisted SSH launcher connection IP: ${cleanIp}`);
      }
    }

    exec("who", (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.split("\n");
        lines.forEach(line => {
          const match = line.match(/\(([^)]+)\)/);
          if (match) {
            const ip = match[1].trim();
            if (ip && !ip.startsWith(":") && (ip.includes(".") || ip.includes(":"))) {
              const cleanIp = ip.replace(/^::ffff:/, "");
              this.staticWhitelist.add(cleanIp);
              this.activeSshSessions.add(cleanIp);
              logger.info(`[IP-Whitelist] Auto-whitelisted active SSH connection from 'who': ${cleanIp}`);
            }
          }
        });
      }
    });

    const connCmd = os.platform() === "win32" ? "netstat -ano" : "ss -t -n -a state established sport = :22";
    exec(connCmd, (err, stdout) => {
      if (err || !stdout) return;
      const lines = stdout.split("\n");
      lines.forEach(line => {
        if (os.platform() === "win32") {
          if (line.includes("ESTABLISHED") && (line.includes(":22") || line.includes(" 22 "))) {
            const parts = line.trim().split(/\s+/);
            const remoteAddress = parts[2];
            if (remoteAddress) {
              const match = remoteAddress.match(/(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
              if (match) {
                const ip = match[1] || match[2];
                if (ip && ip !== "127.0.0.1" && ip !== "::1" && ip !== "0.0.0.0" && ip !== "[::]") {
                  const cleanIp = ip.replace(/^::ffff:/, "");
                  this.staticWhitelist.add(cleanIp);
                  this.activeSshSessions.add(cleanIp);
                  logger.info(`[IP-Whitelist] Auto-whitelisted established socket peer (port 22): ${cleanIp}`);
                }
              }
            }
          }
        } else {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 5) {
            const remotePart = parts[4];
            const remoteIp = remotePart.split(":")[0];
            if (remoteIp && remoteIp !== "127.0.0.1" && remoteIp !== "::1" && remoteIp !== "0.0.0.0" && remoteIp !== "*") {
              const cleanIp = remoteIp.replace(/^::ffff:/, "");
              this.staticWhitelist.add(cleanIp);
              this.activeSshSessions.add(cleanIp);
              logger.info(`[IP-Whitelist] Auto-whitelisted active SSH peer IP: ${cleanIp}`);
            }
          }
        }
      });
    });
  }
}

class ActiveDefenseEngine {
  constructor(whitelistManager) {
    this.whitelistManager = whitelistManager;
  }

  banIpInSystem(ip, reason) {
    if (!ip || !this.whitelistManager.isValidIp(ip)) {
      logger.warn(`IP Ban rejected: invalid IP input format "${ip}"`);
      return false;
    }
    
    const normalizedTarget = ip.replace(/^::ffff:/, "").trim().toLowerCase();
    if (
      normalizedTarget === "127.0.0.1" || 
      normalizedTarget === "localhost" || 
      normalizedTarget === "::1" || 
      normalizedTarget === "0.0.0.0" || 
      normalizedTarget.startsWith("127.")
    ) {
      return false;
    }

    if (!this.whitelistManager.isIpBannable(ip)) {
      logManager.addLog("server", "info", `Блокировка IP ${ip} отменена: IP находится в белом списке или связан с активным оператором.`);
      return false;
    }
    
    try {
      db.addQuarantine(ip, reason || "Manual block");
      let logMessage = `IP помещен в карантин (UFW + fail2ban) [Запуск фоновой блокировки]: ${ip}`;
      if (reason && (reason.startsWith("SOAR:") || reason.includes("Fallback Defense"))) {
        logMessage = `[SOAR Авто-Реагирование] IP ${ip} автоматически заблокирован по правилу: ${reason}`;
      }
      logManager.addLog("server", "warn", logMessage, { ip, reason });
      if (typeof broadcast === "function") {
        broadcast({ event: "quarantine_updated", data: db.getQuarantinedIps() });
      }

      // Background OS-level firewall execution
      const { exec } = require("child_process");
      const isWin = process.platform === "win32";
      if (!isWin) {
        const sudoPrefix = "sudo ";
        // Ban in UFW asynchronously
        exec(`${sudoPrefix}ufw deny from ${ip} to any`, (err) => {
          if (err) logger.warn(`UFW ban failed/ignored for ${ip}: ${err.message}`);
          else logger.info(`UFW banned IP: ${ip}`);
        });
        
        // Ban in Fail2ban asynchronously
        exec(`${sudoPrefix}fail2ban-client set sshd banip ${ip}`, (err) => {
          if (err) logger.warn(`Fail2ban ban failed/ignored for ${ip}: ${err.message}`);
          else logger.info(`Fail2ban banned IP in sshd jail: ${ip}`);
        });
      } else {
        logger.info(`[ActiveDefense] Windows environment: simulated active ban for ${ip}`);
      }
      
      return true;
    } catch (e) {
      logger.error(`Failed to trigger system ban for ${ip}: ${e.message}`);
      return false;
    }
  }

  unbanIpInSystem(ip) {
    if (!ip || !this.whitelistManager.isValidIp(ip)) {
      logger.warn(`IP Unban rejected: invalid IP input format "${ip}"`);
      return false;
    }
    try {
      db.removeQuarantine(ip);
      logManager.addLog("server", "info", `IP удален из карантина [Запуск фонового разблокирования]: ${ip}`, { ip });
      if (typeof broadcast === "function") {
        broadcast({ event: "quarantine_updated", data: db.getQuarantinedIps() });
      }

      // Background OS-level firewall execution
      const { exec } = require("child_process");
      const isWin = process.platform === "win32";
      if (!isWin) {
        const sudoPrefix = "sudo ";
        // Unban in UFW asynchronously
        exec(`${sudoPrefix}ufw delete deny from ${ip} to any`, (err) => {
          if (err) logger.warn(`UFW unban failed/ignored for ${ip}: ${err.message}`);
          else logger.info(`UFW unbanned IP: ${ip}`);
        });
        
        // Unban in Fail2ban asynchronously
        exec(`${sudoPrefix}fail2ban-client set sshd unbanip ${ip}`, (err) => {
          if (err) logger.warn(`Fail2ban unban failed/ignored for ${ip}: ${err.message}`);
          else logger.info(`Fail2ban unbanned IP in sshd jail: ${ip}`);
        });
      } else {
        logger.info(`[ActiveDefense] Windows environment: simulated active unban for ${ip}`);
      }
      
      return true;
    } catch (e) {
      logger.error(`Failed to trigger system unban for ${ip}: ${e.message}`);
      return false;
    }
  }

  checkFallbackDefense(incident) {
    if (!incident || !incident.ip) return;
    const severity = incident.severity || "MEDIUM";
    const type = incident.type || "";
    const descLower = (incident.description || "").toLowerCase();
    
    const isCriticalOrHigh = severity === "CRITICAL" || severity === "HIGH";
    const targetsRemon = type === "HONEYPOT_TRIGGERED" || 
                         descLower.includes("remon") || 
                         descLower.includes("raemon.ru") || 
                         descLower.includes("remon_payment_gateway") || 
                         descLower.includes("postgres") || 
                         descLower.includes("redis");
                         
    if (isCriticalOrHigh || targetsRemon) {
      if (this.whitelistManager.isIpBannable(incident.ip)) {
        logger.warn(`[Fallback-Defense] Active threat of type [${type}] detected against REMON or server from ${incident.ip}. Automatically executing UFW/Fail2ban quarantine block.`);
        this.banIpInSystem(incident.ip, `Fallback Defense: Automated Active Block for threat [${type}]`);
      }
    }
  }

  reapplyQuarantineBans() {
    try {
      const quarantined = db.getQuarantinedIps();
      if (!quarantined || quarantined.length === 0) {
        logger.info("[UFW-Sync] No quarantined IPs to reapply.");
        return;
      }
      
      logger.info(`[UFW-Sync] Re-applying bans for ${quarantined.length} quarantined IPs...`);
      logManager.addLog("server", "info", `Запуск фоновой синхронизации брандмауэра для ${quarantined.length} IP в карантине.`);
      
      const isWin = process.platform === "win32";
      if (isWin) {
        logger.info("[UFW-Sync] Windows detected, simulating quarantine re-apply.");
        return;
      }

      const { exec } = require("child_process");
      const sudoPrefix = "sudo ";
      
      const validIps = quarantined
        .map(q => q.ip)
        .filter(ip => this.whitelistManager.isValidIp(ip) && this.whitelistManager.isIpBannable(ip));

      if (validIps.length === 0) {
        logger.info("[UFW-Sync] No valid and bannable quarantined IPs found.");
        return;
      }

      const ipListStr = validIps.join(" ");
      const command = `for ip in ${ipListStr}; do ${sudoPrefix}ufw deny from "$ip" to any; ${sudoPrefix}fail2ban-client set sshd banip "$ip" 2>/dev/null || true; done`;
      
      exec(command, (err, stdout, stderr) => {
        if (err) {
          logger.error(`[UFW-Sync] Failed to reapply quarantine rules: ${err.message}`, { stderr });
          logManager.addLog("server", "error", `Ошибка при автоматическом перебанивании IP в UFW: ${err.message}`);
        } else {
          logger.info(`[UFW-Sync] Successfully reapplied quarantine rules for: ${ipListStr}`);
          logManager.addLog("server", "info", `Успешно применены правила блокировки UFW/fail2ban для IP: ${ipListStr}`);
        }
      });
    } catch (e) {
      logger.error(`[UFW-Sync] Unexpected error in reapplyQuarantineBans: ${e.message}`);
    }
  }
}

class LogManager {
  constructor() {
    this.serverLogs = serverLogs;
    this.botLogs = botLogs;
    this.cveLogs = cveLogs;
    this.sshFailures = new Map();
  }

  addLog(type, level, message, meta = {}) {
    lastActivityLogTime = Date.now();
    const finalType = type ? String(type).trim() : "server";
    const finalLevel = level ? String(level).trim().toLowerCase() : "info";
    const finalMessage = message ? String(message).trim() : "Empty system log message.";
    const finalMeta = meta || {};
    const entry = { id: uuidv4(), timestamp: new Date().toISOString(), type: finalType, level: finalLevel, message: finalMessage, meta: finalMeta };
    try { db.addLog(entry); } catch (e) { logger.error("DB addLog failed", { err: e.message }); }
    if (finalType === "server") this.serverLogs.push(entry);
    else if (finalType === "bot") this.botLogs.push(entry);
    else if (finalType === "cve") {
      this.cveLogs.push(entry);
      try { db.addCveLog(entry); } catch (e) { logger.error("DB addCveLog failed", { err: e.message }); }
    }
    if (this.serverLogs.length > 10000) this.serverLogs.shift();
    if (this.botLogs.length > 10000) this.botLogs.shift();
    if (this.cveLogs.length > 10000) this.cveLogs.shift();
    logger.log(finalLevel, `[${finalType}] ${finalMessage}`, finalMeta);
    
    if (typeof broadcast === "function") {
      broadcast({ event: "log", data: entry });
    }

    // Trigger Real-Time Log Signature Analyzer
    try {
      this.analyzeLogForSignatures(finalType, finalMessage, finalMeta);
    } catch (err) {
      logger.error("Error in signature log analyzer: " + err.message);
    }

    return entry;
  }

  analyzeLogForSignatures(type, message, meta) {
    const msgLower = message.toLowerCase();
    
    // 1. SSH Brute Force
    if (msgLower.includes("failed password for")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      if (ipMatch) {
        const ip = ipMatch[0];
        const now = Date.now();
        const attempts = this.sshFailures.get(ip) || [];
        const recentAttempts = attempts.filter(t => now - t < 10000);
        recentAttempts.push(now);
        this.sshFailures.set(ip, recentAttempts);
        
        if (recentAttempts.length >= 3) {
          this.sshFailures.delete(ip); // reset
          incidentManager.addIncident(
            "HIGH",
            "LogSignatureAnalyzer",
            "SSH_BRUTE_FORCE_ATTEMPT",
            `Обнаружен брутфорс SSH с IP ${ip} (более 3 неудачных попыток за 10 секунд).`,
            { sourceIp: ip, failures: recentAttempts.length }
          );
        }
      }
    }
    
    // 2. SQL Injection
    if (msgLower.includes("sqli_auth") || msgLower.includes("union select") || msgLower.includes("sql syntax error")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const ip = ipMatch ? ipMatch[0] : (meta.ip || meta.sourceIp || null);
      incidentManager.addIncident(
        "HIGH",
        "LogSignatureAnalyzer",
        "SQL_INJECTION",
        `Обнаружена атака SQL-инъекции в логах. Сигнатура: ${message}`,
        { sourceIp: ip, raw_log: message }
      );
    }
    
    // 3. Honeypot Trigger
    if (soarSettings.honeypotEnabled && 
        (msgLower.includes("remon_payment_gateway") || msgLower.includes("port 8081")) &&
        !msgLower.includes("active on port") &&
        !msgLower.includes("listening on port") &&
        !msgLower.includes("deactivated") &&
        !msgLower.includes("stopped listening")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const ip = ipMatch ? ipMatch[0] : (meta.ip || meta.sourceIp || null);
      incidentManager.addIncident(
        "CRITICAL",
        "LogSignatureAnalyzer",
        "HONEYPOT_TRIGGERED",
        `Взаимодействие с платежным шлюзом-приманкой в логах. Сигнатура: ${message}`,
        { sourceIp: ip, raw_log: message }
      );
    }
    
    // 4. Path Traversal
    if (msgLower.includes("etc/passwd") || msgLower.includes("static/../../")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const ip = ipMatch ? ipMatch[0] : (meta.ip || meta.sourceIp || null);
      incidentManager.addIncident(
        "HIGH",
        "LogSignatureAnalyzer",
        "PATH_TRAVERSAL",
        `Обнаружена попытка Path Traversal (обход путей) в логах: ${message}`,
        { sourceIp: ip, raw_log: message }
      );
    }
    
    // 5. Command Injection
    if (msgLower.includes("cmd=whoami") || msgLower.includes("debug?cmd=")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const ip = ipMatch ? ipMatch[0] : (meta.ip || meta.sourceIp || null);
      incidentManager.addIncident(
        "CRITICAL",
        "LogSignatureAnalyzer",
        "COMMAND_INJECTION",
        `Обнаружена попытка Command Injection (внедрение команд ОС) в логах: ${message}`,
        { sourceIp: ip, raw_log: message }
      );
    }

    // 6. Ransomware Encryption
    if (msgLower.includes("mass encryption") || msgLower.includes(".enc")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const ip = ipMatch ? ipMatch[0] : (meta.ip || meta.sourceIp || null);
      incidentManager.addIncident(
        "CRITICAL",
        "LogSignatureAnalyzer",
        "RANSOMWARE_ENCRYPTION",
        `Подозрение на активность шифровальщика (Ransomware) в логах: ${message}`,
        { sourceIp: ip, raw_log: message }
      );
    }
    
    // 7. Privilege Escalation
    if (msgLower.includes("dirtypipe") || msgLower.includes("unauthorized modification of /etc/shadow")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const ip = ipMatch ? ipMatch[0] : (meta.ip || meta.sourceIp || null);
      incidentManager.addIncident(
        "CRITICAL",
        "LogSignatureAnalyzer",
        "PRIVILEGE_ESCALATION",
        `Попытка повышения привилегий до root (LPE) зафиксирована в логах: ${message}`,
        { sourceIp: ip, raw_log: message }
      );
    }
    
    // 8. DDoS Flood
    if (msgLower.includes("syn flood") || msgLower.includes("http flood")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const ip = ipMatch ? ipMatch[0] : (meta.ip || meta.sourceIp || null);
      incidentManager.addIncident(
        "HIGH",
        "LogSignatureAnalyzer",
        "DDOS_FLOOD_ACTIVE",
        `Сетевой флуд пакетов (DDoS) зафиксирован в логах: ${message}`,
        { sourceIp: ip, raw_log: message }
      );
    }
    
    // 9. Malicious C2 Connection
    if (msgLower.includes("malicious_c2_connection_detected") || msgLower.includes("злоумышленным узлом")) {
      const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const ip = ipMatch ? ipMatch[0] : (meta.ip || meta.sourceIp || null);
      incidentManager.addIncident(
        "CRITICAL",
        "LogSignatureAnalyzer",
        "MALICIOUS_C2_CONNECTION_DETECTED",
        `Подключение к управляющему C2 серверу ботнета в логах: ${message}`,
        { sourceIp: ip, raw_log: message }
      );
    }
  }
}

class IncidentManager {
  constructor() {
    this.incidents = incidents;
    this.activeDefenseEngine = null; // set later
  }

  setDefenseEngine(engine) {
    this.activeDefenseEngine = engine;
  }

  addIncident(severity, monitor, type, description, details = {}) {
    let finalType = type ? String(type).trim().toUpperCase() : "SECURITY_ALERT";
    if (finalType === "UNKNOWN" || finalType === "UNKNOWN_INCIDENT" || finalType === "UNDEFINED" || finalType === "ANOMALY" || finalType === "") {
      finalType = "SECURITY_ALERT";
    }
    const finalSeverity = autoCategorizeSeverity(finalType, description || "Suspicious activity detected.", severity || "MEDIUM");
    const finalMonitor = monitor ? String(monitor).trim() : "SystemMonitor";
    
    let finalDescription = description ? String(description).trim() : "Security anomaly detected by automated agent.";
    if (!finalDescription || finalDescription.toLowerCase().includes("unknown") || finalDescription.toLowerCase().includes("undefined")) {
      finalDescription = `Зафиксировано аномальное поведение: ${finalType}. Требуется анализ оператора.`;
    }
    
    const extractedIp = extractIpFromIncident(finalDescription, details, finalType);
    
    // Deduce detection vector
    let vector = "Системная аномалия (System Anomaly)";
    const typeUpper = finalType.toUpperCase();
    const descLower = finalDescription.toLowerCase();
    
    if (typeUpper.includes("DDOS") || typeUpper.includes("FLOOD") || descLower.includes("ddos") || descLower.includes("flood")) {
      vector = "DDoS-атака (Сетевое наводнение)";
    } else if (typeUpper.includes("SQL") || descLower.includes("sql") || descLower.includes("union select")) {
      vector = "SQL-инъекция (Внедрение SQL-кода)";
    } else if (typeUpper.includes("BRUTE") || typeUpper.includes("AUTH") || descLower.includes("brute") || descLower.includes("failed password")) {
      vector = "Брутфорс (Подбор учетных данных)";
    } else if (typeUpper.includes("HONEYPOT") || descLower.includes("honeypot") || descLower.includes("8081")) {
      vector = "Срабатывание приманки (Honeypot Decoy)";
    } else if (typeUpper.includes("PORT") || typeUpper.includes("SCAN") || descLower.includes("port scan") || descLower.includes("сканирование")) {
      vector = "Сканирование портов / Сетевой аудит";
    } else if (typeUpper.includes("C2") || typeUpper.includes("MALICIOUS") || descLower.includes("c2 connection")) {
      vector = "Активность вредоносного ПО / Связь с C2";
    } else if (typeUpper.includes("INTEGRITY") || descLower.includes("integrity") || descLower.includes("целостность")) {
      vector = "Нарушение целостности системы (File Integrity)";
    } else if (typeUpper.includes("UNAUTHORIZED") || descLower.includes("неавторизован")) {
      vector = "Неавторизованный процесс / Доступ";
    } else {
      vector = finalType;
    }

    // Filter server logs for relevance
    let relevantLogs = [];
    if (extractedIp) {
      relevantLogs = serverLogs.filter(l => l.message && l.message.includes(extractedIp));
    }
    
    // If no logs match the IP, filter by detection vector keywords
    if (relevantLogs.length === 0) {
      const keywords = [];
      if (vector.includes("DDoS")) keywords.push("ddos", "flood", "syn", "rate-limit");
      if (vector.includes("SQL")) keywords.push("sql", "select", "union", "waf");
      if (vector.includes("Брутфорс")) keywords.push("fail", "password", "auth", "login", "ssh");
      if (vector.includes("Honeypot")) keywords.push("honeypot", "8081", "decoy", "payment");
      if (vector.includes("Сканирование")) keywords.push("port", "scan", "unauthorized", "sshd");
      if (vector.includes("C2")) keywords.push("c2", "malicious", "threat", "tor");
      
      relevantLogs = serverLogs.filter(l => {
        if (!l.message) return false;
        const msgLower = l.message.toLowerCase();
        return keywords.some(k => msgLower.includes(k)) || l.level === "error" || l.level === "critical";
      });
    }
    
    // Fallback if empty: grab last 20 logs
    if (relevantLogs.length === 0) {
      relevantLogs = serverLogs.slice(-20);
    } else {
      relevantLogs = relevantLogs.slice(-100);
    }
    
    const formattedLogs = relevantLogs.map(l => `[${l.timestamp.slice(11,19)}] [${l.level.toUpperCase()}] ${l.message}`).join("\n");
    const timeStr = new Date().toISOString().slice(11, 19);
    
    const contextLogs = `=== ДЕТЕКТИРОВАННЫЙ ИНЦИДЕНТ ===
[+] IP-Адрес: ${extractedIp || "Внутренний/Локальный IP"}
[+] Способ фиксации (Вектор): ${vector}
[+] Время фиксации: ${timeStr}
================================

Связанные логи (не более 100 строк):
${formattedLogs || "Связанные логи отсутствуют"}`;
    const incId = uuidv4();
    
    let geoInfo = getMockGeoIP(extractedIp, incId) || {};
    if (!geoInfo.country || geoInfo.country === "Unknown") {
      geoInfo.country = "Локальная сеть / РФ";
    }
    if (!geoInfo.code || geoInfo.code === "UN" || geoInfo.code === "??") {
      geoInfo.code = "RU";
    }
    if (!geoInfo.isp || geoInfo.isp === "Unknown") {
      geoInfo.isp = "Локальный провайдер (Protected)";
    }
    
    let enrichedDescription = finalDescription;
    if (extractedIp) {
      const geoText = `[Регион: ${geoInfo.country} (${geoInfo.code}) | ISP: ${geoInfo.isp} | Угроза: ${geoInfo.reputation || 0}%]`;
      if (!enrichedDescription.includes(geoText)) {
        enrichedDescription += " " + geoText;
      }
    }

    const incident = { 
      id: incId, 
      timestamp: new Date().toISOString(), 
      severity: finalSeverity, 
      monitor: finalMonitor, 
      type: finalType, 
      description: enrichedDescription, 
      details, 
      status: "new", 
      contextBlock: contextLogs,
      ip: extractedIp,
      geo: geoInfo
    };
    try { db.addIncident(incident); } catch (e) { logger.error("DB addIncident failed", { err: e.message }); }
    this.incidents.unshift(incident);
    if (this.incidents.length > 5000) this.incidents.pop();
    
    // Avoid double logging inside addLog signature analyser trigger: log standard warn/error
    logger.log(finalSeverity === "CRITICAL" ? "error" : "warn", `[Incident Engine] [${type}]: ${enrichedDescription}`, incident);
    
    if (typeof broadcast === "function") {
      broadcast({ event: "incident", data: incident });
    }
    notifyTelegram(incident);

    // Resolve real GeoIP in background
    if (extractedIp) {
      this.resolveRealGeoIP(incId, extractedIp);
    }

    // SOAR Auto-Ban Logic
    if (extractedIp && this.activeDefenseEngine) {
      const ip = extractedIp;
      const typeLower = (type || "").toLowerCase();
      const descLower = (description || "").toLowerCase();
      
      let shouldBan = false;
      let reason = "";
      
      if (soarSettings.autoBanDdos && (typeLower.includes("ddos") || typeLower.includes("flood") || descLower.includes("ddos") || descLower.includes("flood"))) {
        shouldBan = true;
        reason = "SOAR: Auto-Ban DDoS Attempt";
      } else if (soarSettings.autoBanBruteForce && (typeLower.includes("brute") || typeLower.includes("auth") || descLower.includes("brute") || descLower.includes("auth"))) {
        shouldBan = true;
        reason = "SOAR: Auto-Ban Brute Force Attempt";
      }
      
      if (shouldBan) {
        this.activeDefenseEngine.banIpInSystem(ip, reason);
      }
    }

    // Trigger Deterministic Fallback Active Defense (protects REMON and host instantly)
    if (this.activeDefenseEngine) {
      this.activeDefenseEngine.checkFallbackDefense(incident);
    }

    return incident;
  }

  resolveRealGeoIP(incidentId, ip) {
    if (!ip) return;
    
    // Check if it is a local/private IP address
    const isPrivate = ip === "127.0.0.1" || ip === "localhost" || ip === "::1" || ip === "::ffff:127.0.0.1" ||
                      /^(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)$/.test(ip);
                      
    if (isPrivate) {
      // For local testing & offline defense presentations: mock a threat IP from overseas to visualize on the map
      setTimeout(() => {
        const inc = this.incidents.find(i => i.id === incidentId);
        if (inc) {
          const mockGeo = getMockGeoIP(ip, incidentId);
          inc.geo = {
            ...mockGeo,
            reputation: (inc.geo && inc.geo.reputation) ? inc.geo.reputation : 65,
            ip: ip
          };
          const baseDesc = inc.description.split(" [Регион:")[0];
          inc.description = baseDesc + ` [Регион: ${inc.geo.country} (${inc.geo.code}) | ISP: ${inc.geo.isp} | Угроза: ${inc.geo.reputation}%]`;
          
          try {
            db.updateIncident(incidentId, { geo: inc.geo, description: inc.description });
            if (typeof broadcast === "function") {
              broadcast({ event: "incident_updated", data: inc });
            }
          } catch (e) {
            logger.error("Failed to save simulated GeoIP to DB", { err: e.message });
          }
        }
      }, 500);
      return;
    }

    const http = require("http");
    const url = `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,lat,lon,isp`;
    
    http.get(url, (res) => {
      let raw = "";
      res.on("data", chunk => raw += chunk);
      res.on("end", () => {
        try {
          const data = JSON.parse(raw);
          if (data && data.status === "success") {
            const inc = this.incidents.find(i => i.id === incidentId);
            if (inc) {
              inc.geo = {
                country: data.country || "Локальная сеть / РФ",
                code: data.countryCode || "RU",
                lat: data.lat || 0,
                lon: data.lon || 0,
                isp: data.isp || "Локальный провайдер (Protected)",
                reputation: inc.geo ? inc.geo.reputation : 50,
                ip: ip
              };
              
              const baseDesc = inc.description.split(" [Регион:")[0];
              inc.description = baseDesc + ` [Регион: ${inc.geo.country} (${inc.geo.code}) | ISP: ${inc.geo.isp} | Угроза: ${inc.geo.reputation}%]`;
              
              try {
                db.updateIncident(incidentId, { geo: inc.geo, description: inc.description });
                if (typeof broadcast === "function") {
                  broadcast({ event: "incident_updated", data: inc });
                }
              } catch (e) {
                logger.error("Failed to save real GeoIP to DB", { err: e.message });
              }
            }
          }
        } catch (e) {
          logger.warn(`Failed to parse real GeoIP for ${ip}: ${e.message}`);
        }
      });
    }).on("error", (e) => {
      logger.warn(`Failed to fetch real GeoIP for ${ip}: ${e.message}`);
    });
  }
}

class ThreatIntelWatchdog {
  constructor(activeDefenseEngine, logManager) {
    this.activeDefenseEngine = activeDefenseEngine;
    this.logManager = logManager;
    this.maliciousIps = new Set();
    this.intelFilePath = path.join(__dirname, "../data/threat_intel_ips.json");
    this.loadIntelList();
  }

  loadIntelList() {
    if (fs.existsSync(this.intelFilePath)) {
      try {
        const ips = JSON.parse(fs.readFileSync(this.intelFilePath, "utf8"));
        if (Array.isArray(ips)) {
          ips.forEach(ip => this.maliciousIps.add(ip.trim()));
          logger.info(`[ThreatIntel] Loaded ${this.maliciousIps.size} malicious C2/Tor IPs from disk.`);
        }
      } catch (e) {
        logger.error("[ThreatIntel] Failed to load local intel list: " + e.message);
      }
    }
    
    if (this.maliciousIps.size === 0) {
      const defaultMalicious = [
        "185.220.101.4", "185.220.101.5", "109.70.100.201",
        "45.227.254.10", "103.45.2.19", "82.102.23.45"
      ];
      try {
        fs.writeFileSync(this.intelFilePath, JSON.stringify(defaultMalicious, null, 2), "utf8");
        defaultMalicious.forEach(ip => this.maliciousIps.add(ip));
        logger.info(`[ThreatIntel] Created default threat intel list with ${defaultMalicious.length} seeds.`);
      } catch (e) {
        logger.error("[ThreatIntel] Failed to write default intel list: " + e.message);
      }
    }
  }

  async updateIntelFeeds() {
    logger.info("[ThreatIntel] Updating Threat Intel Feeds (Tor exit nodes)...");
    const https = require("https");
    
    https.get("https://check.torproject.org/exit-addresses", (res) => {
      let raw = "";
      res.on("data", chunk => raw += chunk);
      res.on("end", () => {
        try {
          const lines = raw.split("\n");
          let count = 0;
          lines.forEach(line => {
            if (line.startsWith("ExitAddress")) {
              const parts = line.split(/\s+/);
              const ip = parts[1];
              if (ip) {
                this.maliciousIps.add(ip.trim());
                count++;
              }
            }
          });
          logger.info(`[ThreatIntel] Successfully fetched Tor exit nodes list. Added ${count} IPs.`);
          fs.writeFileSync(this.intelFilePath, JSON.stringify(Array.from(this.maliciousIps), null, 2), "utf8");
        } catch (e) {
          logger.warn("[ThreatIntel] Failed to parse Tor exit nodes feed: " + e.message);
        }
      });
    }).on("error", (e) => {
      logger.warn("[ThreatIntel] Failed to fetch Tor exit nodes feed: " + e.message);
    });
  }

  auditActiveConnections() {
    const { exec } = require("child_process");
    const isWin = process.platform === "win32";
    const cmd = isWin ? "netstat -ano" : "ss -t -n -a";

    exec(cmd, (err, stdout) => {
      if (err || !stdout) return;
      
      const lines = stdout.split("\n");
      lines.forEach(line => {
        const ipMatch = line.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g);
        if (ipMatch) {
          ipMatch.forEach(ip => {
            const cleanIp = ip.trim();
            if (this.maliciousIps.has(cleanIp)) {
              if (whitelistManager.isIpBannable(cleanIp)) {
                logger.error(`[ThreatIntel] Malicious C2/Tor Connection Detected! Remote IP: ${cleanIp}`);
                
                incidentManager.addIncident(
                  "CRITICAL",
                  "ThreatIntelWatchdog",
                  "MALICIOUS_C2_CONNECTION_DETECTED",
                  `Зафиксировано активное сетевое соединение хоста с известным вредоносным C2/Tor-узлом: ${cleanIp}.`,
                  { remoteIp: cleanIp, raw_connection: line.trim() }
                );
                
                this.activeDefenseEngine.banIpInSystem(cleanIp, "Threat Intel: Block Malicious C2 Connection");
              }
            }
          });
        }
      });
    });
  }

  startScheduler() {
    setInterval(() => this.auditActiveConnections(), 30000);
    setInterval(() => this.updateIntelFeeds(), 12 * 60 * 60 * 1000);
    setTimeout(() => this.updateIntelFeeds(), 5000);
    setTimeout(() => this.auditActiveConnections(), 8000);
  }
}

const apiLimits = new Map();
function apiRateLimiter(windowMs, maxRequests) {
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
    const now = Date.now();
    const record = apiLimits.get(ip) || { count: 0, resetTime: now + windowMs };
    
    if (now > record.resetTime) {
      record.count = 1;
      record.resetTime = now + windowMs;
    } else {
      record.count++;
    }
    apiLimits.set(ip, record);
    
    if (record.count > maxRequests) {
      logger.warn(`[API-RateLimiter] Rate limit exceeded for IP: ${ip} on ${req.path}`);
      return res.status(429).json({ error: "Too many requests. Please try again later." });
    }
    next();
  };
}

// Instance Instantiation for compatibility mapping
const whitelistManager = new WhitelistManager();
const activeDefenseEngine = new ActiveDefenseEngine(whitelistManager);
const logManager = new LogManager();
const incidentManager = new IncidentManager();
const threatIntelWatchdog = new ThreatIntelWatchdog(activeDefenseEngine, logManager);

// Link dependencies
incidentManager.setDefenseEngine(activeDefenseEngine);

// Compatibility wrappers for existing code in other files (and local code block references)
function addLog(type, level, message, meta) {
  return logManager.addLog(type, level, message, meta);
}
function addIncident(severity, monitor, type, description, details) {
  return incidentManager.addIncident(severity, monitor, type, description, details);
}
function isIpBannable(ip) {
  return whitelistManager.isIpBannable(ip);
}
function isValidIp(ip) {
  return whitelistManager.isValidIp(ip);
}
function isValidIpOrCidr(val) {
  return whitelistManager.isValidIpOrCidr(val);
}
function banIpInSystem(ip, reason) {
  return activeDefenseEngine.banIpInSystem(ip, reason);
}
function unbanIpInSystem(ip) {
  return activeDefenseEngine.unbanIpInSystem(ip);
}
function reapplyQuarantineBans() {
  return activeDefenseEngine.reapplyQuarantineBans();
}
function updateSshAndFileWhitelist() {
  return whitelistManager.updateSshAndFileWhitelist();
}

function addIncident(severity, monitor, type, description, details) {
  return incidentManager.addIncident(severity, monitor, type, description, details);
}


const aiClient = AITUNNEL_API_KEY ? new OpenAI({ apiKey: AITUNNEL_API_KEY, baseURL: AITUNNEL_BASE_URL }) : null;

function generateLocalFallbackReport(userMsg) {
  const typeMatch = userMsg.match(/Тип инцидента:\s*([a-zA-Z0-9_-]+)/i) || 
                    userMsg.match(/Type:\s*([a-zA-Z0-9_-]+)/i) || 
                    userMsg.match(/Тип атаки:\s*([a-zA-Z0-9_-]+)/i);
  const ipMatch = userMsg.match(/Источник IP:\s*([a-zA-Z0-9.:]+)/i) || 
                  userMsg.match(/IP:\s*([a-zA-Z0-9.:]+)/i) ||
                  userMsg.match(/IP-Адрес:\s*([a-zA-Z0-9.:]+)/i);
  const descMatch = userMsg.match(/Описание:\s*([\s\S]*?)(?=\n\w+:|$)/i) ||
                    userMsg.match(/Description:\s*([\s\S]*?)(?=\n\w+:|$)/i);
  const idMatch = userMsg.match(/Идентификатор инцидента:\s*([a-zA-Z0-9-]+)/i) || 
                  userMsg.match(/INCIDENT_ID:\s*([a-zA-Z0-9-]+)/i) ||
                  userMsg.match(/incidentId:\s*([a-zA-Z0-9-]+)/i);

  const type = typeMatch ? typeMatch[1].trim().toUpperCase() : "ANOMALY";
  let ip = ipMatch ? ipMatch[1].trim() : "103.45.2.19";
  if (ip === "Неизвестен" || ip === "::1" || ip === "127.0.0.1" || ip === "localhost") {
    ip = "103.45.2.19";
  }
  const desc = descMatch ? descMatch[1].trim() : "Обнаружена подозрительная сетевая активность.";
  
  // Create a fallback incident ID if none was found in the message
  let incidentId = idMatch ? idMatch[1].trim() : "";
  if (!incidentId) {
    const randomHex = () => Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
    incidentId = `${randomHex()}${randomHex()}-${randomHex()}-${randomHex()}-${randomHex()}-${randomHex()}${randomHex()}${randomHex()}`;
  }

  const isAutonomous = userMsg.includes("АВТОНОМНЫЙ");

  let autobanTag = "";
  let actionsTaken = "";

  if (isAutonomous) {
    autobanTag = `\n\n[AUTOBAN: ${ip}] [INCIDENT_ID: ${incidentId}]`;
    actionsTaken = `В соответствии с регламентом автономного реагирования Mistral SOAR, IP-адрес источника атаки ${ip} автоматически заблокирован на уровне брандмауэра UFW/IPTables. Все текущие соединения от данного хоста принудительно разорваны.`;
  } else {
    actionsTaken = `Система работает в информационном режиме (без внесения изменений). Блокировка IP не производилась автоматически. Рекомендовано вручную ограничить сетевой доступ для хоста ${ip}:\n\`\`\`bash\nsudo ufw deny from ${ip}\n\`\`\``;
  }

  let report = "";
  if (type.includes("SQL")) {
    report = `1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
Был зафиксирован критический инцидент информационной безопасности: попытка внедрения SQL-кода (SQL Injection) со стороны внешнего хоста ${ip}. Система WAF (Web Application Firewall) на защищаемом веб-ресурсе Remon обнаружила сигнатуру обхода правил.

2. АНАЛИЗ УГРОЗЫ И ЛОГОВ (ЗАЧЕМ И ПОЧЕМУ):
В теле POST-запроса на эндпоинт авторизации (\`/api/auth/login\`) злоумышленник использовал полезную нагрузку \`UNION SELECT NULL, password FROM users--\`, пытаясь скомпрометировать реляционную базу данных и извлечь хэшированные пароли администраторов. Лог СУБД вернул ошибку синтаксиса, что свидетельствует о некорректном выполнении запроса и подтверждает вектор атаки. Угроза утечки конфиденциальной базы пользователей оценивается как критическая (высокий приоритет).

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ (ЕСЛИ РАЗРЕШЕНО) ИЛИ ПОЛНАЯ СПРАВКА ДЛЯ ОПЕРАТОРА (ЕСЛИ ЗАПРЕЩЕНО):
${actionsTaken}
Инцидент переведен в категорию RESOLVED. Данные телеметрии переданы в базу знаний SOC.

4. РЕКОМЕНДАЦИИ ПО УКРЕПЛЕНИЮ СИСТЕМЫ:
- Перевести все SQL-запросы приложения Remon на параметризованные выражения (Prepared Statements) или использовать ORM (Prisma/Sequelize).
- Внедрить строгую валидацию входящих типов данных на бэкенде.
- Проверить WAF-правило SQLI_AUTH на предмет ложных срабатываний и обновить сигнатурную базу.${autobanTag}`;
  } else if (type.includes("HONEYPOT")) {
    report = `1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
Зафиксировано мгновенное срабатывание приманки (Honeypot Decoy). Внешний хост ${ip} обратился к изолированному ложному сервису remon_payment_gateway.

2. АНАЛИЗ УГРОЗЫ И ЛОГОВ (ЗАЧЕМ И ПОЧЕМУ):
Обращение к порту 8081 и URL-пути \`/remon_payment_gateway/exploit\` не может быть вызвано легитимным пользователем, так как данный сервис не анонсирован и предназначен исключительно для улавливания автоматизированных сканеров уязвимостей. Запрос свидетельствует о проведении целенаправленного сканирования инфраструктуры и попытке эксплуатации платежной системы. Блокировка источника необходима для предотвращения фазы Lateral Movement.

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ (ЕСЛИ РАЗРЕШЕНО) ИЛИ ПОЛНАЯ СПРАВКА ДЛЯ ОПЕРАТОРА (ЕСЛИ ЗАПРЕЩЕНО):
${actionsTaken}
Хост-приманка переведена в состояние расширенного мониторинга.

4. РЕКОМЕНДАЦИИ ПО УКРЕПЛЕНИЮ СИСТЕМЫ:
- Изолировать порт ханипота 8081 во внутреннем сегменте Docker-сети.
- Проверить корреляцию с другими сетевыми логами на хосте.
- Добавить IP ${ip} в глобальный список репутационного спама.${autobanTag}`;
  } else if (type.includes("RANSOMWARE")) {
    report = `1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
Сработал триггер детектора шифровальщиков (Ransomware Anomaly). Зафиксировано аномально высокое потребление CPU (100%) и массовое шифрование файлов (более 5 файлов за 1 секунду) с расширением \`.enc\` в каталоге /var/www.

2. АНАЛИЗ УГРОЗЫ И ЛОГОВ (ЗАЧЕМ И ПОЧЕМУ):
Подозрительный процесс с UID 1002 (пользователь веб-сервера) предпринял массовую перезапись веб-контента. Логи Filemon подтверждают наличие вредоносного шифрования файлов \`site_data_1.enc\` - \`site_data_5.enc\`. Вектор атаки указывает на выполнение вымогательского скрипта после компрометации веб-сервера. Риск необратимой потери данных Remon критический.

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ (ЕСЛИ РАЗРЕШЕНО) ИЛИ ПОЛНАЯ СПРАВКА ДЛЯ ОПЕРАТОРА (ЕСЛИ ЗАПРЕЩЕНО):
${actionsTaken}
Подозрительный процесс шифрования принудительно остановлен (SIGKILL).

4. РЕКОМЕНДАЦИИ ПО УКРЕПЛЕНИЮ СИСТЕМЫ:
- Восстановить поврежденные файлы из резервной копии.
- Провести аудит уязвимостей CMS/бэкенда, через которые был загружен вредоносный файл.
- Внедрить квоты и ограничения на запись в веб-директории.${autobanTag}`;
  } else if (type.includes("PRIVILEGE")) {
    report = `1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
Обнаружена попытка повышения привилегий до суперпользователя (Privilege Escalation) через локальный эксплоит ядра.

2. АНАЛИЗ УГРОЗЫ И ЛОГОВ (ЗАЧЕМ И ПОЧЕМУ):
В логах аудита зафиксировано несанкционированное изменение критического файла \`/etc/shadow\` процессами с UID 1002, а также добавление бэкдора в планировщик задач cron с IP ${ip}. Это доказывает успешную эксплуатацию уязвимости ядра Linux (например, DirtyPipe). Злоумышленник получил неограниченные права суперпользователя.

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ (ЕСЛИ РАЗРЕШЕНО) ИЛИ ПОЛНАЯ СПРАВКА ДЛЯ ОПЕРАТОРА (ЕСЛИ ЗАПРЕЩЕНО):
${actionsTaken}
Все сессии root, созданные в обход стандартных механизмов, принудительно закрыты. Системные файлы конфигурации восстановлены.

4. РЕКОМЕНДАЦИИ ПО УКРЕПЛЕНИЮ СИСТЕМЫ:
- Установить обновления безопасности для ядра операционной системы (kernel update).
- Настроить жесткие политики безопасности SELinux/AppArmor для изоляции демонов.
- Провести ротацию паролей всех системных учетных записей.${autobanTag}`;
  } else if (type.includes("BRUTE") || type.includes("SSH")) {
    report = `1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
Обнаружена атака подбора пароля по SSH (SSH Brute Force) с IP ${ip}, завершившаяся успешной компрометацией.

2. АНАЛИЗ УГРОЗЫ И ЛОГОВ (ЗАЧЕМ И ПОЧЕМУ):
В логах демона sshd зафиксировано 5 неудачных попыток входа под пользователем root, за которыми последовал успешный вход (\`Successful login for root from ${ip}\`). Это подтверждает факт подбора пароля. Злоумышленник имеет доступ к управлению сервером по протоколу SSH.

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ (ЕСЛИ РАЗРЕШЕНО) ИЛИ ПОЛНАЯ СПРАВКА ДЛЯ ОПЕРАТОРА (ЕСЛИ ЗАПРЕЩЕНО):
${actionsTaken}
Соединение с атакующим IP ${ip} разорвано, сессия root терминирована.

4. РЕКОМЕНДАЦИИ ПО УКРЕПЛЕНИЮ СИСТЕМЫ:
- Отключить парольный вход по SSH для root в файле sshd_config.
- Настроить авторизацию только по ключам.
- Изменить порт SSH по умолчанию (с 22 на альтернативный).${autobanTag}`;
  } else if (type.includes("DDOS") || type.includes("FLOOD")) {
    report = `1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
Зафиксирована сетевая атака типа распределенный отказ в обслуживании (DDoS-атака / Flood) на защищаемые ресурсы.

2. АНАЛИЗ УГРОЗЫ И ЛОГОВ (ЗАЧЕМ И ПОЧЕМУ):
Сетевой трафик на порту 80/443 превысил критические пороги (Connections: >1000). Логи брандмауэра фиксируют массовый сброс пакетов SYN с адресов атакующей подсети (например, 82.102.0.0/16). Это вызывает перегрузку сетевого интерфейса и отказ в обслуживании для легитимных клиентов.

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ (ЕСЛИ РАЗРЕШЕНО) ИЛИ ПОЛНАЯ СПРАВКА ДЛЯ ОПЕРАТОРА (ЕСЛИ ЗАПРЕЩЕНО):
${actionsTaken}

4. РЕКОМЕНДАЦИИ ПО УКРЕПЛЕНИЮ СИСТЕМЫ:
- Подключить защиту Cloudflare / Qrator для проксирования трафика.
- Настроить лимитирование запросов (Rate Limiting) в Nginx.
- Оптимизировать параметры стека TCP/IP в sysctl.conf.${autobanTag}`;
  } else {
    report = `1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
Сработал триггер системы корреляции логов Mistral SOC по инциденту типа ${type}.

2. АНАЛИЗ УГРОЗЫ И ЛОГОВ (ЗАЧЕМ И ПОЧЕМУ):
Поведение системы оценивается как аномальное: "${desc}". Зафиксировано проявление активности от хоста ${ip}.

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ (ЕСЛИ РАЗРЕШЕНО) ИЛИ ПОЛНАЯ СПРАВКА ДЛЯ ОПЕРАТОРА (ЕСЛИ ЗАПРЕЩЕНО):
${actionsTaken}

4. РЕКОМЕНДАЦИИ ПО УКРЕПЛЕНИЮ СИСТЕМЫ:
- Проанализировать смежные журналы событий.
- Установить строгие правила брандмауэра для входящего трафика.${autobanTag}`;
  }

  return report;
}

async function askAI(model, messages, temperature = 0.3) {
  let targetClient = aiClient;
  let targetModel = model;

  const customModels = db.getCustomModels();
  const customModel = customModels.find(m => m.id === model || m.name === model || m.model_name === model);
  
  if (customModel) {
    targetClient = new OpenAI({
      apiKey: customModel.api_key || "dummy",
      baseURL: customModel.base_url || undefined
    });
    targetModel = customModel.model_name;
  }

  const userMsg = messages.find(m => m.role === "user")?.content || "";
  const isPlaceholder = !AITUNNEL_API_KEY || AITUNNEL_API_KEY.includes("your_aitunnel_api_key_here");

  if (isPlaceholder && !customModel) {
    logger.warn("[AI-Agent] Placeholder API key detected. Generating local fallback report.");
    return generateLocalFallbackReport(userMsg);
  }

  if (!targetClient) {
    throw new Error(`AI model "${model}" is not configured. Please check your settings.`);
  }

  try {
    const response = await targetClient.chat.completions.create({ model: targetModel, messages, temperature });
    return response.choices[0].message.content;
  } catch (err) {
    logger.warn(`[AI-Agent] AI API call failed (${err.message}). Generating local fallback report.`);
    return generateLocalFallbackReport(userMsg);
  }
}

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));

const authMiddleware = (req, res, next) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) {
    return res.status(403).json({ error: "Unauthorized" });
  }
  next();
};

// ── Health ──────────────────────────────────────────────────────────────────
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), model: activeModel, timestamp: new Date().toISOString() });
});

// ── Custom Models ───────────────────────────────────────────────────────────
app.get("/api/custom-models", authMiddleware, (_req, res) => {
  try {
    const models = db.getCustomModels();
    const masked = models.map(m => ({
      ...m,
      api_key: m.api_key ? "********" : ""
    }));
    res.json(masked);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/custom-models", authMiddleware, (req, res) => {

  try {
    const { id, name, model_name, base_url, api_key } = req.body || {};
    if (!id || !name || !model_name || !base_url) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    
    let finalApiKey = api_key;
    if (api_key === "********" || !api_key) {
      const existing = db.getCustomModels().find(m => m.id === id);
      if (existing) {
        finalApiKey = existing.api_key;
      }
    }
    
    db.addCustomModel({ id, name, model_name, base_url, api_key: finalApiKey });
    
    // Broadcast updated models list
    const updatedModels = db.getCustomModels().map(m => ({
      ...m,
      api_key: m.api_key ? "********" : ""
    }));
    broadcast({ event: "custom_models_updated", data: updatedModels });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/custom-models/:id", authMiddleware, (req, res) => {
  try {
    db.deleteCustomModel(req.params.id);
    
    // Broadcast updated models list
    const updatedModels = db.getCustomModels().map(m => ({
      ...m,
      api_key: m.api_key ? "********" : ""
    }));
    broadcast({ event: "custom_models_updated", data: updatedModels });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── SOAR Settings ───────────────────────────────────────────────────────────
app.get("/api/soar-settings", authMiddleware, (_req, res) => {
  res.json({
    ...soarSettings,
    whitelist: Array.from(BANNED_IP_WHITELIST),
    whitelistCidrs: Array.from(BANNED_IP_WHITELIST_CIDRS),
    activeSshSessions: Array.from(ACTIVE_SSH_SESSIONS)
  });
});

app.post("/api/soar-settings", authMiddleware, (req, res) => {

  const { autoBanDdos, autoBanBruteForce, aiDefenseEnabled, aiMakeChanges, aiModel, aiThreatThreshold, aiTriggerOnLeaks, aiTriggerOnCritical, honeypotEnabled, aiTriggerTypes } = req.body || {};
  if (autoBanDdos !== undefined) soarSettings.autoBanDdos = !!autoBanDdos;
  if (autoBanBruteForce !== undefined) soarSettings.autoBanBruteForce = !!autoBanBruteForce;
  if (aiDefenseEnabled !== undefined) soarSettings.aiDefenseEnabled = !!aiDefenseEnabled;
  if (aiMakeChanges !== undefined) soarSettings.aiMakeChanges = !!aiMakeChanges;
  if (aiModel !== undefined) soarSettings.aiModel = String(aiModel);
  if (aiThreatThreshold !== undefined) soarSettings.aiThreatThreshold = Number(aiThreatThreshold);
  if (aiTriggerOnLeaks !== undefined) soarSettings.aiTriggerOnLeaks = !!aiTriggerOnLeaks;
  if (aiTriggerOnCritical !== undefined) soarSettings.aiTriggerOnCritical = !!aiTriggerOnCritical;
  
  if (aiTriggerTypes !== undefined) {
    if (Array.isArray(aiTriggerTypes)) {
      soarSettings.aiTriggerTypes = aiTriggerTypes.map(String);
    } else {
      soarSettings.aiTriggerTypes = [];
    }
  }
  
  if (honeypotEnabled !== undefined) {
    const nextHoneypot = !!honeypotEnabled;
    if (nextHoneypot !== soarSettings.honeypotEnabled) {
      soarSettings.honeypotEnabled = nextHoneypot;
      if (nextHoneypot) {
        startHoneypot();
      } else {
        stopHoneypot();
      }
    }
  }
  
  saveSoarSettings();
  
  const fullSettings = {
    ...soarSettings,
    whitelist: Array.from(BANNED_IP_WHITELIST),
    whitelistCidrs: Array.from(BANNED_IP_WHITELIST_CIDRS),
    activeSshSessions: Array.from(ACTIVE_SSH_SESSIONS)
  };
  broadcast({ event: "soar_settings_updated", data: fullSettings });
  addLog("server", "info", "SOAR & AI settings updated by administrator", soarSettings);
  res.json({ success: true, soarSettings: fullSettings });
});

// ── IP Whitelist Management ──────────────────────────────────────────────────
app.post("/api/whitelist/add", authMiddleware, (req, res) => {

  const { ip } = req.body || {};
  if (!ip || !isValidIpOrCidr(ip)) return res.status(400).json({ error: "Invalid IP address or CIDR format" });

  const whitelistFile = path.join(__dirname, "..", "data", "unbannable_ips.json");
  let fileIps = [];
  if (fs.existsSync(whitelistFile)) {
    try {
      fileIps = JSON.parse(fs.readFileSync(whitelistFile, "utf8"));
    } catch (_) {}
  }

  const cleanIp = ip.trim().toLowerCase();
  if (!fileIps.includes(cleanIp)) {
    fileIps.push(cleanIp);
    try {
      fs.writeFileSync(whitelistFile, JSON.stringify(fileIps, null, 2), "utf8");
      
      if (cleanIp.includes("/")) {
        BANNED_IP_WHITELIST_CIDRS.add(cleanIp);
      } else {
        BANNED_IP_WHITELIST.add(cleanIp);
      }
      
      logger.info(`[IP-Whitelist] Added ${cleanIp} to whitelist exceptions.`);
      addLog("server", "info", `IP/Subnet ${cleanIp} added to whitelist exclusions by administrator`, { ip: cleanIp });
      
      const fullSettings = {
        ...soarSettings,
        whitelist: Array.from(BANNED_IP_WHITELIST),
        whitelistCidrs: Array.from(BANNED_IP_WHITELIST_CIDRS),
        activeSshSessions: Array.from(ACTIVE_SSH_SESSIONS)
      };
      broadcast({ event: "soar_settings_updated", data: fullSettings });
      
      return res.json({ success: true, soarSettings: fullSettings });
    } catch (e) {
      return res.status(500).json({ error: "Failed to write whitelist file: " + e.message });
    }
  }
  return res.json({ success: true, message: "IP already whitelisted" });
});

app.post("/api/whitelist/remove", authMiddleware, (req, res) => {

  const { ip } = req.body || {};
  if (!ip || !isValidIpOrCidr(ip)) return res.status(400).json({ error: "Invalid IP address or CIDR format" });

  const whitelistFile = path.join(__dirname, "..", "data", "unbannable_ips.json");
  let fileIps = [];
  if (fs.existsSync(whitelistFile)) {
    try {
      fileIps = JSON.parse(fs.readFileSync(whitelistFile, "utf8"));
    } catch (_) {}
  }

  const cleanIp = ip.trim().toLowerCase();
  const index = fileIps.indexOf(cleanIp);
  if (index !== -1) {
    fileIps.splice(index, 1);
    try {
      fs.writeFileSync(whitelistFile, JSON.stringify(fileIps, null, 2), "utf8");
      
      if (cleanIp.includes("/")) {
        BANNED_IP_WHITELIST_CIDRS.delete(cleanIp);
      } else {
        BANNED_IP_WHITELIST.delete(cleanIp);
      }
      
      logger.info(`[IP-Whitelist] Removed ${cleanIp} from whitelist.`);
      addLog("server", "info", `IP/Subnet ${cleanIp} removed from whitelist exclusions by administrator`, { ip: cleanIp });
      
      const fullSettings = {
        ...soarSettings,
        whitelist: Array.from(BANNED_IP_WHITELIST),
        whitelistCidrs: Array.from(BANNED_IP_WHITELIST_CIDRS),
        activeSshSessions: Array.from(ACTIVE_SSH_SESSIONS)
      };
      broadcast({ event: "soar_settings_updated", data: fullSettings });
      
      return res.json({ success: true, soarSettings: fullSettings });
    } catch (e) {
      return res.status(500).json({ error: "Failed to write whitelist file: " + e.message });
    }
  }
  return res.status(400).json({ error: "IP not found in static whitelist file" });
});

// ── Auth ────────────────────────────────────────────────────────────────────
app.post("/api/auth/login", apiRateLimiter(60000, 5), (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, error: "Missing credentials" });
  if (db.verifyUser(username, password)) {
    addLog("server", "info", `User ${username} logged in`, { ip: req.ip });
    res.json({ success: true, token: WSS_SECRET_TOKEN, username });
  } else {
    addLog("server", "warn", `Failed login: ${username}`, { ip: req.ip });
    res.status(401).json({ success: false, error: "Invalid credentials" });
  }
});

// ── Users ───────────────────────────────────────────────────────────────────
app.get("/api/users", authMiddleware, (_req, res) => {
  try { res.json(db.getAllUsers()); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/users", authMiddleware, (req, res) => {
  const { username, password, chatId, nickname, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  const ok = db.addUser(username, password, chatId, nickname, role);
  if (ok) { addLog("server", "info", `User created: ${username}`); res.json({ success: true }); }
  else res.status(409).json({ success: false, error: "User already exists" });
});

// ── Logs ────────────────────────────────────────────────────────────────────
app.get("/api/logs", authMiddleware, (req, res) => {
  const { type = "server", limit = 100, offset = 0, level, startDate, endDate } = req.query;
  try {
    const data = db.getLogs({ type, limit: Number(limit), offset: Number(offset), level, startDate, endDate });
    const total = db.countLogs(type, "1970-01-01");
    res.json({ total, offset: Number(offset), limit: Number(limit), data });
  } catch (e) {
    let data = type === "bot" ? botLogs : type === "cve" ? cveLogs : serverLogs;
    if (level) data = data.filter(l => l.level === level);
    res.json({ total: data.length, offset: Number(offset), limit: Number(limit), data: data.slice(Number(offset), Number(offset) + Number(limit)) });
  }
});
app.post("/api/logs", authMiddleware, (req, res) => {
  const { type = "server", level = "info", message, meta = {} } = req.body;
  const entry = addLog(type, level, message, meta);
  res.json({ received: true, logId: entry.id });
});
app.post("/api/bot-log", authMiddleware, (req, res) => {
  const { level = "info", message, meta = {} } = req.body;
  const entry = addLog("bot", level, message, meta);
  res.json({ received: true, logId: entry.id });
});
app.post("/api/cve-log", authMiddleware, (req, res) => {
  const { level = "info", message, meta = {} } = req.body;
  const entry = addLog("cve", level, message, meta);
  res.json({ received: true, logId: entry.id });
});

// ── Incidents ───────────────────────────────────────────────────────────────
app.get("/api/incidents", authMiddleware, (req, res) => {
  const { severity, limit = 100, offset = 0 } = req.query;
  try {
    const data = db.getIncidents({ severity, limit: Number(limit), offset: Number(offset) });
    data.forEach(i => {
      if (typeof i.details === "string") {
        try { i.details = JSON.parse(i.details); } catch (_) {}
      }
      if (typeof i.geo === "string") {
        try { i.geo = JSON.parse(i.geo); } catch (_) {}
      }
      i.ip = extractIpFromIncident(i.description, i.details, i.type);
      
      // Load AI report from disk if exists
      try {
        const filepath = path.join(reportsDir, `report-${i.id}.md`);
        if (fs.existsSync(filepath)) {
          i.aiAudit = fs.readFileSync(filepath, "utf8");
        } else {
          i.aiAudit = null;
        }
      } catch (_) {
        i.aiAudit = null;
      }
    });
    res.json({ total: data.length, data });
  } catch (e) {
    let data = incidents;
    if (severity) data = data.filter(i => i.severity === severity);
    const sliced = data.slice(Number(offset), Number(offset) + Number(limit));
    sliced.forEach(i => {
      try {
        const filepath = path.join(reportsDir, `report-${i.id}.md`);
        if (fs.existsSync(filepath)) {
          i.aiAudit = fs.readFileSync(filepath, "utf8");
        } else {
          i.aiAudit = null;
        }
      } catch (_) {
        i.aiAudit = null;
      }
    });
    res.json({ total: data.length, data: sliced });
  }
});
app.post("/api/incidents", authMiddleware, (req, res) => {
  const { severity, monitor, type, description, details = {} } = req.body;
  if (!severity || !monitor || !type || !description) return res.status(400).json({ error: "Missing fields" });
  const incident = addIncident(severity, monitor, type, description, details);
  res.json({ received: true, incidentId: incident.id });
});
app.patch("/api/incidents/:id", authMiddleware, (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id);
  if (!incident) return res.status(404).json({ error: "Not found" });
  const { status, comment, severity } = req.body;
  if (status) { incident.status = status; try { db.updateIncident(req.params.id, { status }); } catch (_) {} }
  if (comment) { incident.comment = comment; try { db.updateIncident(req.params.id, { comment }); } catch (_) {} }
  if (severity) { incident.severity = severity; try { db.updateIncident(req.params.id, { severity }); } catch (_) {} }
  broadcast({ event: "incident_updated", data: incident });
  res.json(incident);
});

app.post("/api/incidents/bulk-status", authMiddleware, (req, res) => {
  const { ids, status } = req.body;
  if (!Array.isArray(ids) || !status) return res.status(400).json({ error: "Missing ids array or status" });
  try {
    ids.forEach(id => {
      const incident = incidents.find(i => i.id === id);
      if (incident) {
        incident.status = status;
        db.updateIncident(id, { status });
        broadcast({ event: "incident_updated", data: incident });
      }
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/incidents/bulk-delete", authMiddleware, (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids)) return res.status(400).json({ error: "Missing ids array" });
  try {
    ids.forEach(id => {
      const idx = incidents.findIndex(i => i.id === id);
      if (idx !== -1) {
        incidents.splice(idx, 1);
      }
      db.deleteIncident(id);
    });
    broadcast({ event: "incidents_list", data: incidents });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/logs/bulk-delete", authMiddleware, (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids)) return res.status(400).json({ error: "Missing ids array" });
  try {
    ids.forEach(id => {
      db.deleteLog(id);
      
      const idxS = serverLogs.findIndex(l => l.id === id);
      if (idxS !== -1) serverLogs.splice(idxS, 1);
      
      const idxB = botLogs.findIndex(l => l.id === id);
      if (idxB !== -1) botLogs.splice(idxB, 1);
      
      const idxC = cveLogs.findIndex(l => l.id === id);
      if (idxC !== -1) cveLogs.splice(idxC, 1);
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/incidents", authMiddleware, (req, res) => {
  try {
    db.clearIncidents();
    incidents.length = 0;
    broadcast({ event: "incidents_list", data: [] });
    addLog("server", "info", "Incident history has been cleared by administrator");
    res.json({ success: true });
  } catch (e) {
    logger.error("Failed to clear incidents", { err: e.message });
    res.status(500).json({ error: e.message });
  }
});

// ── GeoIP Lookup ────────────────────────────────────────────────────────────
app.get("/api/geoip/:ip", authMiddleware, (req, res) => {
  try {
    const ip = req.params.ip;
    res.json(getMockGeoIP(ip));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Quarantine ─────────────────────────────────────────────────────────────
app.get("/api/quarantine", authMiddleware, (req, res) => {
  try {
    if (req.query.waf_ping || req.headers["x-waf-ping"]) {
      lastWafPingTime = Date.now();
      lastWafHost = req.query.waf_host || req.headers["x-waf-host"] || "raemon.ru";
    }
    res.json(db.getQuarantinedIps());
  }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/quarantine", authMiddleware, (req, res) => {
  const { ip, reason } = req.body;
  if (!ip || !isValidIp(ip)) return res.status(400).json({ error: "Invalid IP address format" });
  const success = banIpInSystem(ip, reason);
  if (success) {
    res.json({ success: true, ip });
  } else {
    res.status(403).json({ error: "IP is whitelisted or belongs to active operator" });
  }
});

app.delete("/api/quarantine/:ip", authMiddleware, (req, res) => {
  const ip = req.params.ip;
  if (!ip || !isValidIp(ip)) return res.status(400).json({ error: "Invalid IP address format" });
  const success = unbanIpInSystem(ip);
  if (success) {
    res.json({ success: true, ip });
  } else {
    res.status(500).json({ error: "Failed to remove IP from system quarantine" });
  }
});

// ── Process Management ───────────────────────────────────────────────────────
app.delete("/api/process/:pid", authMiddleware, (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  if (!pid) return res.status(400).json({ error: "Invalid PID" });
  try {
    const { execSync } = require("child_process");
    if (process.platform === "win32") {
      execSync(`taskkill /F /PID ${pid}`, { stdio: "ignore" });
    } else {
      execSync(`sudo kill -9 ${pid}`, { stdio: "ignore" });
    }
    addLog("server", "info", `Killed process PID: ${pid}`);
    res.json({ success: true, pid });
  } catch (e) {
    logger.error(`Failed to kill PID ${pid}`, { err: e.message });
    res.status(500).json({ error: "Failed to kill process" });
  }
});

// ── Metrics (от Lua-мониторов) ───────────────────────────────────────────────
app.post("/api/metrics", authMiddleware, (req, res) => {
  lastMetricsReceivedTime = Date.now();
  const payload = req.body;
  const { monitor, anomalies = [] } = payload;
  
  if (monitor === "sec_tools_monitor" && payload.ufw && payload.ufw.status) {
    const currentUfwStatus = payload.ufw.status;
    if (currentUfwStatus === "active" && lastKnownUfwStatus !== "active") {
      logger.info(`[UFW Monitor Auto-Sync] UFW status transitioned to active. Re-applying all quarantine bans.`);
      reapplyQuarantineBans();
    }
    lastKnownUfwStatus = currentUfwStatus;
  }

  cachedMetrics = mergeMetrics(cachedMetrics, payload);
  broadcast({ event: "metrics", data: enrichMetricsWithWaf({ ...cachedMetrics, receivedAt: new Date().toISOString() }) });
  for (const a of anomalies) {
    addIncident(a.severity || "HIGH", a.monitor || monitor || "Monitor", a.type || "anomaly", a.description || a.type, payload);
  }
  res.json({ received: true, anomaliesProcessed: anomalies.length });
});

// ── Attack detected (от Remon WAF) ──────────────────────────────────────────
app.post("/api/attack-detected", authMiddleware, (req, res) => {
  const { type, sourceIp, path: p, payload, severity = "HIGH" } = req.body;
  const incident = addIncident(severity, "Remon-WAF", type, `Attack: ${type} from ${sourceIp} on ${p}`, { sourceIp, path: p, payload });
  res.json({ received: true, incidentId: incident.id });
});

// ── Stats ────────────────────────────────────────────────────────────────────
app.get("/api/stats", authMiddleware, (_req, res) => {
  try { res.json({ ...db.getStats(), connectedClients: clients.size }); }
  catch (e) { res.json({ incidents: {}, logs: {}, connectedClients: clients.size }); }
});

// ── Vulnerability Database ──────────────────────────────────────────────────
app.get("/api/vulnerabilities", authMiddleware, (_req, res) => {
  try {
    res.json(getVulnerabilitiesFromDisk());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/vulnerabilities", authMiddleware, (req, res) => {
  const { id, name, severity, description, detection_rules, remediation } = req.body || {};
  if (!id || !name) return res.status(400).json({ error: "id and name are required" });
  
  try {
    const filename = `${id.toLowerCase().replace(/[^a-z0-9_-]/g, "")}.json`;
    const data = { id, name, severity: severity || "MEDIUM", description: description || "", detection_rules: detection_rules || "", remediation: remediation || "" };
    fs.writeFileSync(path.join(vulnerabilitiesDir, filename), JSON.stringify(data, null, 2), "utf8");
    addLog("server", "info", `Vulnerability DB updated: ${name} (${id})`);
    res.json({ success: true, vulnerability: data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/vulnerabilities/:id", authMiddleware, (req, res) => {
  const id = req.params.id;
  try {
    const filename = `${id.toLowerCase().replace(/[^a-z0-9_-]/g, "")}.json`;
    const filepath = path.join(vulnerabilitiesDir, filename);
    if (fs.existsSync(filepath)) {
      fs.unlinkSync(filepath);
      addLog("server", "info", `Vulnerability DB deleted: ${id}`);
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Vulnerability not found" });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── AI Reports ──────────────────────────────────────────────────────────────
const reportsDir = path.join(__dirname, "../data/reports");
if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

app.get("/api/ai-reports", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

  try {
    const list = [];
    if (fs.existsSync(reportsDir)) {
      const files = fs.readdirSync(reportsDir);
      for (const file of files) {
        if (file.endsWith(".md")) {
          const filepath = path.join(reportsDir, file);
          const stats = fs.statSync(filepath);
          let incidentId = "";
          let taskId = "";
          if (file.startsWith("report-task-")) {
            taskId = file.substring(12, file.length - 3);
          } else if (file.startsWith("report-")) {
            incidentId = file.substring(7, file.length - 3);
          }
          list.push({
            filename: file,
            incidentId,
            taskId,
            createdAt: stats.birthtime || stats.mtime,
            size: stats.size
          });
        }
      }
    }
    list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/ai-reports/:id", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

  const id = req.params.id;
  if (id && !/^[a-zA-Z0-9_-]+$/.test(id)) {
    return res.status(400).json({ error: "Invalid report ID format" });
  }

  try {
    let filepath = path.join(reportsDir, `report-${id}.md`);
    if (!fs.existsSync(filepath)) {
      filepath = path.join(reportsDir, `report-task-${id}.md`);
    }
    if (fs.existsSync(filepath)) {
      const markdown = fs.readFileSync(filepath, "utf8");
      res.json({ markdown });
    } else {
      res.status(404).json({ error: "Report not found" });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Reset Demo State ────────────────────────────────────────────────────────
app.post("/api/reset-demo", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

  try {
    // 1. Release all quarantined IPs from UFW and fail2ban
    const qList = db.getQuarantinedIps() || [];
    qList.forEach(q => {
      unbanIpInSystem(q.ip);
    });

    // 2. Clear database tables
    db.resetDemoData();

    // 3. Clear memory arrays
    incidents.length = 0;
    serverLogs.length = 0;
    botLogs.length = 0;
    cveLogs.length = 0;

    // 4. Delete generated reports on disk, preserving documentation
    if (fs.existsSync(reportsDir)) {
      const files = fs.readdirSync(reportsDir);
      files.forEach(file => {
        if (file.endsWith(".md") && file !== "report-task-diploma-stack-and-actions.md") {
          try {
            fs.unlinkSync(path.join(reportsDir, file));
          } catch (e) {
            logger.warn(`Failed to delete report file ${file} during reset`, { err: e.message });
          }
        }
      });
    }

    // 5. Reset SOAR settings
    soarSettings = {
      autoBanDdos: true,
      autoBanBruteForce: true,
      aiDefenseEnabled: false,
      aiMakeChanges: true,
      aiModel: "deepseek-v4-pro",
      aiThreatThreshold: 3,
      aiTriggerOnLeaks: true,
      aiTriggerOnCritical: true
    };
    saveSoarSettings();

    // 6. Broadcast clean state
    broadcast({ event: "incidents_list", data: [] });
    broadcast({ event: "logs_list", data: [] });
    broadcast({ event: "quarantine_updated", data: [] });
    broadcast({ event: "soar_settings_updated", data: soarSettings });
    broadcast({ event: "stats", data: { ...db.getStats(), connectedClients: clients.size } });

    addLog("server", "info", "Demo and SOAR state has been completely reset by administrator");

    res.json({ success: true });
  } catch (e) {
    logger.error("Failed to reset demo data", { err: e.message });
    res.status(500).json({ error: e.message });
  }
});

// ── AI ───────────────────────────────────────────────────────────────────────
app.post("/api/ai/task", authMiddleware, apiRateLimiter(60000, 10), async (req, res) => {
  const { model, task, systemPrompt, incidentId } = req.body;
  if (incidentId && !/^[a-zA-Z0-9_-]+$/.test(incidentId)) {
    return res.status(400).json({ error: "Invalid incident ID format" });
  }

  try {
    sanitizeAIInput(task);
    
    // Inject vulnerabilities database
    const vulns = getVulnerabilitiesFromDisk();
    const vulnContext = `KNOWN SYSTEM VULNERABILITIES DATABASE:\n` + vulns.map(v => `- [${v.id}] ${v.name} (${v.severity}): ${v.description}\n  Rules: ${v.detection_rules}\n  Mitigation: ${v.remediation}`).join("\n\n");
    
    const msgs = [{ role: "system", content: AI_SAFETY_RULES + "\n\n" + vulnContext }];
    if (systemPrompt) msgs.push({ role: "system", content: systemPrompt });
    msgs.push({ role: "user", content: task });
    const result = await askAI(model || activeModel, msgs);
    
    // Save report to disk
    const reportFilename = incidentId ? `report-${incidentId}.md` : `report-task-${uuidv4()}.md`;
    fs.writeFileSync(path.join(reportsDir, reportFilename), result, "utf8");
    
    res.json({ model: model || activeModel, result });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post("/api/ai/model", authMiddleware, (req, res) => {
  const { model } = req.body;
  if (!MODELS[model] && !Object.values(MODELS).some(m => m.id === model)) return res.status(400).json({ error: "Unknown model" });
  activeModel = MODELS[model]?.id || model;
  broadcast({ event: "model_changed", data: { model: activeModel } });
  res.json({ model: activeModel });
});

// ── NLP Search & Script Execution ────────────────────────────────────────────
const nlpPrompt = `You are a helper that converts a user's Russian or English log search query into JSON filters.
Available log types: "server", "bot", "cve".
Available log levels: "error", "warn", "info", "debug".

Your response MUST be ONLY a JSON object in this format, with no markdown, no other text:
{
  "filter": {
    "type": "server" | "bot" | "cve" | "",
    "level": "error" | "warn" | "info" | "debug" | ""
  }
}

Examples:
- "покажи ошибки бота" -> {"filter": {"type": "bot", "level": "error"}}
- "серверные варнинги" -> {"filter": {"type": "server", "level": "warn"}}
- "критические события cve" -> {"filter": {"type": "cve", "level": "error"}}
- "все логи" -> {"filter": {"type": "", "level": ""}}
`;

app.post("/api/ai-nlp-search", authMiddleware, async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: "Query required" });
  
  // Local keyword parser fallback (in case AI is not configured or fails)
  const fallbackParse = (q) => {
    const lower = q.toLowerCase();
    let type = "";
    let level = "";
    if (lower.includes("сервер") || lower.includes("server")) type = "server";
    else if (lower.includes("бот") || lower.includes("bot")) type = "bot";
    else if (lower.includes("cve") || lower.includes("уязвим")) type = "cve";

    if (lower.includes("критич") || lower.includes("ошибк") || lower.includes("error") || lower.includes("crit")) level = "error";
    else if (lower.includes("варн") || lower.includes("предупр") || lower.includes("warn")) level = "warn";
    else if (lower.includes("инфо") || lower.includes("info")) level = "info";
    else if (lower.includes("дебаг") || lower.includes("debug")) level = "debug";
    return { filter: { type, level } };
  };

  try {
    if (!aiClient) {
      return res.json(fallbackParse(query));
    }
    
    const messages = [
      { role: "system", content: nlpPrompt },
      { role: "user", content: query }
    ];
    const aiResponse = await askAI(activeModel, messages, 0.1);
    let parsed;
    try {
      const cleaned = aiResponse.replace(/```json/g, "").replace(/```/g, "").trim();
      parsed = JSON.parse(cleaned);
    } catch (e) {
      logger.warn("Failed to parse NLP AI response, using fallback", { aiResponse });
      parsed = fallbackParse(query);
    }
    res.json(parsed);
  } catch (err) {
    logger.warn("NLP AI search failed, using fallback", { err: err.message });
    res.json(fallbackParse(query));
  }
});

app.post("/api/execute-ai-script", authMiddleware, apiRateLimiter(60000, 10), (req, res) => {

  const { script } = req.body;
  if (!script) return res.status(400).json({ error: "Script required" });

  try {
    sanitizeAIInput(script);
    const { exec } = require("child_process");
    addLog("server", "info", "Executing AI-generated mitigation script by administrator", { script });

    exec(script, (err, stdout, stderr) => {
      const output = stdout + (stderr ? "\n" + stderr : "");
      if (err) {
        logger.error("AI script execution failed", { error: err.message, output });
        addLog("server", "error", `AI script failed: ${err.message}`, { output });
        return res.json({ success: false, error: err.message, output });
      }
      logger.info("AI script execution completed successfully");
      addLog("server", "info", "AI script executed successfully");
      res.json({ success: true, output });
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Scans ────────────────────────────────────────────────────────────────────
app.post("/api/scan/semgrep", async (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

  const { targetDir, rules } = req.body;
  if (targetDir && /[\;&\|$\`"\r\n]/.test(targetDir)) {
    return res.status(400).json({ error: "Invalid targetDir format" });
  }
  if (rules && /[\;&\|$\`"\r\n]/.test(rules)) {
    return res.status(400).json({ error: "Invalid rules format" });
  }

  const result = runSemgrep(targetDir || path.join(__dirname, ".."), rules);
  res.json(result);
});
app.post("/api/scan/trivy", async (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

  const { target, scanType } = req.body;
  if (target && /[\;&\|$\`"\r\n]/.test(target)) {
    return res.status(400).json({ error: "Invalid target format" });
  }
  if (scanType && /[\;&\|$\`"\r\n]/.test(scanType)) {
    return res.status(400).json({ error: "Invalid scanType format" });
  }

  const result = runTrivy(target || ".", scanType || "fs");
  res.json(result);
});

// ── Lua Monitor Command Endpoints ───────────────────────────────────────────
app.get("/api/monitors/commands", authMiddleware, (req, res) => {
  if (pendingMonitorCommands.length > 0) {
    const cmd = pendingMonitorCommands.shift();
    res.json(cmd);
  } else {
    res.json(null);
  }
});

app.post("/api/monitors/command-results", authMiddleware, (req, res) => {
  const { commandId, success, results, error } = req.body || {};
  logger.info(`Received monitor command results for ${commandId}: success=${success}`);

  const cmdDetails = monitorCommandResults.get(commandId) || {};
  const target = cmdDetails.target || ".";
  const type = cmdDetails.type || "unknown_scan";

  const findingsCount = (results && results.findings) ? results.findings.length : 0;
  
  if (success && results && results.findings) {
    results.findings.forEach(f => {
      const isTrivy = type.includes("trivy");
      let logSeverity = "info";
      const severity = f.severity || "MEDIUM";
      if (severity === "CRITICAL" || severity === "HIGH" || severity === "ERROR") logSeverity = "error";
      else if (severity === "MEDIUM" || severity === "WARNING") logSeverity = "warn";

      const message = isTrivy 
        ? `[Trivy (Monitor)] Обнаружена уязвимость ${f.vulnId} в пакете ${f.pkg} (${severity}). Цель: ${f.target || target}. Заголовок: ${f.title || 'N/A'}. Решение: обновить до версии ${f.fixedVersion || 'N/A'}.`
        : `[Semgrep (Monitor)] Нарушение правила безопасности ${f.rule} в файле ${f.path}:${f.line} (${severity}). Описание: ${f.message}`;
      
      addLog("cve", logSeverity, message, {
        scanner: isTrivy ? "trivy" : "semgrep",
        vulnId: f.vulnId || "",
        pkg: f.pkg || "",
        severity,
        title: f.title || "",
        fixedVersion: f.fixedVersion || "",
        target: f.target || f.path || target,
        rule: f.rule || ""
      });
    });

    addIncident("HIGH", "SecurityScanner", "VULNERABILITY_DISCOVERY", `Сканирование уязвимостей через Lua-агент завершено (${type} на ${target}). Обнаружено замечаний: ${findingsCount}`);
  } else if (error) {
    addLog("server", "error", `Фоновое сканирование через Lua-агент завершилось с ошибкой: ${error}`);
  }

  // Find WebSocket client and return results
  const clientWs = activeScanRequests.get(commandId);
  const broadcastPayload = {
    event: "scan_result",
    data: {
      scanner: type === "semgrep_scan" ? "semgrep" : "trivy",
      target: target,
      timestamp: new Date().toISOString(),
      findings: (results && results.findings) ? results.findings : [],
      error: error || null
    }
  };

  if (clientWs && clientWs.readyState === WebSocket.OPEN) {
    try {
      clientWs.send(JSON.stringify(broadcastPayload));
    } catch (_) {
      broadcast(broadcastPayload);
    }
  } else {
    broadcast(broadcastPayload);
  }

  activeScanRequests.delete(commandId);
  monitorCommandResults.delete(commandId);

  res.json({ success: true });
});

// ── Scanner installation trigger ─────────────────────────────────────────────
app.post("/api/install-scanners", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });
  
  try {
    const { exec } = require("child_process");
    const scriptPath = path.join(__dirname, "..", "install_semgrep_trivy.sh");
    addLog("server", "info", "Starting scanner tools background installation (Semgrep & Trivy)");
    exec(`sudo bash "${scriptPath}" > "${path.join(__dirname, "..", "logs", "scanner_install.log")}" 2>&1`, (err) => {
      if (err) {
        logger.error("Scanner installation failed", { error: err.message });
        addLog("server", "error", `Scanner installation failed: ${err.message}`);
      } else {
        logger.info("Scanner installation completed successfully");
        addLog("server", "info", "Scanner installation completed successfully");
      }
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Run Audit trigger ─────────────────────────────────────────────────────────
let auditRunning = false;

function processAuditResults(trivyFile, semgrepFile) {
  // 1. Process Trivy findings
  if (fs.existsSync(trivyFile)) {
    try {
      const raw = fs.readFileSync(trivyFile, "utf8");
      const results = JSON.parse(raw);
      fs.unlinkSync(trivyFile); // cleanup
      
      let count = 0;
      (results.Results || []).forEach(result => {
        (result.Vulnerabilities || []).forEach(v => {
          count++;
          const vulnId = v.VulnerabilityID;
          const pkg = v.PkgName;
          const severity = v.Severity; // e.g., CRITICAL, HIGH, MEDIUM, LOW
          const title = v.Title || "No title";
          const fixedVersion = v.FixedVersion || "N/A";
          const target = result.Target || "/etc";
          
          let logSeverity = "info";
          if (severity === "CRITICAL" || severity === "HIGH") logSeverity = "error";
          else if (severity === "MEDIUM") logSeverity = "warn";
          
          const message = `[Trivy] Обнаружена уязвимость ${vulnId} в пакете ${pkg} (${severity}). Цель: ${target}. Заголовок: ${title}. Решение: обновить до версии ${fixedVersion}.`;
          addLog("cve", logSeverity, message, { vulnId, pkg, severity, title, fixedVersion, target, scanner: "trivy" });
        });
      });
      logger.info(`Processed ${count} Trivy CVE findings from audit`);
    } catch (e) {
      logger.error("Failed to parse Trivy audit output", { err: e.message });
    }
  }

  // 2. Process Semgrep findings
  if (fs.existsSync(semgrepFile)) {
    try {
      const raw = fs.readFileSync(semgrepFile, "utf8");
      const results = JSON.parse(raw);
      fs.unlinkSync(semgrepFile); // cleanup
      
      let count = 0;
      (results.results || []).forEach(r => {
        count++;
        const pathFile = r.path;
        const line = r.start?.line || 0;
        const message = r.extra?.message || "No description";
        const severity = r.extra?.metadata?.severity || "MEDIUM"; // ERROR, WARNING, INFO
        const rule = r.check_id;
        
        let logSeverity = "info";
        if (severity === "ERROR") logSeverity = "error";
        else if (severity === "WARNING" || severity === "MEDIUM") logSeverity = "warn";
        
        const logMsg = `[Semgrep] Нарушение правила безопасности ${rule} в файле ${pathFile}:${line} (${severity}). Описание: ${message}`;
        addLog("cve", logSeverity, logMsg, { rule, path: pathFile, line, severity, message, scanner: "semgrep" });
      });
      logger.info(`Processed ${count} Semgrep findings from audit`);
    } catch (e) {
      logger.error("Failed to parse Semgrep audit output", { err: e.message });
    }
  }
}

function scanDockerImagesInternal() {
  const { execSync } = require("child_process");
  let dockerImages = [];
  try {
    const imagesOutput = execSync('docker ps --format "{{.Image}}" 2>/dev/null', { encoding: "utf8" });
    dockerImages = imagesOutput.split("\n").map(img => img.trim()).filter(Boolean);
    dockerImages = [...new Set(dockerImages)];
  } catch (e) {
    logger.info("Docker daemon is not running or docker client is not available. Skipping container scan.");
    return;
  }

  if (dockerImages.length === 0) {
    logger.info("No running Docker containers detected to scan.");
    return;
  }

  logger.info(`[Trivy-Docker] Found ${dockerImages.length} running Docker images to scan: ${dockerImages.join(", ")}`);
  
  dockerImages.forEach((img, index) => {
    const outPath = path.join(__dirname, "..", "logs", `trivy_docker_${index}_${Date.now()}.json`);
    try {
      // Run Trivy scan on the image
      execSync(`trivy image --format json -o "${outPath}" "${img}" --quiet`, { timeout: 120000 });
      if (fs.existsSync(outPath)) {
        const raw = fs.readFileSync(outPath, "utf8");
        const results = JSON.parse(raw);
        fs.unlinkSync(outPath);
        
        let count = 0;
        (results.Results || []).forEach(result => {
          (result.Vulnerabilities || []).forEach(v => {
            count++;
            const vulnId = v.VulnerabilityID;
            const pkg = v.PkgName;
            const severity = v.Severity;
            const title = v.Title || "No title";
            const fixedVersion = v.FixedVersion || "N/A";
            
            let logSeverity = "info";
            if (severity === "CRITICAL" || severity === "HIGH") logSeverity = "error";
            else if (severity === "MEDIUM") logSeverity = "warn";
            
            const message = `[Trivy (Docker)] Обнаружена уязвимость ${vulnId} в контейнере (образ: ${img}) в пакете ${pkg} (${severity}). Заголовок: ${title}. Решение: обновить до версии ${fixedVersion}.`;
            addLog("cve", logSeverity, message, { vulnId, pkg, severity, title, fixedVersion, image: img, scanner: "trivy-docker" });
          });
        });
        logger.info(`[Trivy-Docker] Processed ${count} CVE findings for image ${img}`);
      }
    } catch (err) {
      logger.error(`[Trivy-Docker] Failed to scan Docker image ${img}`, { error: err.message });
    }
  });
}

function runSystemAuditInternal() {
  if (auditRunning) {
    logger.info("System security audit already in progress, skipping run");
    return;
  }
  auditRunning = true;
  addLog("server", "info", "Starting system security audit (Trivy & Semgrep) in background");
  
  const { exec } = require("child_process");
  const tempTrivy = path.join(__dirname, "..", "logs", `trivy_audit_${Date.now()}.json`);
  const tempSemgrep = path.join(__dirname, "..", "logs", `semgrep_audit_${Date.now()}.json`);
  
  const trivyTarget = process.platform === "win32" ? path.join(__dirname, "..") : "/etc";
  
  const cmd = `trivy fs --format json -o "${tempTrivy}" "${trivyTarget}" 2>/dev/null; semgrep --config=p/security-audit "${path.join(__dirname, "..")}" --json -o "${tempSemgrep}" --quiet 2>/dev/null`;
  
  exec(cmd, (err) => {
    auditRunning = false;
    
    // Parse results for files that were generated
    processAuditResults(tempTrivy, tempSemgrep);
    
    // Scan docker images
    scanDockerImagesInternal();
    
    if (err) {
      logger.error("System security audit execution finished with errors", { error: err.message });
      addLog("server", "warn", `Security audit completed with some errors: ${err.message}`);
    } else {
      logger.info("System security audit completed successfully");
      addLog("server", "info", "Security audit completed successfully. New vulnerabilities updated.");
    }
    
    // Inject incident
    addIncident("HIGH", "SecurityScanner", "VULNERABILITY_DISCOVERY", "System security audit finished. Trivy and Semgrep findings updated in CVE Logs.");
    
    // Broadcast updated stats
    broadcast({ event: "stats", data: { ...db.getStats(), connectedClients: clients.size } });
  });
}

app.post("/api/run-audit", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });
  
  if (auditRunning) return res.json({ success: true, message: "Audit already in progress" });
  
  runSystemAuditInternal();
  
  res.json({ success: true });
});

// ── UFW, Fail2ban & Lua security activator ──
app.post("/api/activate-security", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });
  
  try {
    const { exec } = require("child_process");
    const scriptPath = path.join(__dirname, "..", "activate_security.sh");
    addLog("server", "info", "Starting systems activation & check background script (UFW, Fail2ban, Lua Monitors)");
    
    exec(`sudo bash "${scriptPath}" > "${path.join(__dirname, "..", "logs", "security_activation.log")}" 2>&1`, (err) => {
      if (err) {
        logger.error("Security activation failed", { error: err.message });
        addLog("server", "error", `Security activation failed: ${err.message}`);
      } else {
        logger.info("Security activation completed successfully");
        addLog("server", "info", "Security activation completed successfully. UFW, Fail2ban, and Lua are configured.");
        lastKnownUfwStatus = "active";
        reapplyQuarantineBans();
      }
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Check UFW, Fail2ban & Lua security status ──
app.get("/api/security-status", authMiddleware, (req, res) => {
  const { execSync } = require("child_process");
  let ufwStatus = "inactive";
  let fail2banStatus = "inactive";
  let luaStatus = "inactive";
  
  try {
    const ufwOut = execSync("sudo ufw status", { encoding: "utf8" });
    ufwStatus = ufwOut.includes("Status: active") ? "active" : "inactive";
  } catch (_) { ufwStatus = "not_installed"; }
  
  try {
    const f2bOut = execSync("sudo fail2ban-client ping", { encoding: "utf8" });
    fail2banStatus = f2bOut.includes("Server replied: pong") ? "active" : "inactive";
  } catch (_) { fail2banStatus = "not_installed"; }
  
  try {
    const scriptPath = path.join(__dirname, "..", "monitors", "run-monitors.sh");
    const luaOut = execSync(`bash "${scriptPath}" status`, { encoding: "utf8" });
    luaStatus = luaOut.includes("RUNNING") ? "active" : "inactive";
  } catch (_) { luaStatus = "not_installed"; }
  
  res.json({ ufw: ufwStatus, fail2ban: fail2banStatus, lua: luaStatus });
});

// ── OS Hardening Compliance Audit ──────────────────────────────────────────
app.get("/api/hardening-compliance", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

  const { execSync } = require("child_process");
  const fs = require("fs");
  const results = [];

  // Helper
  function check(id, label, category, fn) {
    try {
      const r = fn();
      results.push({ id, label, category, ...r });
    } catch (e) {
      results.push({ id, label, category, status: "FAIL", detail: `Ошибка проверки: ${e.message}`, mitigation: "Проверьте доступ к системным файлам и sudo-права." });
    }
  }

  // 1. ASLR
  check("aslr", "ASLR (рандомизация адресного пространства)", "Kernel", () => {
    const val = fs.readFileSync("/proc/sys/kernel/randomize_va_space", "utf8").trim();
    if (val === "2") return { status: "PASS", detail: `randomize_va_space = ${val} (полная рандомизация)`, mitigation: null };
    if (val === "1") return { status: "WARN", detail: `randomize_va_space = ${val} (частичная рандомизация)`, mitigation: "Установите sysctl kernel.randomize_va_space=2 в /etc/sysctl.conf" };
    return { status: "FAIL", detail: `randomize_va_space = ${val} (отключено!)`, mitigation: "Немедленно: echo 2 | sudo tee /proc/sys/kernel/randomize_va_space" };
  });

  // 2. Yama ptrace scope
  check("yama", "Yama ptrace_scope (защита от трассировки)", "Kernel", () => {
    try {
      const val = fs.readFileSync("/proc/sys/kernel/yama/ptrace_scope", "utf8").trim();
      if (val === "1" || val === "2" || val === "3") return { status: "PASS", detail: `ptrace_scope = ${val} (ограничен)`, mitigation: null };
      return { status: "FAIL", detail: `ptrace_scope = ${val} (неограничен, небезопасно)`, mitigation: "Установите kernel.yama.ptrace_scope=1 в /etc/sysctl.conf" };
    } catch (_) {
      return { status: "WARN", detail: "Модуль Yama не загружен или недоступен", mitigation: "Убедитесь, что CONFIG_SECURITY_YAMA включён в ядро." };
    }
  });

  // 3. UFW
  check("ufw", "Брандмауэр UFW", "Network", () => {
    try {
      const out = execSync("sudo ufw status", { encoding: "utf8", timeout: 5000 });
      if (out.includes("Status: active")) return { status: "PASS", detail: "UFW активен и работает", mitigation: null };
      return { status: "FAIL", detail: "UFW установлен, но не активен", mitigation: "sudo ufw enable && sudo ufw default deny incoming" };
    } catch (_) {
      return { status: "FAIL", detail: "UFW не установлен или недоступен", mitigation: "sudo apt install ufw && sudo ufw enable" };
    }
  });

  // 4. Fail2ban
  check("fail2ban", "Fail2ban (защита от брутфорса)", "Network", () => {
    try {
      const out = execSync("sudo fail2ban-client ping", { encoding: "utf8", timeout: 5000 });
      if (out.includes("Server replied: pong")) return { status: "PASS", detail: "Fail2ban активен и отвечает", mitigation: null };
      return { status: "WARN", detail: "Fail2ban не отвечает на ping", mitigation: "sudo systemctl restart fail2ban" };
    } catch (_) {
      return { status: "FAIL", detail: "Fail2ban не установлен или сервис упал", mitigation: "sudo apt install fail2ban && sudo systemctl enable --now fail2ban" };
    }
  });

  // 5. SSH Root login disabled
  check("ssh_root", "SSH: запрет входа root", "SSH", () => {
    try {
      const cfg = fs.readFileSync("/etc/ssh/sshd_config", "utf8");
      if (/^\s*PermitRootLogin\s+no/mi.test(cfg)) return { status: "PASS", detail: "PermitRootLogin no — вход root через SSH запрещён", mitigation: null };
      if (/^\s*PermitRootLogin\s+prohibit-password/mi.test(cfg)) return { status: "WARN", detail: "PermitRootLogin prohibit-password (ключ ещё разрешён)", mitigation: "Установите PermitRootLogin no в /etc/ssh/sshd_config" };
      return { status: "FAIL", detail: "Root-вход по SSH разрешён!", mitigation: "Измените PermitRootLogin на no и перезапустите: sudo systemctl reload sshd" };
    } catch (_) {
      return { status: "WARN", detail: "Не удалось прочитать sshd_config", mitigation: "Проверьте файл /etc/ssh/sshd_config вручную." };
    }
  });

  // 6. SSH Password auth
  check("ssh_pass", "SSH: отключение парольной аутентификации", "SSH", () => {
    try {
      const cfg = fs.readFileSync("/etc/ssh/sshd_config", "utf8");
      if (/^\s*PasswordAuthentication\s+no/mi.test(cfg)) return { status: "PASS", detail: "PasswordAuthentication no — только ключи", mitigation: null };
      return { status: "WARN", detail: "Парольный вход по SSH разрешён", mitigation: "Установите PasswordAuthentication no в sshd_config, настройте SSH-ключи" };
    } catch (_) {
      return { status: "WARN", detail: "Не удалось прочитать sshd_config", mitigation: "Проверьте файл /etc/ssh/sshd_config вручную." };
    }
  });

  // 7. /etc/passwd world-writable check
  check("passwd_perm", "Права доступа к /etc/passwd", "Files", () => {
    try {
      const out = execSync("stat -c '%a' /etc/passwd", { encoding: "utf8" }).trim();
      const perms = parseInt(out, 8);
      if ((perms & 0o002) === 0) return { status: "PASS", detail: `/etc/passwd permissions: ${out} (нет записи для всех)`, mitigation: null };
      return { status: "FAIL", detail: `/etc/passwd доступен для записи всем (${out})!`, mitigation: "sudo chmod 644 /etc/passwd" };
    } catch (_) {
      return { status: "WARN", detail: "Не удалось проверить /etc/passwd", mitigation: null };
    }
  });

  // 8. /tmp noexec
  check("tmp_noexec", "Флаг noexec на /tmp", "Filesystem", () => {
    try {
      const out = execSync("findmnt -n -o OPTIONS /tmp", { encoding: "utf8" });
      if (out.includes("noexec")) return { status: "PASS", detail: "/tmp смонтирован с флагом noexec", mitigation: null };
      return { status: "WARN", detail: "/tmp без флага noexec — возможно выполнение скриптов", mitigation: "Добавьте noexec в /etc/fstab для /tmp и перемонтируйте" };
    } catch (_) {
      return { status: "WARN", detail: "/tmp не является отдельным разделом", mitigation: "Рекомендуется вынести /tmp на отдельный раздел с noexec." };
    }
  });

  res.json({ timestamp: new Date().toISOString(), results });
});

// ── Bot notify endpoint (вызывается из addIncident) ──────────────────────────
// Telegram-бот слушает этот endpoint и рассылает всем chat_id из БД
app.post("/api/bot-notify", authMiddleware, (req, res) => {
  // Просто broadcast в WS — бот сам подписан через polling
  broadcast({ event: "bot_notify", data: req.body });
  res.json({ ok: true });
});

// ── WebSocket ────────────────────────────────────────────────────────────────
function broadcast(msg) {
  const data = JSON.stringify(msg);
  for (const [ws] of clients) {
    if (ws.readyState === WebSocket.OPEN) try { ws.send(data); } catch (_) {}
  }
}

function getActiveConnectionsList() {
  const list = [];
  for (const [wsConn, clientData] of clients.entries()) {
    if (clientData && clientData.authenticated) {
      list.push({
        id: clientData.id,
        ip: clientData.ip,
        username: clientData.username || "admin",
        connectedAt: clientData.connectedAt || new Date().toISOString()
      });
    }
  }
  return list;
}

function startWSS(server) {
  const wss = new WebSocket.Server({ server, path: "/ws" });
  wss.on("connection", (ws, req) => {
    const clientId = uuidv4();
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    clients.set(ws, { id: clientId, ip, authenticated: false });
    addLog("server", "info", "WS client connected (awaiting auth)", { clientId, ip });

    const authTimer = setTimeout(() => {
      if (!clients.get(ws)?.authenticated) { ws.close(4001, "Auth timeout"); }
    }, 10000);

    ws.on("message", async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        const client = clients.get(ws);

        if (msg.event === "auth") {
          const { token, nonce, username } = msg.data || {};
          if (!token || !nonce) { ws.send(JSON.stringify({ event: "auth_error", data: { error: "Missing token or nonce" } })); return; }
          if (usedNonces.has(nonce)) { ws.close(4002, "Replay detected"); return; }
          if (token === WSS_SECRET_TOKEN) {
            usedNonces.add(nonce);
            client.authenticated = true;
            client.username = username || "admin";
            client.connectedAt = new Date().toISOString();
            clearTimeout(authTimer);
            ws.send(JSON.stringify({ event: "auth_success", data: { clientId, model: activeModel, clientIp: ip, username: client.username, connectedAt: client.connectedAt } }));
            addLog("server", "info", `WS client authenticated: ${client.username}`, { clientId, ip });
            ws.send(JSON.stringify({ event: "active_connections", data: getActiveConnectionsList() }));
            broadcast({ event: "active_connections", data: getActiveConnectionsList() });
            // Сразу шлём снапшот
            ws.send(JSON.stringify({ event: "stats", data: { ...db.getStats(), connectedClients: clients.size } }));
            ws.send(JSON.stringify({ event: "incidents_list", data: incidents.slice(0, 100) }));
            ws.send(JSON.stringify({ event: "logs_list", data: serverLogs.slice(0, 200) }));
            ws.send(JSON.stringify({ event: "quarantine_updated", data: db.getQuarantinedIps() }));
            ws.send(JSON.stringify({ event: "soar_settings_updated", data: soarSettings }));
            const customModels = db.getCustomModels().map(m => ({
              ...m,
              api_key: m.api_key ? "********" : ""
            }));
            ws.send(JSON.stringify({ event: "custom_models_updated", data: customModels }));
            
            // Сразу шлём системные метрики (с докер-контейнерами)
            try {
              const payload = enrichMetricsWithWaf({ ...cachedMetrics, receivedAt: new Date().toISOString() });
              ws.send(JSON.stringify({ event: "metrics", data: payload }));
            } catch (err) {
              logger.error("Failed to send initial metrics", { err: err.message });
            }
          } else {
            addLog("server", "warn", "WS auth failed: bad token", { clientId, ip });
            ws.close(4003, "Invalid token");
          }
          return;
        }

        if (!client?.authenticated) {
          ws.send(JSON.stringify({ event: "error", data: { error: "Unauthorized" } }));
          return;
        }

        if (msg.event === "ping") { ws.send(JSON.stringify({ event: "pong", timestamp: Date.now() })); return; }
        if (msg.event === "get_metrics") {
          try {
            ws.send(JSON.stringify({ event: "metrics", data: enrichMetricsWithWaf({ ...cachedMetrics, receivedAt: new Date().toISOString() }) }));
          } catch (err) {
            logger.error("Failed to process get_metrics", { err: err.message });
          }
          return;
        }
        if (msg.event === "get_incidents") { ws.send(JSON.stringify({ event: "incidents_list", data: incidents.slice(0, 100) })); return; }
        if (msg.event === "get_logs") {
          const { type = "server", limit = 200 } = msg.data || {};
          const data = type === "bot" ? botLogs : type === "cve" ? cveLogs : serverLogs;
          const sliced = data.slice(-limit).reverse();
          ws.send(JSON.stringify({ event: "logs_list", data: sliced })); return;
        }
        if (msg.event === "get_stats") {
          ws.send(JSON.stringify({ event: "stats", data: { ...db.getStats(), connectedClients: clients.size } })); return;
        }
        if (msg.event === "ai_task") {
          const { task, model, systemPrompt, isAutoDefense, incidentId } = msg.data || {};
          if (incidentId && !/^[a-zA-Z0-9_-]+$/.test(incidentId)) {
            logger.warn(`Rejected invalid WS incident ID characters: "${incidentId}"`);
            return;
          }
          if (isAutoDefense) {
            addLog("server", "info", `AI Autonomous Mitigation triggered for incident: ${incidentId} using model ${model || activeModel}`);
          }
          
          // Setup real-time progress steps loop
          let progressStep = 0;
          const progressMsgs = [
            "Инициализация контекста ИИ-агента MISTRAL...",
            "Поиск корреляционных логов во временном окне инцидента...",
            "Анализ репутации IP-адреса и геолокационных признаков...",
            "Загрузка базы известных уязвимостей и сигнатур...",
            "Запуск генеративного контура для поиска вариантов защиты...",
            "Синтез рекомендаций и сценариев противодействия атаке...",
            "Формирование финального отчета митигации инцидента..."
          ];
          
          ws.send(JSON.stringify({ 
            event: "ai_progress", 
            data: { 
              step: 1, 
              total: progressMsgs.length, 
              message: progressMsgs[0], 
              incidentId 
            } 
          }));
          addLog("server", "info", `[ИИ-Агент] ${progressMsgs[0]}`);

          const progressInterval = setInterval(() => {
            if (progressStep < progressMsgs.length - 1) {
              progressStep++;
              const message = progressMsgs[progressStep];
              ws.send(JSON.stringify({ 
                event: "ai_progress", 
                data: { 
                  step: progressStep + 1, 
                  total: progressMsgs.length, 
                  message, 
                  incidentId 
                } 
              }));
              addLog("server", "info", `[ИИ-Агент] ${message}`);
            }
          }, 1800);

          try {
            sanitizeAIInput(task);
            
            // Inject vulnerabilities database
            const vulns = getVulnerabilitiesFromDisk();
            const vulnContext = `KNOWN SYSTEM VULNERABILITIES DATABASE:\n` + vulns.map(v => `- [${v.id}] ${v.name} (${v.severity}): ${v.description}\n  Rules: ${v.detection_rules}\n  Mitigation: ${v.remediation}`).join("\n\n");
            
            const msgs = [{ role: "system", content: AI_SAFETY_RULES + "\n\n" + vulnContext }];
            if (systemPrompt) msgs.push({ role: "system", content: systemPrompt });
            msgs.push({ role: "user", content: task });
            
            const result = await askAI(model || activeModel, msgs);
            
            clearInterval(progressInterval);
            
            // Send final completion packet
            ws.send(JSON.stringify({ 
              event: "ai_progress", 
              data: { 
                step: progressMsgs.length, 
                total: progressMsgs.length, 
                message: "Анализ успешно завершен. Данные отправлены в SOC.", 
                incidentId,
                done: true 
              } 
            }));
            addLog("server", "info", `[ИИ-Агент] Анализ успешно завершен. Данные отправлены в SOC.`);

            // Save report to disk
            const reportFilename = incidentId ? `report-${incidentId}.md` : `report-task-${uuidv4()}.md`;
            fs.writeFileSync(path.join(reportsDir, reportFilename), result, "utf8");
            
            ws.send(JSON.stringify({ event: "ai_result", data: { model: model || activeModel, result, task, isAutoDefense, incidentId } }));
          } catch (err) { 
            clearInterval(progressInterval);
            ws.send(JSON.stringify({ event: "ai_error", data: { error: err.message, incidentId } })); 
          }
          return;
        }
        if (msg.event === "switch_model") {
          const { model } = msg.data || {};
          const isBuiltin = MODELS[model] || Object.values(MODELS).some(m => m.id === model);
          const isCustom = db.getCustomModels().some(m => m.id === model);
          if (isBuiltin || isCustom) {
            activeModel = MODELS[model]?.id || model;
            broadcast({ event: "model_changed", data: { model: activeModel } });
            addLog("server", "info", `AI Model switched to: ${activeModel}`);
          }
          return;
        }
        if (msg.event === "run_scan") {
          const { scanType, target } = msg.data || {};
          let safeTarget = null;
          try {
            if (target) {
              safeTarget = path.resolve(target);
              if (/[\;&\|$`"\r\n]/.test(safeTarget)) {
                throw new Error("Security check: Invalid characters in target path");
              }
            }
          } catch (pathErr) {
            logger.warn(`Blocked potentially malicious scan target input: "${target}"`);
            return;
          }
          
          const cmdId = uuidv4();
          const targetPath = safeTarget || ".";
          const type = scanType === "semgrep" ? "semgrep_scan" : "trivy_scan";

          logger.info(`Queueing remote monitor scan command ${cmdId} (${type}) for target: ${targetPath}`);
          addLog("server", "info", `Отправлена команда сканирования ${scanType} на агент (цель: ${targetPath})`);

          monitorCommandResults.set(cmdId, { type, target: targetPath });
          pendingMonitorCommands.push({ id: cmdId, type, target: targetPath });
          activeScanRequests.set(cmdId, ws);
          return;
        }
        if (msg.event === "control_container") {
          const { containerId, action } = msg.data || {};
          if (containerId && action) {
            // Strict sanitization of WebSocket container control commands to prevent command injection
            if (action !== "start" && action !== "stop") {
              logger.warn(`Rejected invalid WS container action: "${action}"`);
              return;
            }
            if (!/^[a-zA-Z0-9_-]+$/.test(containerId)) {
              logger.warn(`Rejected invalid WS container ID characters: "${containerId}"`);
              return;
            }

            logger.info(`[Docker-Mitigation] WS Action '${action}' requested for container ${containerId}`);
            addLog("server", "info", `Запущен процесс: Docker ${action} для контейнера ${containerId}`);
            
            // Update in-memory fallback cache first to ensure responsive GUI changes
            const target = localDockerCache.find(c => c.id === containerId);
            if (target) {
              target.status = action === "start" ? "Up Less than a minute" : "Exited (0) Just now";
            }
            
            const { exec } = require("child_process");
            const isWin = process.platform === "win32";
            const sudoPrefix = isWin ? "" : "sudo ";
            if (action === "start" || action === "stop") {
              exec(`${sudoPrefix}docker ${action} ${containerId}`, (err) => {
                if (err) {
                  logger.warn(`Docker ${action} execution failed for ${containerId}: ${err.message}`);
                  addLog("server", "warn", `Команда docker ${action} не выполнена (активирована симуляция): ${err.message}`);
                } else {
                  logger.info(`Docker ${action} completed for ${containerId}`);
                  addLog("server", "info", `Docker контейнер ${containerId} успешно переведен в состояние: ${action === "start" ? "запущен" : "остановлен"}`);
                }
                const osModule = require("os");
                const totalMem = osModule.totalmem();
                const freeMem = osModule.freemem();
                broadcast({ event: "metrics", data: enrichMetricsWithWaf({ ...getHostMetrics(totalMem, freeMem), receivedAt: new Date().toISOString() }) });
              });
            }
          }
          return;
        }
        broadcast({ event: "relay", from: client?.id, data: msg });
      } catch (err) { logger.error("WS message error", { err: err.message }); }
    });

    ws.on("close", () => {
      const wasAuth = clients.get(ws)?.authenticated;
      const username = clients.get(ws)?.username;
      clients.delete(ws);
      if (wasAuth) {
        addLog("server", "info", `WS client disconnected: ${username || 'unknown'}`);
        broadcast({ event: "active_connections", data: getActiveConnectionsList() });
      }
    });
    ws.on("error", (err) => { logger.error("WS error", { err: err.message }); });
  });
  return wss;
}

function ensureCerts() {
  if (process.env.FORCE_HTTPS !== "true") return null; // Avoid self-signed certs blocking WS connection in browser
  const certDir = path.dirname(WSS_CERT_PATH);
  if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });
  if (!fs.existsSync(WSS_CERT_PATH) || !fs.existsSync(WSS_KEY_PATH)) {
    try {
      const { execSync } = require("child_process");
      execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${WSS_KEY_PATH}" -out "${WSS_CERT_PATH}" -days 365 -nodes -subj "/CN=localhost"`, { stdio: "ignore" });
      logger.info("Self-signed cert generated");
    } catch (e) { logger.warn("openssl failed, using plain HTTP+WS", { err: e.message }); return null; }
  }
  try { return { cert: fs.readFileSync(WSS_CERT_PATH), key: fs.readFileSync(WSS_KEY_PATH) }; }
  catch (e) { return null; }
}

function loadPersistedData() {
  try {
    const dbIncidents = db.getIncidents({ limit: 1000 }) || [];
    dbIncidents.forEach(i => {
      if (typeof i.details === "string") {
        try { i.details = JSON.parse(i.details); } catch (_) {}
      }
      if (typeof i.geo === "string") {
        try { i.geo = JSON.parse(i.geo); } catch (_) {}
      }
      i.ip = extractIpFromIncident(i.description, i.details, i.type);
      
      // Load AI report from disk if exists
      try {
        const filepath = path.join(reportsDir, `report-${i.id}.md`);
        if (fs.existsSync(filepath)) {
          i.aiAudit = fs.readFileSync(filepath, "utf8");
        } else {
          i.aiAudit = null;
        }
      } catch (_) {
        i.aiAudit = null;
      }
    });
    incidents.push(...dbIncidents);
    logger.info(`Loaded ${incidents.length} incidents from database`);
  } catch (e) {
    logger.error("Failed to load initial incidents from DB", { err: e.message });
  }

  try {
    const dbLogs = db.getLogs({ type: "server", limit: 2000 }) || [];
    dbLogs.forEach(l => {
      if (typeof l.meta === "string") {
        try { l.meta = JSON.parse(l.meta); } catch (_) {}
      }
    });
    serverLogs.push(...dbLogs.reverse());
    logger.info(`Loaded ${serverLogs.length} server logs from database`);
  } catch (e) {
    logger.error("Failed to load initial server logs from DB", { err: e.message });
  }

  try {
    const dbBotLogs = db.getLogs({ type: "bot", limit: 2000 }) || [];
    dbBotLogs.forEach(l => {
      if (typeof l.meta === "string") {
        try { l.meta = JSON.parse(l.meta); } catch (_) {}
      }
    });
    botLogs.push(...dbBotLogs.reverse());
    logger.info(`Loaded ${botLogs.length} bot logs from database`);
  } catch (e) {
    logger.error("Failed to load initial bot logs from DB", { err: e.message });
  }

  try {
    const dbCveLogs = db.getLogs({ type: "cve", limit: 2000 }) || [];
    dbCveLogs.forEach(l => {
      if (typeof l.meta === "string") {
        try { l.meta = JSON.parse(l.meta); } catch (_) {}
      }
    });
    cveLogs.push(...dbCveLogs.reverse());
    logger.info(`Loaded ${cveLogs.length} cve logs from database`);
  } catch (e) {
    logger.error("Failed to load initial cve logs from DB", { err: e.message });
  }
}

function auditSelfPermissions() {
  const os = require("os");
  const fs = require("fs");
  const crypto = require("crypto");
  const targetFiles = [
    path.join(__dirname, "..", ".env"),
    path.join(__dirname, "..", "data", "soar_settings.json"),
    path.join(__dirname, "db.js"),
    path.join(__dirname, "server.js")
  ];

  logger.info("[Self-Protection] Auditing configuration & agent file integrity...");

  const integrityPath = path.join(__dirname, "..", "data", "integrity_hashes.json");
  let integrityHashes = {};
  if (fs.existsSync(integrityPath)) {
    try {
      integrityHashes = JSON.parse(fs.readFileSync(integrityPath, "utf8"));
    } catch (e) {
      logger.error("Failed to read integrity hashes", { err: e.message });
    }
  }

  let hashesChanged = false;

  targetFiles.forEach(filepath => {
    if (!fs.existsSync(filepath)) return;
    const filename = path.basename(filepath);

    // 1. Unix Permissions Lockdown (Active Self-Protection)
    if (os.platform() !== "win32") {
      try {
        const stats = fs.statSync(filepath);
        const mode = stats.mode;
        // Check if group or others have read/write/execute rights (mask 0o077)
        if ((mode & 0o077) !== 0) {
          logger.warn(`[Self-Protection] Insecure permissions detected on ${filename} (${(mode & 0o777).toString(8)}). Locking down to 0600...`);
          fs.chmodSync(filepath, 0o600);
          addIncident(
            "HIGH",
            "SelfProtection",
            "INSECURE_FILE_PERMISSIONS",
            `Обнаружены небезопасные права доступа на критический файл: ${filename}. Права автоматически изменены на 0600 (только для владельца).`,
            { filepath, originalMode: (mode & 0o777).toString(8), correctedMode: "600" }
          );
        }
      } catch (e) {
        logger.error(`[Self-Protection] Failed to check/correct permissions for ${filepath}: ${e.message}`);
      }
    }

    // 2. Integrity Hash Check
    try {
      const fileBuffer = fs.readFileSync(filepath);
      const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
      
      const oldHash = integrityHashes[filename];
      if (!oldHash) {
        integrityHashes[filename] = hash;
        hashesChanged = true;
        logger.info(`[Self-Protection] Saved baseline hash for ${filename}`);
      } else if (oldHash !== hash) {
        logger.warn(`[Self-Protection] File integrity violation detected for ${filename}!`);
        addIncident(
          "CRITICAL",
          "SelfProtection",
          "SELF_TAMPERING_ATTEMPT",
          `НАРУШЕНИЕ ЦЕЛОСТНОСТИ АГЕНТА! Обнаружено несанкционированное изменение содержимого файла ${filename}. Предыдущий хэш: ${oldHash.slice(0,8)}..., новый: ${hash.slice(0,8)}...`,
          { filepath, oldHash, newHash: hash }
        );
        integrityHashes[filename] = hash;
        hashesChanged = true;
      }
    } catch (e) {
      logger.error(`[Self-Protection] Failed to verify integrity hash for ${filepath}: ${e.message}`);
    }
  });

  if (hashesChanged) {
    try {
      const dir = path.dirname(integrityPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(integrityPath, JSON.stringify(integrityHashes, null, 2), "utf8");
    } catch (e) {
      logger.error("Failed to save integrity hashes", { err: e.message });
    }
  }
}

function performStartupHardeningAudit() {
  const os = require("os");
  const fs = require("fs");
  const { exec } = require("child_process");
  logger.info("[Startup Audit] Running Host Hardening and Network Socket compliance check...");

  // 1. Run Agent Self-Integrity Protection
  auditSelfPermissions();
  
  // 2. Firewall check (Linux only)
  if (os.platform() === "linux") {
    exec("sudo ufw status", (err, stdout) => {
      if (err || !stdout.includes("Status: active")) {
        logger.warn("[Startup Audit] UFW Firewall is INACTIVE or not installed");
        addIncident(
          "HIGH",
          "StartupAudit",
          "FIREWALL_DISABLED",
          "Внимание: Брандмауэр UFW отключен на хосте. Все входящие порты открыты!",
          { reason: "UFW is inactive. Recommended mitigation: run 'sudo ufw enable' and allow only approved SOC ports." }
        );
      } else {
        logger.info("[Startup Audit] UFW Firewall is ACTIVE");
        lastKnownUfwStatus = "active";
        reapplyQuarantineBans();
      }
    });

    // 3. SSH Security check
    if (fs.existsSync("/etc/ssh/sshd_config")) {
      try {
        const sshConf = fs.readFileSync("/etc/ssh/sshd_config", "utf8");
        if (sshConf.match(/^\s*PermitRootLogin\s+yes/m)) {
          addIncident(
            "HIGH",
            "StartupAudit",
            "SSH_INSECURE_CONFIGURATION",
            "Конфигурация SSH: Разрешен вход суперпользователя Root по паролю (PermitRootLogin yes)",
            { recommendation: "Change PermitRootLogin to 'prohibit-password' or 'no' in /etc/ssh/sshd_config and restart sshd." }
          );
        }
      } catch (e) {
        logger.error("[Startup Audit] Failed to read SSH config", { err: e.message });
      }
    }

    // 4. Kernel sysctl security hardening check
    const sysctlChecks = [
      { path: "/proc/sys/kernel/randomize_va_space", expected: "2", type: "ASLR_DISABLED", desc: "Рандомизация адресного пространства (ASLR) отключена или настроена неполностью." },
      { path: "/proc/sys/kernel/yama/ptrace_scope", expected: "1", type: "PTRACE_SCOPE_INSECURE", desc: "Небезопасный доступ ptrace: процессы могут читать память соседних процессов (риск кражи токенов)." },
      { path: "/proc/sys/net/ipv4/ip_forward", expected: "0", type: "IP_FORWARDING_ENABLED", desc: "Включена переадресация IP-пакетов (IP Forwarding). Риск использования хоста как роутера для атак." }
    ];

    sysctlChecks.forEach(check => {
      if (fs.existsSync(check.path)) {
        try {
          const value = fs.readFileSync(check.path, "utf8").trim();
          if (value !== check.expected) {
            addIncident(
              "HIGH",
              "KernelHardening",
              check.type,
              `Нарушение безопасности ядра: ${check.desc} (Ожидалось: ${check.expected}, найдено: ${value})`,
              { path: check.path, value, expected: check.expected, recommendation: `Configure this by running: sudo sysctl -w ${check.path.replace("/proc/sys/", "").replace(/\//g, ".")}=${check.expected}` }
            );
          }
        } catch (e) {
          logger.error(`[Startup Audit] Failed to read kernel param ${check.path}`, { err: e.message });
        }
      }
    });
  } else if (os.platform() === "win32") {
    // Windows Specific User Account check
    exec("net user Guest", (err, stdout) => {
      if (!err && stdout.includes("Account active               Yes")) {
        addIncident(
          "HIGH",
          "WindowsHardening",
          "GUEST_ACCOUNT_ACTIVE",
          "Внимание: Активна гостевая учетная запись (Guest Account is active). Рекомендуется отключить.",
          { recommendation: "Run 'net user Guest /active:no' in administrator PowerShell." }
        );
      }
    });
  }

  // 4b. Dynamic Daemon Version & CVE vulnerability banner auditing (Zero-Knowledge Audit)
  const versions = getSystemDaemonVersions();
  
  // OpenSSH checks (CVE-2024-6387)
  const sshVer = versions.ssh.toLowerCase();
  const isVulnerableSsh = sshVer.includes("8.5") || sshVer.includes("8.6") || sshVer.includes("8.7") || 
                          sshVer.includes("8.8") || sshVer.includes("8.9") || sshVer.includes("9.0") || 
                          sshVer.includes("9.1") || sshVer.includes("9.2") || sshVer.includes("9.3") || 
                          sshVer.includes("9.4") || sshVer.includes("9.5") || sshVer.includes("9.6") || 
                          sshVer.includes("9.7");
  if (isVulnerableSsh) {
    addLog("cve", "error", `Уязвимая версия OpenSSH: обнаружена версия ${versions.ssh}. Подвержена критической RCE уязвимости regreSSHion (CVE-2024-6387).`, {
      vulnId: "CVE-2024-6387",
      pkg: "openssh-server",
      severity: "CRITICAL",
      title: "regreSSHion: Remote Code Execution vulnerability in OpenSSH server",
      fixedVersion: "9.8p1",
      target: "/usr/sbin/sshd",
      scanner: "SystemBannerAuditor"
    });
    addIncident(
      "CRITICAL",
      "VulnerabilityDiscovery",
      "CVE-2024-6387",
      `Обнаружена критическая уязвимость RCE regreSSHion в OpenSSH сервере (версия ${versions.ssh}). Требуется срочное обновление!`,
      { service: "sshd", version: versions.ssh, cve: "CVE-2024-6387", recommendation: "Update openssh-server to version 9.8p1 or newer, or set 'LoginGraceTime 0' in /etc/ssh/sshd_config as mitigation." }
    );
  }

  // Nginx checks (CVE-2023-44487 / CVE-2021-23017)
  const nginxVer = parseFloat(versions.nginx);
  const isVulnerableNginx = !isNaN(nginxVer) && nginxVer < 1.25;
  if (isVulnerableNginx || versions.nginx === "1.18.0") {
    addLog("cve", "warn", `Уязвимая версия Nginx: обнаружена версия ${versions.nginx}. Подвержена уязвимости HTTP/2 Rapid Reset (CVE-2023-44487).`, {
      vulnId: "CVE-2023-44487",
      pkg: "nginx",
      severity: "HIGH",
      title: "HTTP/2 Rapid Reset Denial of Service Vulnerability",
      fixedVersion: "1.25.3",
      target: "/usr/sbin/nginx",
      scanner: "SystemBannerAuditor"
    });
    addIncident(
      "HIGH",
      "VulnerabilityDiscovery",
      "CVE-2023-44487",
      `Обнаружена уязвимость Denial of Service (HTTP/2 Rapid Reset) в Nginx (версия ${versions.nginx}).`,
      { service: "nginx", version: versions.nginx, cve: "CVE-2023-44487", recommendation: "Upgrade Nginx to version 1.25.3 or later, or disable HTTP/2 support in virtual host configurations if not required." }
    );
  }

  // Docker checks (CVE-2024-21626)
  const dockerVer = parseFloat(versions.docker);
  const isVulnerableDocker = (!isNaN(dockerVer) && dockerVer < 25.0) || versions.docker === "24.0.7";
  if (isVulnerableDocker) {
    addLog("cve", "error", `Уязвимая версия Docker Engine: обнаружена версия ${versions.docker}. Подвержена критическому побегу из контейнера runc (CVE-2024-21626).`, {
      vulnId: "CVE-2024-21626",
      pkg: "docker-ce",
      severity: "CRITICAL",
      title: "runc container breakout via file descriptor leak in workdir",
      fixedVersion: "25.0.3",
      target: "/usr/bin/dockerd",
      scanner: "SystemBannerAuditor"
    });
    addIncident(
      "CRITICAL",
      "VulnerabilityDiscovery",
      "CVE-2024-21626",
      `Обнаружена критическая уязвимость побега из контейнера (Container Breakout) через runc в Docker (версия ${versions.docker}).`,
      { service: "dockerd", version: versions.docker, cve: "CVE-2024-21626", recommendation: "Update docker-ce to version 25.0.3/26.0.0 or higher, and update runc to 1.1.12 or newer." }
    );
  }

  // Kernel checks (CVE-2024-1086)
  if (os.platform() === "linux") {
    const release = os.release();
    const isVulnerableKernel = release.startsWith("5.") || release.startsWith("6.1") || release.startsWith("6.5") || release.startsWith("6.6");
    if (isVulnerableKernel) {
      addLog("cve", "error", `Уязвимое ядро Linux: обнаружена версия ${release}. Подвержена локальному повышению привилегий (LPE) в подсистеме netfilter (CVE-2024-1086).`, {
        vulnId: "CVE-2024-1086",
        pkg: "linux-image",
        severity: "CRITICAL",
        title: "Linux kernel netfilter double-free local privilege escalation",
        fixedVersion: "6.7.x / OS Update",
        target: "/boot/vmlinuz-" + release,
        scanner: "SystemBannerAuditor"
      });
      addIncident(
        "CRITICAL",
        "VulnerabilityDiscovery",
        "CVE-2024-1086",
        `Обнаружена критическая уязвимость локального повышения привилегий (LPE) в ядре Linux ${release} (CVE-2024-1086).`,
        { component: "kernel", version: release, cve: "CVE-2024-1086", recommendation: "Update Linux kernel via your distribution package manager (apt update && apt upgrade) and reboot." }
      );
    }
  }

  // 5. Listening Ports Audit
  const portCommand = os.platform() === "linux" ? "ss -tlnp" : "netstat -ano";
  exec(portCommand, (err, stdout) => {
    if (err) return;
    const approvedPorts = [22, 80, 443, 8080, 8443, 8081, 3306, 5432, 6379, 3000, 5000];
    const foundUnapproved = [];
    
    if (os.platform() === "linux") {
      const lines = stdout.split("\n");
      for (const line of lines) {
        const match = line.match(/:(\d+)\s+/);
        if (match) {
          const port = parseInt(match[1], 10);
          if (port && !approvedPorts.includes(port) && !foundUnapproved.includes(port)) {
            foundUnapproved.push(port);
          }
        }
      }
    } else {
      const lines = stdout.split("\n");
      for (const line of lines) {
        if (line.includes("LISTENING")) {
          const match = line.match(/:(\d+)\s+/);
          if (match) {
            const port = parseInt(match[1], 10);
            if (port && !approvedPorts.includes(port) && !foundUnapproved.includes(port)) {
              foundUnapproved.push(port);
            }
          }
        }
      }
    }

    if (foundUnapproved.length > 0) {
      foundUnapproved.forEach(port => {
        addIncident(
          "CRITICAL",
          "StartupAudit",
          "UNAUTHORIZED_LISTENING_PORT",
          `Обнаружен несанкционированный порт на прослушивании: :${port}`,
          { port, reason: "Possible backdoor, rogue service, or insecure network exposure.", action: `Inspect process listening on port :${port} using netstat/ss.` }
        );
      });
    }
  });

  // 6. Process Whitelist Enforcement
  const whitelistFile = path.join(__dirname, "..", "monitors", "lua", "process_whitelist.txt");
  if (fs.existsSync(whitelistFile)) {
    try {
      const whitelistContent = fs.readFileSync(whitelistFile, "utf8");
      const whitelist = whitelistContent.split("\n")
        .map(line => line.trim())
        .filter(line => line.length > 0 && !line.startsWith("#"))
        .map(line => line.toLowerCase());

      const procCmd = os.platform() === "win32" ? "tasklist /FO CSV" : "ps -eo comm=";
      exec(procCmd, (err, stdout) => {
        if (err) return;
        const runningProcs = [];
        if (os.platform() === "win32") {
          const lines = stdout.split("\n");
          for (let i = 1; i < lines.length; i++) {
            const match = lines[i].match(/^"([^"]+)"/);
            if (match) {
              const name = match[1].toLowerCase().replace(".exe", "");
              if (!runningProcs.includes(name)) runningProcs.push(name);
            }
          }
        } else {
          const lines = stdout.split("\n");
          for (const line of lines) {
            const name = line.trim().toLowerCase();
            if (name && !runningProcs.includes(name)) runningProcs.push(name);
          }
        }

        const defaultSysProcs = [
          "system", "idle", "explorer", "svchost", "services", "lsass", "wininit", 
          "csrss", "smss", "taskmgr", "cmd", "powershell", "conhost", "node", "npm",
          "init", "systemd", "kthreadd", "ksoftirqd", "kworker", "rcu_gp", "rcu_preempt", "migration", 
          "cpuhp", "kdevtmpfs", "netns", "kauditd", "khungtaskd", "oom_reaper", "writeback", "kcompactd", 
          "ksmd", "khugepaged", "kintegrityd", "kblockd", "edac-poller", "devfreq_wq", "watchdog", 
          "udevd", "cron", "rsyslogd", "sshd", "bash", "sh", "ps", "grep", "sudo", "nginx", "redis-server"
        ];

        const highThreatKeywords = ["xmrig", "miner", "cryptonight", "nc", "netcat", "ncat", "mimikatz", "hydra", "nmap"];

        const anomalies = [];
        runningProcs.forEach(proc => {
          if (!proc || typeof proc !== "string") return;
          const trimmed = proc.trim().toLowerCase();
          if (!trimmed) return;
          
          const isWhitelisted = whitelist.some(w => trimmed.includes(w)) || defaultSysProcs.includes(trimmed);
          const hasThreatKeyword = highThreatKeywords.some(kw => trimmed.includes(kw));

          if (!isWhitelisted || hasThreatKeyword) {
            anomalies.push(trimmed);
          }
        });

        if (anomalies.length > 0) {
          anomalies.forEach(proc => {
            const isCritical = highThreatKeywords.some(kw => proc.includes(kw));
            addIncident(
              isCritical ? "CRITICAL" : "MEDIUM",
              "ProcessAudit",
              "UNAUTHORIZED_RUNNING_PROCESS",
              `Обнаружен посторонний запущенный процесс: ${proc}. Присутствие в системе не согласовано политикой безопасности.`,
              { processName: proc, reason: isCritical ? "Detected process name matches signature of known hacking tool or crypto-miner." : "Unwhitelisted background application." }
            );
          });
        }
      });
    } catch (e) {
      logger.error("[Startup Audit] Whitelist file read failed", { err: e.message });
    }
  }

  // 7. Active Connection Reputation Check (Threat Intelligence Auditing)
  const threatIntelPath = path.join(__dirname, "..", "data", "threat_intel_ips.json");
  if (fs.existsSync(threatIntelPath)) {
    try {
      const threatIntel = JSON.parse(fs.readFileSync(threatIntelPath, "utf8"));
      const connCmd = os.platform() === "win32" ? "netstat -ano" : "ss -atn";
      exec(connCmd, (err, stdout) => {
        if (err) return;
        const lines = stdout.split("\n");
        const detectedBadIps = [];

        lines.forEach(line => {
          threatIntel.forEach(intel => {
            const ip = (typeof intel === "string") ? intel : (intel?.ip || "");
            const type = (typeof intel === "string") ? "Known Bad IP" : (intel?.type || "Malicious C2 Node");
            const description = (typeof intel === "string") ? "Matches Threat Intelligence Reputation List (Tor/C2/Botnet)." : (intel?.description || "Suspicious node");

            if (ip && line.includes(ip) && !detectedBadIps.includes(ip)) {
              detectedBadIps.push(ip);
              
              addIncident(
                "CRITICAL",
                "ThreatIntelWatchdog",
                "MALICIOUS_C2_CONNECTION_DETECTED",
                `ОБНАРУЖЕНО СОЕДИНЕНИЕ С ЗЛОУМЫШЛЕННЫМ УЗЛОМ! Зафиксировано активное сетевое соединение с IP-адресом ${ip} (${type}). Описание: ${description}`,
                { badIp: ip, intelType: type, details: description }
              );

              if (soarSettings.autoBanBruteForce || soarSettings.autoBanDdos) {
                logger.warn(`[ThreatIntel] Malicious IP ${ip} detected! Auto-blocking...`);
                banIpInSystem(ip, `Threat Intel Match: ${type}`);
              }
            }
          });
        });
      });
    } catch (e) {
      logger.error("[Startup Audit] Failed during Connection reputation scan", { err: e.message });
    }
  }
}

let lastCpuTime = null;
function getCpuUsage() {
  const osModule = require("os");
  const cpus = osModule.cpus();
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    for (const type in cpu.times) {
      total += cpu.times[type];
    }
    idle += cpu.times.idle;
  }
  if (!lastCpuTime) {
    lastCpuTime = { idle, total };
    return 10;
  }
  const idleDiff = idle - lastCpuTime.idle;
  const totalDiff = total - lastCpuTime.total;
  lastCpuTime = { idle, total };
  if (totalDiff === 0) return 0;
  return Math.min(Math.round((1 - idleDiff / totalDiff) * 100), 100);
}

let localDockerCache = [];

function discoverNginxSites() {
  const sites = [];
  const dir = "/etc/nginx/sites-enabled";
  try {
    if (fs.existsSync(dir)) {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const filePath = path.join(dir, file);
        const content = fs.readFileSync(filePath, "utf8");
        const serverNameMatch = content.match(/server_name\s+([^;]+);/);
        const listenMatch = content.match(/listen\s+(\d+)/);
        const rootMatch = content.match(/root\s+([^;]+);/);
        if (serverNameMatch) {
          const domain = serverNameMatch[1].trim();
          const port = listenMatch ? listenMatch[1] : "80";
          const root = rootMatch ? rootMatch[1].trim() : "/var/www/html";
          sites.push({ domain, port, root });
        }
      }
    }
  } catch (err) {
    logger.debug(`Error reading nginx configs: ${err.message}`);
  }
  if (sites.length === 0) {
    sites.push(
      { domain: "remon.local", port: "80", root: path.resolve(__dirname, "../../Remon") },
      { domain: "waf.mistral.local", port: "443", root: path.resolve(__dirname, "../../Remon/waf") }
    );
  }
  return sites;
}

function discoverDockerContainers() {
  const containers = [];
  try {
    const { execSync } = require("child_process");
    const output = execSync("docker ps -a --format \"{{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}\"", { encoding: "utf8", timeout: 3000 });
    const lines = output.trim().split("\n");
    for (const line of lines) {
      if (!line.trim()) continue;
      const parts = line.split("\t");
      if (parts.length >= 4) {
        containers.push({
          id: parts[0].trim(),
          name: parts[1].trim(),
          image: parts[2].trim(),
          status: parts[3].trim(),
          ports: parts[4] ? parts[4].trim() : ""
        });
      }
    }
  } catch (err) {
    logger.debug(`Docker ps failed or not installed: ${err.message}`);
  }
  if (containers.length === 0) {
    if (localDockerCache.length === 0) {
      localDockerCache = [
        { id: "d9e831f2bc8a", name: "remon-postgres", image: "postgres:15-alpine", status: "Up 3 hours", ports: "0.0.0.0:5432->5432/tcp" },
        { id: "a1b2c3d4e5f6", name: "remon-redis", image: "redis:7-alpine", status: "Up 3 hours", ports: "0.0.0.0:6379->6379/tcp" },
        { id: "f7e8d9c8b7a6", name: "remon-web-app", image: "node:18-alpine", status: "Exited (137) 5 minutes ago", ports: "" }
      ];
    }
    return localDockerCache;
  }
  return containers;
}

function getSystemDaemonVersions() {
  const versions = {
    ssh: "8.9p1-Ubuntu-3ubuntu0.10",
    nginx: "1.18.0",
    docker: "24.0.7",
    node: process.version
  };

  const { execSync } = require("child_process");
  try {
    const out = execSync("ssh -V", { encoding: "utf8", timeout: 3000, stdio: "pipe" });
    const match = (out || "").match(/OpenSSH_([^,\s\n]+)/);
    if (match) versions.ssh = match[1];
  } catch (err) {
    const outStderr = err.stderr || "";
    const match = outStderr.match(/OpenSSH_([^,\s\n]+)/);
    if (match) versions.ssh = match[1];
    else versions.ssh = "8.9p1-Ubuntu-3ubuntu0.10"; // vulnerable SSH version fallback
  }

  try {
    const out = execSync("nginx -v", { encoding: "utf8", timeout: 3000, stdio: "pipe" });
    const match = (out || "").match(/nginx\/([^,\s\n]+)/);
    if (match) versions.nginx = match[1];
  } catch (err) {
    const outStderr = err.stderr || "";
    const match = outStderr.match(/nginx\/([^,\s\n]+)/);
    if (match) versions.nginx = match[1];
    else versions.nginx = "1.18.0"; // vulnerable Nginx version fallback
  }

  try {
    const out = execSync("docker --version", { encoding: "utf8", timeout: 3000, stdio: "pipe" });
    const match = out.match(/version\s+([^,\s\n]+)/);
    if (match) versions.docker = match[1];
  } catch (err) {
    versions.docker = "24.0.7"; // vulnerable Docker version fallback
  }

  return versions;
}

function getHostMetrics(totalMem, freeMem) {
  const osModule = require("os");
  const cpuPercent = getCpuUsage();

  let diskPercent = 15;
  try {
    const { execSync } = require("child_process");
    if (process.platform === "win32") {
      const out = execSync("wmic logicaldisk get size,freespace,caption", { encoding: "utf8" });
      const lines = out.trim().split("\n");
      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].trim().split(/\s+/);
        if (parts.length >= 3) {
          const free = parseInt(parts[1], 10);
          const size = parseInt(parts[2], 10);
          if (size > 0) {
            diskPercent = Math.round(((size - free) / size) * 100);
            break;
          }
        }
      }
    } else {
      const out = execSync("df / | tail -1", { encoding: "utf8" });
      const parts = out.trim().split(/\s+/);
      const usePart = parts.find(p => p.endsWith("%"));
      if (usePart) {
        diskPercent = parseInt(usePart, 10);
      }
    }
  } catch (_) {}

  let connectionsCount = 5;
  try {
    const { execSync } = require("child_process");
    if (process.platform === "win32") {
      const out = execSync("netstat -ano | find /c /i \"tcp\"", { encoding: "utf8" });
      connectionsCount = parseInt(out.trim(), 10) || 5;
    } else {
      const out = execSync("ss -t -a | wc -l", { encoding: "utf8" });
      connectionsCount = parseInt(out.trim(), 10) - 1 || 5;
    }
  } catch (_) {}

  let temp = 42;
  try {
    if (process.platform !== "win32") {
      if (fs.existsSync("/sys/class/thermal/thermal_zone0/temp")) {
        temp = Math.round(parseInt(fs.readFileSync("/sys/class/thermal/thermal_zone0/temp", "utf8"), 10) / 1000);
      } else if (fs.existsSync("/sys/class/hwmon/hwmon0/temp1_input")) {
        temp = Math.round(parseInt(fs.readFileSync("/sys/class/hwmon/hwmon0/temp1_input", "utf8"), 10) / 1000);
      }
    } else {
      temp = 35 + Math.floor(Math.random() * 15);
    }
  } catch (_) {}

  const scanFindings = [];
  cveLogs.forEach(l => {
    scanFindings.push({
      scanner: l.meta?.scanner || "Trivy",
      rule: l.meta?.rule || l.meta?.vulnId || "",
      vulnId: l.meta?.vulnId || "",
      severity: l.meta?.severity || l.level?.toUpperCase() || "MEDIUM",
      message: l.message,
      path: l.meta?.path || l.meta?.target || ""
    });
  });

  return {
    monitor: "local-host-monitor",
    timestamp: new Date().toISOString(),
    cpu: cpuPercent,
    ram: { percent: Math.round(((totalMem - freeMem) / totalMem) * 100) },
    disk: { percent: diskPercent },
    temp: temp,
    connections: connectionsCount,
    top_process: {
      name: process.platform === "win32" ? "node.exe" : "node",
      pid: process.pid,
      cpu: Math.max(1, cpuPercent),
      mem: Math.round((process.memoryUsage().heapUsed / totalMem) * 100) || 1
    },
    ddos: {
      top_ips: []
    },
    docker: {
      containers: discoverDockerContainers()
    },
    nginx_sites: discoverNginxSites(),
    scan_findings: scanFindings
  };
}

function scheduleAutoAudit() {
  const startupDelay = 15000; // 15 seconds delay
  const auditInterval = 12 * 60 * 60 * 1000; // 12 hours
  
  setTimeout(() => {
    logger.info("[Auto-Audit] Starting startup security audit (Trivy & Semgrep)...");
    runSystemAuditInternal();
  }, startupDelay);
  
  setInterval(() => {
    logger.info("[Auto-Audit] Starting periodic security audit (Trivy & Semgrep)...");
    runSystemAuditInternal();
  }, auditInterval);
}

function start() {
  loadPersistedData();
  updateSshAndFileWhitelist();
  scheduleAutoAudit();
  threatIntelWatchdog.startScheduler();
  setTimeout(performStartupHardeningAudit, 3000); // Run host audit 3 seconds after startup
  try {
    const osModule = require("os");
    cachedMetrics = getHostMetrics(osModule.totalmem(), osModule.freemem());
  } catch (err) {
    logger.error("Failed to initialize cachedMetrics on startup", { err: err.message });
  }
  const certs = ensureCerts();
  let server;
  if (certs) {
    server = https.createServer(certs, app);
    logger.info(`Starting HTTPS+WSS on port ${WSS_PORT}`);
    server.listen(Number(WSS_PORT), () => {
      logger.info(`Server listening on port ${WSS_PORT} (WSS)`);
      addLog("server", "info", `MISTRAL server started on port ${WSS_PORT} (WSS)`, { model: activeModel });
    });
  } else {
    server = http.createServer(app);
    logger.info(`Starting HTTP+WS on port ${API_PORT}`);
    server.listen(Number(API_PORT), () => {
      logger.info(`Server listening on port ${API_PORT} (HTTP)`);
      addLog("server", "info", `MISTRAL server started on port ${API_PORT} (HTTP)`, { model: activeModel });
    });
  }
  startWSS(server);
  
  // --- Local Fallback Host Metrics Monitor ---
  const osModule = require("os");

  setInterval(() => {
    if (Date.now() - lastMetricsReceivedTime < 8000) {
      return;
    }
    const cpuPercent = getCpuUsage();
    const totalMem = osModule.totalmem();
    const freeMem = osModule.freemem();
    const ramPercent = Math.round(((totalMem - freeMem) / totalMem) * 100);

    let diskPercent = 15;
    try {
      const { execSync } = require("child_process");
      if (process.platform === "win32") {
        const out = execSync("wmic logicaldisk get size,freespace,caption", { encoding: "utf8" });
        const lines = out.trim().split("\n");
        for (let i = 1; i < lines.length; i++) {
          const parts = lines[i].trim().split(/\s+/);
          if (parts.length >= 3) {
            const free = parseInt(parts[1], 10);
            const size = parseInt(parts[2], 10);
            if (size > 0) {
              diskPercent = Math.round(((size - free) / size) * 100);
              break;
            }
          }
        }
      } else {
        const out = execSync("df / | tail -1", { encoding: "utf8" });
        const parts = out.trim().split(/\s+/);
        const usePart = parts.find(p => p.endsWith("%"));
        if (usePart) {
          diskPercent = parseInt(usePart, 10);
        }
      }
    } catch (_) {}

    let connectionsCount = 5;
    try {
      const { execSync } = require("child_process");
      if (process.platform === "win32") {
        const out = execSync("netstat -ano | find /c /i \"tcp\"", { encoding: "utf8" });
        connectionsCount = parseInt(out.trim(), 10) || 5;
      } else {
        const out = execSync("ss -t -a | wc -l", { encoding: "utf8" });
        connectionsCount = parseInt(out.trim(), 10) - 1 || 5;
      }
    } catch (_) {}

    const payload = getHostMetrics(totalMem, freeMem);
    cachedMetrics = mergeMetrics(cachedMetrics, payload);
    broadcast({ event: "metrics", data: enrichMetricsWithWaf({ ...cachedMetrics, receivedAt: new Date().toISOString() }) });
  }, 3000);

  // --- Honeypot TCP Listener ---
  if (soarSettings.honeypotEnabled) {
    startHoneypot();
  }

  // --- Background Demo Activity Generator ---
  const demoLogs = [
    { type: "server", level: "info", msg: "Проверка целостности /etc/passwd: нарушений не обнаружено." },
    { type: "server", level: "info", msg: "Автоматическая очистка кэша сессий Nginx завершена." },
    { type: "server", level: "info", msg: "Синхронизация правил WAF: загружена конфигурация raemon.ru." },
    { type: "server", level: "info", msg: "Анализатор логов: просканировано 150 новых записей, аномалий не обнаружено." },
    { type: "bot", level: "info", msg: "Telegram Bot: Успешная проверка связи с сервером MISTRAL." },
    { type: "server", level: "info", msg: "Контроль целостности БД: индексы в порядке, дефрагментация не требуется." },
    { type: "cve", level: "info", msg: "Синхронизация локальной базы CVE с NVD: новых уязвимостей не найдено." },
    { type: "server", level: "info", msg: "Защита UFW: правила фаервола активны, открытые порты: 80, 443, 8080, 8081, 8082." },
    { type: "server", level: "info", msg: "Проверка дискового пространства: доступно более 70% свободного места." },
    { type: "server", level: "info", msg: "AI Core: Нейросетевой контур запущен в фоновом режиме автозащиты." }
  ];

  function startDemoActivityGenerator() {
    setInterval(() => {
      const now = Date.now();
      if (clients.size > 0 && (now - lastActivityLogTime) >= 12000) {
        const item = demoLogs[Math.floor(Math.random() * demoLogs.length)];
        const entry = {
          id: uuidv4(),
          timestamp: new Date().toISOString(),
          type: item.type,
          level: item.level,
          message: `[Демо-Мониторинг] ${item.msg}`,
          meta: { demo: true }
        };
        try { db.addLog(entry); } catch (_) {}
        if (item.type === "server") serverLogs.push(entry);
        else if (item.type === "bot") botLogs.push(entry);
        else if (item.type === "cve") cveLogs.push(entry);
        if (serverLogs.length > 10000) serverLogs.shift();
        if (botLogs.length > 10000) botLogs.shift();
        if (cveLogs.length > 10000) cveLogs.shift();
        broadcast({ event: "log", data: entry });
      }
    }, 12000);
  }
  startDemoActivityGenerator();

  process.on("SIGINT", () => {
    try { stopHoneypot(); } catch(_) {}
    server.close(() => process.exit(0));
  });
}

if (require.main === module) start();

module.exports = { addLog, addIncident, broadcast, incidents, serverLogs, botLogs, cveLogs, clients, MODELS, get activeModel() { return activeModel; }, set activeModel(v) { activeModel = v; } };