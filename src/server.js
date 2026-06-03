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

// SOAR Settings Persistence
const soarSettingsPath = path.join(__dirname, "../data/soar_settings.json");
let soarSettings = {
  autoBanDdos: false,
  autoBanBruteForce: false,
  aiDefenseEnabled: false,
  aiMakeChanges: true,
  aiModel: "deepseek-v4-pro",
  aiThreatThreshold: 3,
  aiTriggerOnLeaks: true,
  aiTriggerOnCritical: true
};
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



function addLog(type, level, message, meta = {}) {
  const entry = { id: uuidv4(), timestamp: new Date().toISOString(), type, level, message, meta };
  try { db.addLog(entry); } catch (e) { logger.error("DB addLog failed", { err: e.message }); }
  if (type === "server") serverLogs.push(entry);
  else if (type === "bot") botLogs.push(entry);
  else if (type === "cve") cveLogs.push(entry);
  if (serverLogs.length > 10000) serverLogs.shift();
  if (botLogs.length > 10000) botLogs.shift();
  if (cveLogs.length > 10000) cveLogs.shift();
  logger.log(level, `[${type}] ${message}`, meta);
  broadcast({ event: "log", data: entry });
  return entry;
}

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

function extractIpFromIncident(description, details) {
  if (details) {
    if (details.sourceIp) return details.sourceIp;
    if (details.ip) return details.ip;
    if (details.ddos && details.ddos.top_ips && Array.isArray(details.ddos.top_ips) && details.ddos.top_ips.length > 0) {
      return details.ddos.top_ips[0].ip;
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

function resolveRealGeoIP(incidentId, ip) {
  if (!ip || ip === "127.0.0.1" || ip === "localhost" || ip === "::1" || ip === "::ffff:127.0.0.1") return;
  const http = require("http");
  const url = `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,lat,lon,isp`;
  
  http.get(url, (res) => {
    let raw = "";
    res.on("data", chunk => raw += chunk);
    res.on("end", () => {
      try {
        const data = JSON.parse(raw);
        if (data && data.status === "success") {
          const inc = incidents.find(i => i.id === incidentId);
          if (inc) {
            inc.geo = {
              country: data.country || "Unknown",
              code: data.countryCode || "UN",
              lat: data.lat || 0,
              lon: data.lon || 0,
              isp: data.isp || "Unknown",
              reputation: inc.geo ? inc.geo.reputation : 50,
              ip: ip
            };
            try {
              db.updateIncident(incidentId, { geo: inc.geo });
              broadcast({ event: "incident_updated", data: inc });
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

function addIncident(severity, monitor, type, description, details = {}) {
  const finalSeverity = autoCategorizeSeverity(type, description, severity);
  const contextLogs = serverLogs.slice(-100).map(l => `[${l.timestamp.slice(11,19)}] [${l.level.toUpperCase()}] ${l.message}`).join("\n");
  const extractedIp = extractIpFromIncident(description, details);
  const incId = uuidv4();
  const geoInfo = getMockGeoIP(extractedIp, incId);
  const incident = { 
    id: incId, 
    timestamp: new Date().toISOString(), 
    severity: finalSeverity, 
    monitor, 
    type, 
    description, 
    details, 
    status: "new", 
    contextBlock: contextLogs,
    ip: extractedIp,
    geo: geoInfo
  };
  try { db.addIncident(incident); } catch (e) { logger.error("DB addIncident failed", { err: e.message }); }
  incidents.unshift(incident);
  if (incidents.length > 5000) incidents.pop();
  addLog("server", finalSeverity === "CRITICAL" ? "error" : "warn", `Incident: ${type}`, incident);
  broadcast({ event: "incident", data: incident });
  notifyTelegram(incident);

  // Resolve real GeoIP in background
  if (extractedIp) {
    resolveRealGeoIP(incId, extractedIp);
  }

  // SOAR Auto-Ban Logic
  if (extractedIp) {
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
    
    // Safety check: Don't ban ourselves or the server itself
    const serverHost = process.env.API_HOST || "127.0.0.1";
    const isSafe = ip === "127.0.0.1" || ip === "localhost" || ip === "::1" || ip === "::ffff:127.0.0.1" || ip === serverHost;
    
    if (shouldBan && !isSafe) {
      try {
        const { execSync } = require("child_process");
        execSync(`ufw deny from ${ip} to any`, { stdio: "ignore" });
      } catch (e) {
        logger.warn(`UFW block failed for ${ip}: ${e.message}`);
      }
      db.addQuarantine(ip, reason);
      addLog("server", "warn", `SOAR Auto-Ban Neutralized Threat: ${ip} (${reason})`, { ip, reason });
      broadcast({ event: "quarantine_updated", data: db.getQuarantinedIps() });
    }
  }

  return incident;
}

const BOT_HTTP_PORT = process.env.BOT_HTTP_PORT || 8081;

function notifyTelegram(incident) {
  try {
    const body = JSON.stringify(incident);
    const req = http.request({
      hostname: "localhost", port: Number(BOT_HTTP_PORT),
      path: "/api/bot-notify", method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
    });
    req.on("error", () => {});
    req.write(body); req.end();
  } catch (_) {}
}
const aiClient = AITUNNEL_API_KEY ? new OpenAI({ apiKey: AITUNNEL_API_KEY, baseURL: AITUNNEL_BASE_URL }) : null;

async function askAI(model, messages, temperature = 0.3) {
  if (!aiClient) throw new Error("AI not configured — set AITUNNEL_API_KEY in .env");
  const response = await aiClient.chat.completions.create({ model, messages, temperature });
  return response.choices[0].message.content;
}

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));

// ── Health ──────────────────────────────────────────────────────────────────
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), model: activeModel, timestamp: new Date().toISOString() });
});

// ── SOAR Settings ───────────────────────────────────────────────────────────
app.get("/api/soar-settings", (_req, res) => {
  res.json(soarSettings);
});

app.post("/api/soar-settings", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

  const { autoBanDdos, autoBanBruteForce, aiDefenseEnabled, aiMakeChanges, aiModel, aiThreatThreshold, aiTriggerOnLeaks, aiTriggerOnCritical } = req.body || {};
  if (autoBanDdos !== undefined) soarSettings.autoBanDdos = !!autoBanDdos;
  if (autoBanBruteForce !== undefined) soarSettings.autoBanBruteForce = !!autoBanBruteForce;
  if (aiDefenseEnabled !== undefined) soarSettings.aiDefenseEnabled = !!aiDefenseEnabled;
  if (aiMakeChanges !== undefined) soarSettings.aiMakeChanges = !!aiMakeChanges;
  if (aiModel !== undefined) soarSettings.aiModel = String(aiModel);
  if (aiThreatThreshold !== undefined) soarSettings.aiThreatThreshold = Number(aiThreatThreshold);
  if (aiTriggerOnLeaks !== undefined) soarSettings.aiTriggerOnLeaks = !!aiTriggerOnLeaks;
  if (aiTriggerOnCritical !== undefined) soarSettings.aiTriggerOnCritical = !!aiTriggerOnCritical;
  
  saveSoarSettings();
  broadcast({ event: "soar_settings_updated", data: soarSettings });
  addLog("server", "info", "SOAR & AI settings updated by administrator", soarSettings);
  res.json({ success: true, soarSettings });
});

// ── Auth ────────────────────────────────────────────────────────────────────
app.post("/api/auth/login", (req, res) => {
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
app.get("/api/users", (_req, res) => {
  try { res.json(db.getAllUsers()); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/users", (req, res) => {
  const { username, password, chatId, nickname, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  const ok = db.addUser(username, password, chatId, nickname, role);
  if (ok) { addLog("server", "info", `User created: ${username}`); res.json({ success: true }); }
  else res.status(409).json({ success: false, error: "User already exists" });
});

// ── Logs ────────────────────────────────────────────────────────────────────
app.get("/api/logs", (req, res) => {
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
app.post("/api/logs", (req, res) => {
  const { type = "server", level = "info", message, meta = {} } = req.body;
  const entry = addLog(type, level, message, meta);
  res.json({ received: true, logId: entry.id });
});
app.post("/api/bot-log", (req, res) => {
  const { level = "info", message, meta = {} } = req.body;
  const entry = addLog("bot", level, message, meta);
  res.json({ received: true, logId: entry.id });
});
app.post("/api/cve-log", (req, res) => {
  const { level = "info", message, meta = {} } = req.body;
  const entry = addLog("cve", level, message, meta);
  res.json({ received: true, logId: entry.id });
});

// ── Incidents ───────────────────────────────────────────────────────────────
app.get("/api/incidents", (req, res) => {
  const { severity, limit = 100, offset = 0 } = req.query;
  try {
    const data = db.getIncidents({ severity, limit: Number(limit), offset: Number(offset) });
    res.json({ total: data.length, data });
  } catch (e) {
    let data = incidents;
    if (severity) data = data.filter(i => i.severity === severity);
    res.json({ total: data.length, data: data.slice(Number(offset), Number(offset) + Number(limit)) });
  }
});
app.post("/api/incidents", (req, res) => {
  const { severity, monitor, type, description, details = {} } = req.body;
  if (!severity || !monitor || !type || !description) return res.status(400).json({ error: "Missing fields" });
  const incident = addIncident(severity, monitor, type, description, details);
  res.json({ received: true, incidentId: incident.id });
});
app.patch("/api/incidents/:id", (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id);
  if (!incident) return res.status(404).json({ error: "Not found" });
  const { status, comment, severity } = req.body;
  if (status) { incident.status = status; try { db.updateIncident(req.params.id, { status }); } catch (_) {} }
  if (comment) { incident.comment = comment; try { db.updateIncident(req.params.id, { comment }); } catch (_) {} }
  if (severity) { incident.severity = severity; try { db.updateIncident(req.params.id, { severity }); } catch (_) {} }
  broadcast({ event: "incident_updated", data: incident });
  res.json(incident);
});

app.delete("/api/incidents", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

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
app.get("/api/geoip/:ip", (req, res) => {
  try {
    const ip = req.params.ip;
    res.json(getMockGeoIP(ip));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Quarantine ─────────────────────────────────────────────────────────────
app.get("/api/quarantine", (req, res) => {
  try { res.json(db.getQuarantinedIps()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/quarantine", (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });
  try {
    const { execSync } = require("child_process");
    execSync(`ufw deny from ${ip} to any`, { stdio: "ignore" }); // Mockable via dry-run later if needed, but assuming ufw exists
  } catch (e) {
    logger.warn(`UFW block failed for ${ip}: ${e.message}`);
  }
  db.addQuarantine(ip, reason);
  addLog("server", "warn", `IP Quarantined: ${ip}`, { ip, reason });
  broadcast({ event: "quarantine_updated", data: db.getQuarantinedIps() });
  res.json({ success: true, ip });
});

app.delete("/api/quarantine/:ip", (req, res) => {
  const ip = req.params.ip;
  try {
    const { execSync } = require("child_process");
    execSync(`ufw delete deny from ${ip} to any`, { stdio: "ignore" });
  } catch (e) {
    logger.warn(`UFW unblock failed for ${ip}: ${e.message}`);
  }
  db.removeQuarantine(ip);
  addLog("server", "info", `IP Un-quarantined: ${ip}`, { ip });
  broadcast({ event: "quarantine_updated", data: db.getQuarantinedIps() });
  res.json({ success: true, ip });
});

// ── Process Management ───────────────────────────────────────────────────────
app.delete("/api/process/:pid", (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  if (!pid) return res.status(400).json({ error: "Invalid PID" });
  try {
    const { execSync } = require("child_process");
    execSync(`kill -9 ${pid}`, { stdio: "ignore" });
    addLog("server", "info", `Killed process PID: ${pid}`);
    res.json({ success: true, pid });
  } catch (e) {
    logger.error(`Failed to kill PID ${pid}`, { err: e.message });
    res.status(500).json({ error: "Failed to kill process" });
  }
});

// ── Metrics (от Lua-мониторов) ───────────────────────────────────────────────
app.post("/api/metrics", (req, res) => {
  const payload = req.body;
  const { monitor, anomalies = [] } = payload;
  broadcast({ event: "metrics", data: { ...payload, receivedAt: new Date().toISOString() } });
  addLog("server", "info", `Metrics from ${monitor || "unknown"}`, { monitor });
  for (const a of anomalies) {
    addIncident(a.severity || "HIGH", a.monitor || monitor || "Monitor", a.type || "anomaly", a.description || a.type, payload);
  }
  res.json({ received: true, anomaliesProcessed: anomalies.length });
});

// ── Attack detected (от Remon WAF) ──────────────────────────────────────────
app.post("/api/attack-detected", (req, res) => {
  const { type, sourceIp, path: p, payload, severity = "HIGH" } = req.body;
  const incident = addIncident(severity, "Remon-WAF", type, `Attack: ${type} from ${sourceIp} on ${p}`, { sourceIp, path: p, payload });
  res.json({ received: true, incidentId: incident.id });
});

// ── Stats ────────────────────────────────────────────────────────────────────
app.get("/api/stats", (_req, res) => {
  try { res.json({ ...db.getStats(), connectedClients: clients.size }); }
  catch (e) { res.json({ incidents: {}, logs: {}, connectedClients: clients.size }); }
});

// ── Vulnerability Database ──────────────────────────────────────────────────
app.get("/api/vulnerabilities", (_req, res) => {
  try {
    res.json(getVulnerabilitiesFromDisk());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/vulnerabilities", (req, res) => {
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

app.delete("/api/vulnerabilities/:id", (req, res) => {
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

app.get("/api/ai-reports", (_req, res) => {
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
  const id = req.params.id;
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
    // 1. Release all quarantined IPs from UFW
    const qList = db.getQuarantinedIps() || [];
    const { execSync } = require("child_process");
    qList.forEach(q => {
      try {
        execSync(`ufw delete deny from ${q.ip} to any`, { stdio: "ignore" });
      } catch (e) {
        logger.warn(`UFW delete deny failed for ${q.ip} during reset`, { err: e.message });
      }
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
      autoBanDdos: false,
      autoBanBruteForce: false,
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
app.post("/api/ai/task", async (req, res) => {
  const { model, task, systemPrompt, incidentId } = req.body;
  const apiKey = req.headers["x-api-key"];
  const isLocal = req.ip === "::1" || req.ip === "127.0.0.1" || req.ip === "::ffff:127.0.0.1";
  if (apiKey !== WSS_SECRET_TOKEN && !isLocal) return res.status(403).json({ error: "Unauthorized" });
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
app.post("/api/ai/model", (req, res) => {
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

app.post("/api/ai-nlp-search", async (req, res) => {
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

app.post("/api/execute-ai-script", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });

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
  const { targetDir, rules } = req.body;
  const result = runSemgrep(targetDir || path.join(__dirname, ".."), rules);
  res.json(result);
});
app.post("/api/scan/trivy", async (req, res) => {
  const { target, scanType } = req.body;
  const result = runTrivy(target || ".", scanType || "fs");
  res.json(result);
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
app.post("/api/run-audit", (req, res) => {
  const tokenHeader = req.headers["x-auth-token"] || req.headers["x-api-key"];
  if (tokenHeader !== WSS_SECRET_TOKEN) return res.status(403).json({ error: "Unauthorized" });
  
  if (auditRunning) return res.json({ success: true, message: "Audit already in progress" });
  auditRunning = true;
  
  addLog("server", "info", "Starting system security audit (Trivy & Semgrep) in background");
  
  // Run background scan
  const { exec } = require("child_process");
  const tempTrivy = "/tmp/trivy_scan_out.json";
  const tempSemgrep = "/tmp/semgrep_scan_out.json";
  
  const cmd = `trivy fs --format json -o ${tempTrivy} /etc 2>/dev/null; semgrep --config=p/security-audit "${path.join(__dirname, "..")}" --json -o ${tempSemgrep} --quiet 2>/dev/null`;
  
  exec(cmd, (err) => {
    auditRunning = false;
    if (err) {
      logger.error("System security audit failed", { error: err.message });
      addLog("server", "error", `Security audit failed: ${err.message}`);
    } else {
      logger.info("System security audit completed");
      addLog("server", "info", "Security audit completed. New vulnerabilities detected.");
      // Inject as an incident
      addIncident("HIGH", "SecurityScanner", "VULNERABILITY_DISCOVERY", "Security audit finished. Trivy and Semgrep findings updated.");
    }
  });
  
  res.json({ success: true });
});

// ── Bot notify endpoint (вызывается из addIncident) ──────────────────────────
// Telegram-бот слушает этот endpoint и рассылает всем chat_id из БД
app.post("/api/bot-notify", (req, res) => {
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
          const { token, nonce } = msg.data || {};
          if (!token || !nonce) { ws.send(JSON.stringify({ event: "auth_error", data: { error: "Missing token or nonce" } })); return; }
          if (usedNonces.has(nonce)) { ws.close(4002, "Replay detected"); return; }
          if (token === WSS_SECRET_TOKEN) {
            usedNonces.add(nonce);
            client.authenticated = true;
            clearTimeout(authTimer);
            ws.send(JSON.stringify({ event: "auth_success", data: { clientId, model: activeModel, clientIp: ip } }));
            addLog("server", "info", "WS client authenticated", { clientId, ip });
            // Сразу шлём снапшот
            ws.send(JSON.stringify({ event: "stats", data: { ...db.getStats(), connectedClients: clients.size } }));
            ws.send(JSON.stringify({ event: "incidents_list", data: incidents.slice(0, 100) }));
            ws.send(JSON.stringify({ event: "logs_list", data: serverLogs.slice(0, 200) }));
            ws.send(JSON.stringify({ event: "quarantine_updated", data: db.getQuarantinedIps() }));
            ws.send(JSON.stringify({ event: "soar_settings_updated", data: soarSettings }));
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
          if (isAutoDefense) {
            addLog("server", "info", `AI Autonomous Mitigation triggered for incident: ${incidentId} using model ${model || activeModel}`);
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
            
            ws.send(JSON.stringify({ event: "ai_result", data: { model: model || activeModel, result, task, isAutoDefense, incidentId } }));
          } catch (err) { ws.send(JSON.stringify({ event: "ai_error", data: { error: err.message } })); }
          return;
        }
        if (msg.event === "switch_model") {
          const { model } = msg.data || {};
          if (MODELS[model] || Object.values(MODELS).some(m => m.id === model)) {
            activeModel = MODELS[model]?.id || model;
            broadcast({ event: "model_changed", data: { model: activeModel } });
            addLog("server", "info", `AI Model switched to: ${activeModel}`);
          }
          return;
        }
        if (msg.event === "run_scan") {
          const { scanType, target } = msg.data || {};
          if (scanType === "semgrep") runSemgrep(target || __dirname).then(r => broadcast({ event: "scan_result", data: r }));
          else if (scanType === "trivy") runTrivy(target || ".", "fs").then(r => broadcast({ event: "scan_result", data: r }));
          return;
        }
        broadcast({ event: "relay", from: client?.id, data: msg });
      } catch (err) { logger.error("WS message error", { err: err.message }); }
    });

    ws.on("close", () => { clients.delete(ws); });
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

function start() {
  loadPersistedData();
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
  process.on("SIGINT", () => { server.close(() => process.exit(0)); });
}

if (require.main === module) start();

module.exports = { addLog, addIncident, broadcast, incidents, serverLogs, botLogs, cveLogs, clients, MODELS, get activeModel() { return activeModel; }, set activeModel(v) { activeModel = v; } };