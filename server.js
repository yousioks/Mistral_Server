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

const logDir = path.join(__dirname, "logs");
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
5. ALWAYS explain before doing. ALWAYS prefer monitoring over intervention.
6. CRITICAL: DO NOT break the structure of the application. Do not try to escape the server sandbox. Do not shutdown or reboot the server.`;

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

function addIncident(severity, monitor, type, description, details = {}) {
  const contextLogs = serverLogs.slice(-100).map(l => `[${l.timestamp.slice(11,19)}] [${l.level.toUpperCase()}] ${l.message}`).join("\n");
  const incident = { id: uuidv4(), timestamp: new Date().toISOString(), severity, monitor, type, description, details, status: "new", contextBlock: contextLogs };
  try { db.addIncident(incident); } catch (e) { logger.error("DB addIncident failed", { err: e.message }); }
  incidents.unshift(incident);
  if (incidents.length > 5000) incidents.pop();
  addLog("server", severity === "CRITICAL" ? "error" : "warn", `Incident: ${type}`, incident);
  broadcast({ event: "incident", data: incident });
  notifyTelegram(incident);
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
  const { status, comment } = req.body;
  if (status) { incident.status = status; try { db.updateIncident(req.params.id, { status }); } catch (_) {} }
  if (comment) { incident.comment = comment; try { db.updateIncident(req.params.id, { comment }); } catch (_) {} }
  broadcast({ event: "incident_updated", data: incident });
  res.json(incident);
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

// ── AI ───────────────────────────────────────────────────────────────────────
app.post("/api/ai/task", async (req, res) => {
  const { model, task, systemPrompt } = req.body;
  const apiKey = req.headers["x-api-key"];
  const isLocal = req.ip === "::1" || req.ip === "127.0.0.1" || req.ip === "::ffff:127.0.0.1";
  if (apiKey !== WSS_SECRET_TOKEN && !isLocal) return res.status(403).json({ error: "Unauthorized" });
  try {
    sanitizeAIInput(task);
    const msgs = [{ role: "system", content: AI_SAFETY_RULES }];
    if (systemPrompt) msgs.push({ role: "system", content: systemPrompt });
    msgs.push({ role: "user", content: task });
    const result = await askAI(model || activeModel, msgs);
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

// ── Scans ────────────────────────────────────────────────────────────────────
app.post("/api/scan/semgrep", async (req, res) => {
  const { targetDir, rules } = req.body;
  const result = runSemgrep(targetDir || __dirname, rules);
  res.json(result);
});
app.post("/api/scan/trivy", async (req, res) => {
  const { target, scanType } = req.body;
  const result = runTrivy(target || ".", scanType || "fs");
  res.json(result);
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
    const ip = req.socket.remoteAddress;
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
            ws.send(JSON.stringify({ event: "auth_success", data: { clientId, model: activeModel } }));
            addLog("server", "info", "WS client authenticated", { clientId, ip });
            // Сразу шлём снапшот
            ws.send(JSON.stringify({ event: "stats", data: { ...db.getStats(), connectedClients: clients.size } }));
            ws.send(JSON.stringify({ event: "incidents_list", data: incidents.slice(0, 100) }));
            ws.send(JSON.stringify({ event: "logs_list", data: serverLogs.slice(0, 200) }));
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
          ws.send(JSON.stringify({ event: "logs_list", data: data.slice(0, limit) })); return;
        }
        if (msg.event === "get_stats") {
          ws.send(JSON.stringify({ event: "stats", data: { ...db.getStats(), connectedClients: clients.size } })); return;
        }
        if (msg.event === "ai_task") {
          const { task, model, systemPrompt } = msg.data || {};
          try {
            sanitizeAIInput(task);
            const msgs = [{ role: "system", content: AI_SAFETY_RULES }];
            if (systemPrompt) msgs.push({ role: "system", content: systemPrompt });
            msgs.push({ role: "user", content: task });
            const result = await askAI(model || activeModel, msgs);
            ws.send(JSON.stringify({ event: "ai_result", data: { model: model || activeModel, result, task } }));
          } catch (err) { ws.send(JSON.stringify({ event: "ai_error", data: { error: err.message } })); }
          return;
        }
        if (msg.event === "switch_model") {
          const { model } = msg.data || {};
          if (MODELS[model] || Object.values(MODELS).some(m => m.id === model)) {
            activeModel = MODELS[model]?.id || model;
            broadcast({ event: "model_changed", data: { model: activeModel } });
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

function start() {
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