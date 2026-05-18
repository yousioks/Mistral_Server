require('dotenv').config();

const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const WebSocket = require('ws');
const cors = require('cors');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const OpenAI = require('openai');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const db = require('./db.js');
const { runSemgrep, runTrivy } = require('./scanners.js');

const {
  AITUNNEL_API_KEY,
  AITUNNEL_BASE_URL = 'https://api.aitunnel.ru/v1/',
  WSS_PORT = 8443,
  API_PORT = 8080,
  WSS_CERT_PATH = './certs/cert.pem',
  WSS_KEY_PATH = './certs/key.pem',
  WSS_SECRET_TOKEN,
  LOG_LEVEL = 'info',
  LOG_RETENTION_DAYS = '30',
} = process.env;

const MODELS = {
  deepseek: { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro', default: true },
  kimi: { id: 'kimi-k2.6', name: 'Kimi K2.6', default: false },
  claude: { id: 'claude-sonnet-4.6', name: 'Claude Sonnet 4.6', default: false },
};

let activeModel = MODELS.deepseek.id;

const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ level, message, timestamp, ...meta }) => {
    const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    return `${timestamp} [${level.toUpperCase()}] ${message}${metaStr}`;
  })
);

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: logFormat,
  transports: [
    new winston.transports.Console(),
    new DailyRotateFile({
      filename: path.join(logDir, 'server-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxFiles: `${LOG_RETENTION_DAYS}d`,
      zippedArchive: true,
    }),
    new DailyRotateFile({
      filename: path.join(logDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxFiles: `${LOG_RETENTION_DAYS}d`,
      zippedArchive: true,
    }),
  ],
});

const AI_ALLOWED_ORIGINS = new Set(['bot', 'client']);

const AI_SAFETY_RULES = `
STRICT OPERATIONAL RULES — You are a defensive security assistant.
1. NEVER block port 22 (SSH). Never modify firewall rules that could lock out the administrator.
2. NEVER stop nginx or modify SSL certificates. Website availability is paramount.
3. NEVER delete system files, logs, or configuration files.
4. NEVER create new user accounts or modify authentication systems without explicit approval.
5. NEVER run commands that could cause denial of service.
6. ALWAYS explain what you plan to do BEFORE doing it.
7. ALWAYS prefer monitoring and reporting over active intervention.
8. If unsure, ask for confirmation. Safety > Speed.
`;

function sanitizeAIInput(task) {
  const forbidden = [
    /ufw\s+(disable|reset|deny.*22|delete.*22)/i,
    /iptables\s+.*-p\s+tcp\s+--dport\s+22/i,
    /systemctl\s+(stop|restart)\s+nginx/i,
    /rm\s+-rf\s+\//i,
    /mkfs\./i,
    /dd\s+if=/i,
    /:\(\)\{\s*:\|:\s*&\s*\};/i,
  ];
  for (const pattern of forbidden) {
    if (pattern.test(task)) {
      throw new Error(`FORBIDDEN: Task contains dangerous pattern matching ${pattern}`);
    }
  }
  return true;
}

function isAICallerAuthorized(callerType, token) {
  if (!AI_ALLOWED_ORIGINS.has(callerType)) return false;
  if (callerType === 'client' && token !== WSS_SECRET_TOKEN) return false;
  return true;
}

const incidents = [];
const serverLogs = [];
const botLogs = [];
const cveLogs = [];
const clients = new Map();
const telegramSessions = new Map();
const usedTokens = new Set();

function addLog(type, level, message, meta = {}) {
  const entry = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    type,
    level,
    message,
    meta,
  };
  try { db.addLog(entry); } catch (e) { logger.error('DB addLog failed', e); }
  if (type === 'server') serverLogs.push(entry);
  if (type === 'bot') botLogs.push(entry);
  if (type === 'cve') cveLogs.push(entry);
  if (serverLogs.length > 10000) serverLogs.shift();
  if (botLogs.length > 10000) botLogs.shift();
  if (cveLogs.length > 10000) cveLogs.shift();
  logger.log(level, `[${type}] ${message}`, meta);
  broadcast({ event: 'log', data: entry });
  return entry;
}

function addIncident(severity, monitor, type, description, details = {}) {
  const incident = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    severity,
    monitor,
    type,
    description,
    details,
    status: 'new',
  };
  try { db.addIncident(incident); } catch (e) { logger.error('DB addIncident failed', e); }
  incidents.unshift(incident);
  if (incidents.length > 5000) incidents.pop();
  addLog('server', severity === 'CRITICAL' ? 'error' : 'warn', `Incident: ${type}`, incident);
  broadcast({ event: 'incident', data: incident });
  return incident;
}

const aiClient = new OpenAI({
  apiKey: AITUNNEL_API_KEY,
  baseURL: AITUNNEL_BASE_URL,
});

async function askAI(model, messages, temperature = 0.3) {
  try {
    const response = await aiClient.chat.completions.create({ model, messages, temperature });
    return response.choices[0].message.content;
  } catch (err) {
    logger.error('AI request failed', { error: err.message, model });
    throw err;
  }
}

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), model: activeModel, timestamp: new Date().toISOString() });
});

app.get('/api/logs', (req, res) => {
  const { type = 'server', limit = 100, offset = 0, level, startDate, endDate } = req.query;
  try {
    const data = db.getLogs({ type, limit: Number(limit), offset: Number(offset), level, startDate, endDate });
    const total = db.countLogs(type, '1970-01-01');
    res.json({ total, offset: Number(offset), limit: Number(limit), data });
  } catch (e) {
    let data = type === 'bot' ? botLogs : type === 'cve' ? cveLogs : serverLogs;
    if (level) data = data.filter(l => l.level === level);
    if (startDate) data = data.filter(l => l.timestamp >= startDate);
    if (endDate) data = data.filter(l => l.timestamp <= endDate);
    const total = data.length;
    const paginated = data.slice(Number(offset), Number(offset) + Number(limit));
    res.json({ total, offset: Number(offset), limit: Number(limit), data: paginated });
  }
});

app.get('/api/incidents', (req, res) => {
  const { severity, limit = 100, offset = 0 } = req.query;
  try {
    const data = db.getIncidents({ severity, limit: Number(limit), offset: Number(offset) });
    res.json({ total: data.length, offset: Number(offset), limit: Number(limit), data });
  } catch (e) {
    let data = incidents;
    if (severity) data = data.filter(i => i.severity === severity);
    const total = data.length;
    const paginated = data.slice(Number(offset), Number(offset) + Number(limit));
    res.json({ total, offset: Number(offset), limit: Number(limit), data: paginated });
  }
});

app.get('/api/incidents/:id', (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id);
  if (!incident) return res.status(404).json({ error: 'Not found' });
  res.json(incident);
});

app.patch('/api/incidents/:id', (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id);
  if (!incident) return res.status(404).json({ error: 'Not found' });
  const { status, comment } = req.body;
  if (status) { incident.status = status; try { db.updateIncident(req.params.id, { status }); } catch (e) {} }
  if (comment) { incident.comment = comment; try { db.updateIncident(req.params.id, { comment }); } catch (e) {} }
  addLog('server', 'info', `Incident ${incident.id} updated`, { status, comment });
  broadcast({ event: 'incident_updated', data: incident });
  res.json(incident);
});

app.post('/api/ai/task', async (req, res) => {
  const { model, task, systemPrompt, caller = 'api' } = req.body;
  const apiKey = req.headers['x-api-key'];
  if (caller !== 'bot' && apiKey !== WSS_SECRET_TOKEN) {
    addLog('server', 'warn', 'Unauthorized AI API call blocked', { caller, ip: req.ip });
    return res.status(403).json({ error: 'AI access denied — unauthorized caller' });
  }
  const selectedModel = model || activeModel;
  try {
    sanitizeAIInput(task);
    const messages = [{ role: 'system', content: AI_SAFETY_RULES }];
    if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
    messages.push({ role: 'user', content: task });
    const result = await askAI(selectedModel, messages);
    addLog('server', 'info', 'AI task completed', { model: selectedModel, taskPreview: task.slice(0, 200), caller });
    res.json({ model: selectedModel, result });
  } catch (err) {
    addLog('server', 'error', 'AI task failed', { error: err.message, caller });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (db.verifyUser(username, password)) {
    addLog('server', 'info', `User ${username} logged in`);
    res.json({ success: true, token: WSS_SECRET_TOKEN });
  } else {
    addLog('server', 'warn', `Failed login attempt for user ${username}`);
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
});

  if (!MODELS[model] && !Object.values(MODELS).some(m => m.id === model)) {
    return res.status(400).json({ error: 'Unknown model' });
  }
  activeModel = MODELS[model]?.id || model;
  addLog('server', 'info', `AI model switched to ${activeModel}`);
  broadcast({ event: 'model_changed', data: { model: activeModel } });
  res.json({ model: activeModel });
});

app.post('/api/logs', (req, res) => {
  const { type = 'server', level = 'info', message, meta = {} } = req.body;
  const entry = addLog(type, level, message, meta);
  res.json({ received: true, logId: entry.id });
});

app.post('/api/bot-log', (req, res) => {
  const { level = 'info', message, meta = {} } = req.body;
  const entry = addLog('bot', level, message, meta);
  res.json({ received: true, logId: entry.id });
});

app.post('/api/cve-log', (req, res) => {
  const { level = 'info', message, meta = {} } = req.body;
  const entry = addLog('cve', level, message, meta);
  res.json({ received: true, logId: entry.id });
});

app.get('/api/stats', (_req, res) => {
  try {
    res.json({ ...db.getStats(), connectedClients: clients.size });
  } catch (e) {
    const today = new Date().toISOString().slice(0, 10);
    const weekAgo = new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
    const monthAgo = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
    const countLogs = (arr, since) => arr.filter(l => l.timestamp >= since).length;
    res.json({
      incidents: {
        critical: incidents.filter(i => i.severity === 'CRITICAL').length,
        high: incidents.filter(i => i.severity === 'HIGH').length,
        medium: incidents.filter(i => i.severity === 'MEDIUM').length,
        low: incidents.filter(i => i.severity === 'LOW').length,
      },
      logs: { today: countLogs(serverLogs, today), week: countLogs(serverLogs, weekAgo), month: countLogs(serverLogs, monthAgo) },
      botLogs: { today: countLogs(botLogs, today), week: countLogs(botLogs, weekAgo), month: countLogs(botLogs, monthAgo) },
      cveLogs: cveLogs.length,
      connectedClients: clients.size,
    });
  }
});

app.post('/api/attack-detected', (req, res) => {
  const { type, sourceIp, path, payload, severity = 'HIGH' } = req.body;
  const incident = addIncident(severity, 'Remon-WAF', type, `Attack detected: ${type} from ${sourceIp} on ${path}`, { sourceIp, path, payload });
  addLog('server', 'warn', `Attack detected via middleware: ${type}`, { sourceIp, path });
  res.json({ received: true, incidentId: incident.id });
});

app.post('/api/metrics', (req, res) => {
  const payload = req.body;
  const { monitor, hostname, timestamp, anomalies = [] } = payload;
  broadcast({ event: 'metrics', data: { ...payload, receivedAt: new Date().toISOString() } });
  addLog('server', 'info', `Metrics received from ${monitor || 'unknown'}`, payload);

  // Auto-create incidents from monitor anomalies
  for (const a of anomalies) {
    addIncident(a.severity || 'HIGH', a.monitor || monitor || 'Monitor', a.type || 'anomaly', a.description || `${a.type}=${a.value}`, payload);
  }

  res.json({ received: true, anomaliesProcessed: anomalies.length });
});

app.post('/api/incidents', (req, res) => {
  const { severity, monitor, type, description, details = {} } = req.body;
  if (!severity || !monitor || !type || !description) {
    return res.status(400).json({ error: 'Missing required fields: severity, monitor, type, description' });
  }
  const incident = addIncident(severity, monitor, type, description, details);
  res.json({ received: true, incidentId: incident.id });
});

// Scan API endpoints
app.post('/api/scan/semgrep', async (req, res) => {
  const { targetDir, rules } = req.body;
  addLog('server', 'info', `Semgrep scan started`, { targetDir });
  const result = runSemgrep(targetDir || __dirname, rules);
  result.findings.forEach(f => addLog('server', f.severity === 'CRITICAL' ? 'error' : 'warn', `Semgrep: ${f.message}`, f));
  res.json(result);
});

app.post('/api/scan/trivy', async (req, res) => {
  const { target, scanType } = req.body;
  addLog('server', 'info', `Trivy scan started`, { target, scanType });
  const result = runTrivy(target || '.', scanType || 'fs');
  result.findings.forEach(f => addLog('server', f.severity === 'CRITICAL' ? 'error' : 'warn', `Trivy: ${f.title}`, f));
  res.json(result);
});

function broadcast(msg) {
  const data = JSON.stringify(msg);
  for (const [ws, info] of clients.entries()) {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(data); } catch (e) { logger.error('WS broadcast error', e); }
    }
  }
}

function startWSS(server) {
  const wss = new WebSocket.Server({ server, path: '/ws' });

  wss.on('connection', (ws, req) => {
    const clientId = uuidv4();
    const ip = req.socket.remoteAddress;
    let authTimer = setTimeout(() => {
      if (!clients.get(ws)?.authenticated) {
        addLog('server', 'warn', 'WS client failed to authenticate in time', { clientId, ip });
        ws.close(4001, 'Authentication timeout');
      }
    }, 5000);

    clients.set(ws, { id: clientId, ip, connectedAt: new Date().toISOString(), authenticated: false });
    addLog('server', 'info', `WS client connected (awaiting auth)`, { clientId, ip });

    ws.on('message', async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        const client = clients.get(ws);
        addLog('server', 'debug', 'WS message received', { event: msg.event, clientId: client?.id });

        if (msg.event === 'auth') {
          const { token, nonce } = msg.data || {};
          if (!token || !nonce) {
            ws.send(JSON.stringify({ event: 'auth_error', data: { error: 'Missing token or nonce' } }));
            return;
          }
          if (usedTokens.has(nonce)) {
            addLog('server', 'warn', 'WS nonce replay attack detected', { clientId, ip, nonce });
            ws.close(4002, 'Replay detected');
            return;
          }
          if (token === WSS_SECRET_TOKEN) {
            usedTokens.add(nonce);
            client.authenticated = true;
            client.authToken = token;
            clearTimeout(authTimer);
            ws.send(JSON.stringify({ event: 'auth_success', data: { clientId, model: activeModel } }));
            addLog('server', 'info', 'WS client authenticated', { clientId, ip });
          } else {
            addLog('server', 'warn', 'WS authentication failed: invalid token', { clientId, ip });
            ws.close(4003, 'Invalid token');
          }
          return;
        }

        if (!client?.authenticated) {
          addLog('server', 'warn', 'Unauthorized WS message blocked', { event: msg.event, clientId, ip });
          ws.send(JSON.stringify({ event: 'error', data: { error: 'Unauthorized — authenticate first' } }));
          return;
        }

        if (msg.event === 'ping') {
          ws.send(JSON.stringify({ event: 'pong', timestamp: Date.now() }));
          return;
        }

        if (msg.event === 'get_incidents') {
          ws.send(JSON.stringify({ event: 'incidents_list', data: incidents.slice(0, 100) }));
          return;
        }

        if (msg.event === 'get_logs') {
          const { type = 'server', limit = 100 } = msg.data || {};
          const data = type === 'bot' ? botLogs : type === 'cve' ? cveLogs : serverLogs;
          ws.send(JSON.stringify({ event: 'logs_list', data: data.slice(0, limit) }));
          return;
        }

        if (msg.event === 'get_stats') {
          const today = new Date().toISOString().slice(0, 10);
          const weekAgo = new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
          const monthAgo = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
          const countLogs = (arr, since) => arr.filter(l => l.timestamp >= since).length;
          ws.send(JSON.stringify({
            event: 'stats',
            data: {
              incidents: {
                critical: incidents.filter(i => i.severity === 'CRITICAL').length,
                high: incidents.filter(i => i.severity === 'HIGH').length,
                medium: incidents.filter(i => i.severity === 'MEDIUM').length,
                low: incidents.filter(i => i.severity === 'LOW').length,
              },
              logs: { today: countLogs(serverLogs, today), week: countLogs(serverLogs, weekAgo), month: countLogs(serverLogs, monthAgo) },
              botLogs: { today: countLogs(botLogs, today), week: countLogs(botLogs, weekAgo), month: countLogs(botLogs, monthAgo) },
              cveLogs: cveLogs.length,
              connectedClients: clients.size,
            },
          }));
          return;
        }

        if (msg.event === 'ai_task') {
          const { task, model, systemPrompt } = msg.data || {};
          if (!isAICallerAuthorized('client', client.authToken)) {
            addLog('server', 'warn', 'Blocked unauthorized AI task attempt', { clientId, ip });
            ws.send(JSON.stringify({ event: 'ai_error', data: { error: 'AI access denied — unauthorized caller' } }));
            return;
          }
          const selectedModel = model || activeModel;
          try {
            sanitizeAIInput(task);
            const messages = [{ role: 'system', content: AI_SAFETY_RULES }];
            if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
            messages.push({ role: 'user', content: task });
            const result = await askAI(selectedModel, messages);
            ws.send(JSON.stringify({ event: 'ai_result', data: { model: selectedModel, result, task } }));
            addLog('server', 'info', 'AI task via WS completed', { model: selectedModel, clientId: client?.id });
          } catch (err) {
            ws.send(JSON.stringify({ event: 'ai_error', data: { error: err.message } }));
            addLog('server', 'error', 'AI task failed', { error: err.message, clientId: client?.id });
          }
          return;
        }

        if (msg.event === 'switch_model') {
          const { model } = msg.data || {};
          if (MODELS[model] || Object.values(MODELS).some(m => m.id === model)) {
            activeModel = MODELS[model]?.id || model;
            broadcast({ event: 'model_changed', data: { model: activeModel } });
            addLog('server', 'info', `Model switched via WS to ${activeModel}`, { clientId: client?.id });
          }
          return;
        }

        if (msg.event === 'run_scan') {
          const { scanType, target } = msg.data || {};
          ws.send(JSON.stringify({ event: 'scan_started', data: { scanType, target } }));
          addLog('server', 'info', `Scan requested: ${scanType}`, { clientId: client?.id, target });
          if (scanType === 'semgrep') {
            runSemgrep(target || __dirname).then(r => broadcast({ event: 'scan_result', data: r }));
          } else if (scanType === 'trivy') {
            runTrivy(target || '.', 'fs').then(r => broadcast({ event: 'scan_result', data: r }));
          }
          return;
        }

        broadcast({ event: 'relay', from: client?.id, data: msg });
      } catch (err) {
        logger.error('WS message handling error', { error: err.message, raw: raw.toString().slice(0, 200) });
      }
    });

    ws.on('close', () => {
      const client = clients.get(ws);
      clients.delete(ws);
      addLog('server', 'info', `WS client disconnected`, { clientId: client?.id });
    });

    ws.on('error', (err) => {
      logger.error('WS error', { error: err.message });
    });
  });

  return wss;
}

function ensureCerts() {
  const certDir = path.dirname(WSS_CERT_PATH);
  if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });
  if (!fs.existsSync(WSS_CERT_PATH) || !fs.existsSync(WSS_KEY_PATH)) {
    try {
      const { execSync } = require('child_process');
      execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${WSS_KEY_PATH}" -out "${WSS_CERT_PATH}" -days 365 -nodes -subj "/CN=localhost"`, { stdio: 'ignore' });
      logger.info('Self-signed certificate generated for WSS');
    } catch (e) {
      logger.warn('Failed to generate self-signed cert, falling back to HTTP+WS', { error: e.message });
      return null;
    }
  }
  return { cert: fs.readFileSync(WSS_CERT_PATH), key: fs.readFileSync(WSS_KEY_PATH) };
}

function start() {
  const certs = ensureCerts();
  let server;
  if (certs) {
    server = https.createServer(certs, app);
    logger.info(`Starting HTTPS+WSS server on port ${WSS_PORT}`);
  } else {
    const http = require('http');
    server = http.createServer(app);
    logger.info(`Starting HTTP+WS server on port ${API_PORT}`);
  }

  const port = certs ? WSS_PORT : API_PORT;
  server.listen(port, () => {
    logger.info(`Server listening on port ${port}`);
    addLog('server', 'info', `MISTRAL server started on port ${port}`, { model: activeModel });
  });

  startWSS(server);

  process.on('SIGINT', () => {
    logger.info('Shutting down...');
    server.close(() => process.exit(0));
  });
}

if (require.main === module) {
  start();
}

module.exports = {
  addLog,
  addIncident,
  askAI,
  broadcast,
  incidents,
  serverLogs,
  botLogs,
  cveLogs,
  clients,
  telegramSessions,
  MODELS,
  AI_SAFETY_RULES,
  get activeModel() { return activeModel; },
  set activeModel(v) { activeModel = v; },
};
