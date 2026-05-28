const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../data', 'mistral.db');

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      severity TEXT NOT NULL,
      monitor TEXT,
      type TEXT NOT NULL,
      description TEXT,
      details TEXT,
      status TEXT DEFAULT 'new',
      comment TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      type TEXT NOT NULL,
      level TEXT NOT NULL,
      message TEXT NOT NULL,
      meta TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_logs_type_timestamp ON logs(type, timestamp);
    CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

    CREATE TABLE IF NOT EXISTS cve_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      level TEXT,
      message TEXT,
      meta TEXT,
      status TEXT DEFAULT 'new',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS bot_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      level TEXT,
      message TEXT,
      meta TEXT,
      chat_id TEXT,
      nickname TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      chat_id TEXT,
      nickname TEXT,
      role TEXT DEFAULT 'operator',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

initSchema();

// Миграция старых БД — добавить колонки если нет
['chat_id TEXT', 'nickname TEXT', 'role TEXT DEFAULT \'operator\''].forEach(col => {
  try { db.exec(`ALTER TABLE users ADD COLUMN ${col}`); } catch (_) {}
});

// Дефолтный admin если таблица пустая
const adminExists = db.prepare('SELECT count(*) as count FROM users').get();
if (adminExists.count === 0) {
  const hash = bcrypt.hashSync('admin', 10);
  db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run('admin', hash, 'admin');
  console.log('[DB] Default admin created: login=admin password=admin');
}

// --- Users ---
function verifyUser(username, password) {
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return false;
  // Поддержка plain-text паролей (старые записи) — апгрейд до bcrypt на лету
  if (!user.password.startsWith('$2')) {
    if (user.password !== password) return false;
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, user.id);
    return true;
  }
  return bcrypt.compareSync(password, user.password);
}

function addUser(username, password, chatId, nickname, role) {
  const hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare('INSERT INTO users (username, password, chat_id, nickname, role) VALUES (?, ?, ?, ?, ?)')
      .run(username, hash, chatId || null, nickname || username, role || 'operator');
    return true;
  } catch (e) {
    if (e.message.includes('UNIQUE')) return false;
    throw e;
  }
}

function getAllUsers() {
  return db.prepare('SELECT id, username, chat_id, nickname, role, created_at FROM users').all();
}

function getUserByChatId(chatId) {
  return db.prepare('SELECT * FROM users WHERE chat_id = ?').get(String(chatId));
}

function updateUserChatId(username, chatId) {
  db.prepare('UPDATE users SET chat_id = ? WHERE username = ?').run(String(chatId), username);
}

// Все chat_id для рассылки уведомлений
function getAllChatIds() {
  return db.prepare('SELECT chat_id FROM users WHERE chat_id IS NOT NULL AND chat_id != \'\'').all().map(r => r.chat_id);
}

// --- Incidents ---
function addIncident(incident) {
  db.prepare(`
    INSERT INTO incidents (id, timestamp, severity, monitor, type, description, details, status)
    VALUES (@id, @timestamp, @severity, @monitor, @type, @description, @details, @status)
  `).run({
    id: incident.id || uuidv4(),
    timestamp: incident.timestamp || new Date().toISOString(),
    severity: incident.severity,
    monitor: incident.monitor || null,
    type: incident.type,
    description: incident.description,
    details: JSON.stringify(incident.details || {}),
    status: incident.status || 'new',
  });
  return incident;
}

function getIncidents({ severity, limit = 100, offset = 0 } = {}) {
  let sql = 'SELECT * FROM incidents WHERE 1=1';
  const params = [];
  if (severity) { sql += ' AND severity = ?'; params.push(severity); }
  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  return db.prepare(sql).all(...params);
}

function updateIncident(id, { status, comment }) {
  const sets = [];
  const params = [];
  if (status) { sets.push('status = ?'); params.push(status); }
  if (comment !== undefined) { sets.push('comment = ?'); params.push(comment); }
  if (sets.length === 0) return;
  params.push(id);
  db.prepare(`UPDATE incidents SET ${sets.join(', ')} WHERE id = ?`).run(...params);
}

// --- Logs ---
function addLog(entry) {
  db.prepare(`
    INSERT INTO logs (id, timestamp, type, level, message, meta)
    VALUES (@id, @timestamp, @type, @level, @message, @meta)
  `).run({
    id: entry.id || uuidv4(),
    timestamp: entry.timestamp || new Date().toISOString(),
    type: entry.type,
    level: entry.level,
    message: entry.message,
    meta: JSON.stringify(entry.meta || {}),
  });
}

function getLogs({ type = 'server', level, startDate, endDate, limit = 100, offset = 0 } = {}) {
  let sql = 'SELECT * FROM logs WHERE type = ?';
  const params = [type];
  if (level) { sql += ' AND level = ?'; params.push(level); }
  if (startDate) { sql += ' AND timestamp >= ?'; params.push(startDate); }
  if (endDate) { sql += ' AND timestamp <= ?'; params.push(endDate); }
  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  return db.prepare(sql).all(...params);
}

function countLogs(type, since) {
  return db.prepare('SELECT COUNT(*) as count FROM logs WHERE type = ? AND timestamp >= ?')
    .get(type, since).count;
}

// --- CVE Logs ---
function addCveLog(entry) {
  db.prepare(`
    INSERT INTO cve_logs (id, timestamp, level, message, meta, status)
    VALUES (@id, @timestamp, @level, @message, @meta, @status)
  `).run({
    id: entry.id || uuidv4(),
    timestamp: entry.timestamp || new Date().toISOString(),
    level: entry.level || 'info',
    message: entry.message,
    meta: JSON.stringify(entry.meta || {}),
    status: entry.status || 'new',
  });
}

function getCveLogs(limit = 100) {
  return db.prepare('SELECT * FROM cve_logs ORDER BY timestamp DESC LIMIT ?').all(limit);
}

// --- Bot Logs ---
function addBotLog(entry) {
  const chatId = entry.meta && entry.meta.chatId ? entry.meta.chatId : null;
  const nickname = entry.meta && entry.meta.nickname ? entry.meta.nickname : null;
  db.prepare(`
    INSERT INTO bot_logs (id, timestamp, level, message, meta, chat_id, nickname)
    VALUES (@id, @timestamp, @level, @message, @meta, @chat_id, @nickname)
  `).run({
    id: entry.id || uuidv4(),
    timestamp: entry.timestamp || new Date().toISOString(),
    level: entry.level || 'info',
    message: entry.message,
    meta: JSON.stringify(entry.meta || {}),
    chat_id: chatId,
    nickname: nickname,
  });
}

function getBotLogs(limit = 100) {
  return db.prepare('SELECT * FROM bot_logs ORDER BY timestamp DESC LIMIT ?').all(limit);
}

// --- Stats ---
function getStats() {
  const today = new Date().toISOString().slice(0, 10);
  const weekAgo = new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
  const monthAgo = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
  return {
    incidents: {
      critical: db.prepare("SELECT COUNT(*) as c FROM incidents WHERE severity = 'CRITICAL'").get().c,
      high: db.prepare("SELECT COUNT(*) as c FROM incidents WHERE severity = 'HIGH'").get().c,
      medium: db.prepare("SELECT COUNT(*) as c FROM incidents WHERE severity = 'MEDIUM'").get().c,
      low: db.prepare("SELECT COUNT(*) as c FROM incidents WHERE severity = 'LOW'").get().c,
    },
    logs: {
      today: countLogs('server', today),
      week: countLogs('server', weekAgo),
      month: countLogs('server', monthAgo),
    },
    botLogs: {
      today: countLogs('bot', today),
      week: countLogs('bot', weekAgo),
      month: countLogs('bot', monthAgo),
    },
    cveLogs: db.prepare('SELECT COUNT(*) as c FROM cve_logs').get().c,
  };
}

function cleanupOld(days = 90) {
  const cutoff = new Date(Date.now() - days * 864e5).toISOString();
  db.prepare('DELETE FROM logs WHERE timestamp < ?').run(cutoff);
  db.prepare('DELETE FROM bot_logs WHERE timestamp < ?').run(cutoff);
  db.prepare('DELETE FROM cve_logs WHERE timestamp < ?').run(cutoff);
  db.prepare('DELETE FROM incidents WHERE timestamp < ? AND status = ?').run(cutoff, 'resolved');
}

setInterval(() => cleanupOld(30), 24 * 60 * 60 * 1000);

module.exports = {
  addIncident, getIncidents, updateIncident,
  addLog, getLogs, countLogs,
  addCveLog, getCveLogs,
  addBotLog, getBotLogs,
  getStats, cleanupOld,
  verifyUser, addUser, getAllUsers,
  getUserByChatId, updateUserChatId, getAllChatIds,
};
