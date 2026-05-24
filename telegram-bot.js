require("dotenv").config();
const http = require("http");
const express = require("express");
const TelegramBot = require("node-telegram-bot-api");
const db = require("./db.js");

const API_PORT = process.env.API_PORT || 8080;
const BOT_HTTP_PORT = process.env.BOT_HTTP_PORT || 8081;
const { TELEGRAM_BOT_TOKEN } = process.env;

if (!TELEGRAM_BOT_TOKEN) {
  console.error("[Bot] TELEGRAM_BOT_TOKEN не задан в .env");
  process.exit(1);
}

const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
console.log("[Bot] MISTRAL Telegram Bot запущен. Polling...");

function apiRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = { hostname: "localhost", port: Number(API_PORT), path, method, headers: { "Content-Type": "application/json" } };
    if (data) opts.headers["Content-Length"] = Buffer.byteLength(data);
    const req = http.request(opts, (res) => {
      let raw = "";
      res.on("data", c => raw += c);
      res.on("end", () => { try { resolve(JSON.parse(raw)); } catch { resolve(raw); } });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

async function reply(chatId, text, opts = {}) {
  try { return await bot.sendMessage(chatId, text, { parse_mode: "HTML", ...opts }); }
  catch (err) { console.error("[Bot] sendMessage error:", err.message); }
}

async function broadcastAlert(severity, type, description) {
  const chatIds = db.getAllChatIds();
  if (!chatIds.length) { console.log("[Bot] Нет chat_id в БД"); return; }
  const emoji = severity === "CRITICAL" ? "🚨" : severity === "HIGH" ? "⚠️" : "ℹ️";
  let text = `${emoji} <b>MISTRAL ALERT</b>\n\nУровень: <b>${severity}</b>\nТип: <b>${type}</b>\nОписание: ${description}\n\n<i>${new Date().toLocaleString("ru-RU")}</i>`;
  if (severity === "CRITICAL" || severity === "HIGH") text += "\n\n🔴 <b>ВОЗМОЖНА УТЕЧКА — ТРЕБУЕТСЯ ВМЕШАТЕЛЬСТВО!</b>";
  for (const chatId of chatIds) await reply(chatId, text);
}

const pending = new Map();
const sessions = new Map();

function mainMenu() {
  return { reply_markup: { keyboard: [[{ text: "📊 Статус" }, { text: "📋 Инциденты" }], [{ text: "📝 Логи" }, { text: "👥 Пользователи" }]], resize_keyboard: true } };
}

async function showMenu(chatId, username) {
  await reply(chatId, `👋 Привет, <b>${username}</b>!\n\nMISTRAL Defense активна. Выберите раздел:`, mainMenu());
}

bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  if (sessions.get(chatId)?.authenticated) { await showMenu(chatId, sessions.get(chatId).username); return; }
  pending.set(chatId, { step: "login" });
  await reply(chatId, "🔐 <b>MISTRAL Defense</b>\n\nВведите логин:", { reply_markup: { remove_keyboard: true } });
});

bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  const text = (msg.text || "").trim();
  const state = pending.get(chatId);

  if (state && state.step === "login") {
    pending.set(chatId, { step: "password", username: text });
    await reply(chatId, "Введите пароль:", { reply_markup: { remove_keyboard: true } });
    return;
  }

  if (state && state.step === "password") {
    const { username } = state;
    const ok = db.verifyUser(username, text);
    pending.delete(chatId);
    if (ok) {
      db.updateUserChatId(username, String(chatId));
      sessions.set(chatId, { authenticated: true, username });
      apiRequest("POST", "/api/bot-log", { level: "info", message: `Telegram login: ${username}`, meta: { chatId: String(chatId), username } }).catch(() => {});
      await showMenu(chatId, username);
    } else {
      await reply(chatId, "❌ Неверный логин или пароль.\n/start — повторить.");
    }
    return;
  }

  if (!sessions.get(chatId)?.authenticated) { await reply(chatId, "🔒 Требуется авторизация. /start"); return; }

  const username = sessions.get(chatId).username;

  if (text === "📊 Статус") {
    try {
      const stats = await apiRequest("GET", "/api/stats");
      const inc = stats.incidents || {}, logs = stats.logs || {};
      await reply(chatId, `📊 <b>Статус системы</b>\n\n🚨 Критических: <b>${inc.critical||0}</b>\n⚠️ Высоких: <b>${inc.high||0}</b>\n🟡 Средних: <b>${inc.medium||0}</b>\n🟢 Низких: <b>${inc.low||0}</b>\n\n📝 Логов сегодня: <b>${logs.today||0}</b>\n📝 За неделю: <b>${logs.week||0}</b>\n👥 Онлайн: <b>${stats.connectedClients||0}</b>`, mainMenu());
    } catch (e) { await reply(chatId, "⚠️ Сервер недоступен", mainMenu()); }
    return;
  }

  if (text === "📋 Инциденты") {
    try {
      const data = await apiRequest("GET", "/api/incidents?limit=10");
      const list = (data.data || []).slice(0,10).map(i => `• [${i.severity}] ${i.type}: ${(i.description||"").slice(0,80)}`).join("\n") || "Инцидентов нет.";
      await reply(chatId, `📋 <b>Последние инциденты:</b>\n\n${list}`, mainMenu());
    } catch (e) { await reply(chatId, "⚠️ Ошибка", mainMenu()); }
    return;
  }

  if (text === "📝 Логи") {
    try {
      const data = await apiRequest("GET", "/api/logs?type=server&limit=10");
      const list = (data.data || []).slice(0,10).map(l => `• [${(l.level||"info").toUpperCase()}] ${(l.message||"").slice(0,80)}`).join("\n") || "Логов нет.";
      await reply(chatId, `📝 <b>Последние логи:</b>\n\n${list}`, mainMenu());
    } catch (e) { await reply(chatId, "⚠️ Ошибка", mainMenu()); }
    return;
  }

  if (text === "👥 Пользователи") {
    try {
      const users = db.getAllUsers();
      const list = users.map(u => `• <b>${u.username}</b> [${u.role}]${u.chat_id ? " 📱" : ""}`).join("\n") || "Нет пользователей.";
      await reply(chatId, `👥 <b>Пользователи системы:</b>\n\n${list}`, mainMenu());
    } catch (e) { await reply(chatId, "⚠️ Ошибка", mainMenu()); }
    return;
  }
});

// HTTP-сервер: принимает POST /api/bot-notify от server.js и рассылает алерты
const botApp = express();
botApp.use(express.json());
botApp.post("/api/bot-notify", async (req, res) => {
  const { severity, type, description } = req.body || {};
  if (severity && type && description) await broadcastAlert(severity, type, description);
  res.json({ ok: true });
});
botApp.listen(Number(BOT_HTTP_PORT), () => console.log(`[Bot] HTTP listener on port ${BOT_HTTP_PORT}`));