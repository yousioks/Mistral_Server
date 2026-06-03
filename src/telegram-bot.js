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

const incidentsMap = new Map();

async function broadcastAlert(incident) {
  const chatIds = db.getAllChatIds();
  if (!chatIds.length) { console.log("[Bot] Нет chat_id в БД"); return; }
  
  const { id, severity, type, description, contextBlock, timestamp } = incident;
  incidentsMap.set(id, incident);
  if (incidentsMap.size > 500) {
    const firstKey = incidentsMap.keys().next().value;
    incidentsMap.delete(firstKey);
  }

  const emoji = severity === "CRITICAL" ? "🚨" : severity === "HIGH" ? "⚠️" : severity === "MEDIUM" ? "🟡" : "🟢";
  let text = `${emoji} <b>MISTRAL ALERT</b>\n\n`;
  text += `Уровень: <b>${severity}</b>\n`;
  text += `Тип: <b>${type}</b>\n`;
  text += `Время: <i>${(timestamp||'').replace('T', ' ').slice(0, 19)}</i>\n\n`;
  text += `<b>Описание:</b>\n${description}\n`;

  const opts = {};
  
  if (severity === "CRITICAL" || severity === "HIGH") {
    text += `\n🔴 <b>ВНИМАНИЕ: СИСТЕМА ПОД УГРОЗОЙ!</b>\n`;
    opts.reply_markup = {
      inline_keyboard: [[{ text: "🧠 АНАЛИЗ ИИ", callback_data: `ai_${id}` }]]
    };
  }

  for (const chatId of chatIds) await reply(chatId, text, opts);
}

const pending = new Map();
const sessions = new Map();

function mainMenu() {
  return { reply_markup: { keyboard: [[{ text: "📊 Статус" }, { text: "🚨 Инциденты" }], [{ text: "📝 Логи" }, { text: "👥 Пользователи" }]], resize_keyboard: true } };
}

async function showMenu(chatId, username) {
  await reply(chatId, `👋 Привет, <b>${username}</b>!\n\n🛡 <b>MISTRAL Defense Command</b> активна.\nВыберите действие:`, mainMenu());
}

bot.onText(/\/start(.*)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const context = (match[1] || "").trim();

  // Обработка контекста с фронтенда (Remon)
  if (context === "register") {
    await reply(chatId, "📋 <b>Регистрация резидента Remon</b>\n\nЧтобы создать аккаунт, пожалуйста, перейдите на сайт:\n👉 <a href='https://raemon.ru/register'>Зарегистрироваться</a>");
    return;
  }
  if (context === "recover") {
    await reply(chatId, "🔑 <b>Восстановление пароля</b>\n\nДля восстановления доступа к аккаунту Remon, обратитесь в службу поддержки или перейдите по ссылке:\n👉 <a href='https://raemon.ru/recover'>Восстановить пароль</a>");
    return;
  }
  if (context === "login") {
    await reply(chatId, "🚪 <b>Вход для резидентов</b>\n\nДля входа в личный кабинет Remon перейдите на сайт:\n👉 <a href='https://raemon.ru/login'>Войти</a>\n\n<i>(Если вы администратор сервера MISTRAL, отправьте любой текст для начала авторизации)</i>");
    return;
  }

  // Стандартная авторизация администратора MISTRAL
  if (sessions.get(chatId)?.authenticated) { await showMenu(chatId, sessions.get(chatId).username); return; }
  pending.set(chatId, { step: "login" });
  await reply(chatId, "🔐 <b>MISTRAL Defense</b>\n\nВведите логин:", { reply_markup: { remove_keyboard: true } });
});

bot.on("callback_query", async (query) => {
  const chatId = query.message.chat.id;
  const data = query.data;

  if (data.startsWith("ai_")) {
    const incId = data.split("_")[1];
    bot.answerCallbackQuery(query.id, { text: "Отправка логов в ИИ..." });
    
    const inc = incidentsMap.get(incId);
    if (!inc) {
      await reply(chatId, "❌ Инцидент не найден в кэше.");
      return;
    }

    const waitMsg = await bot.sendMessage(chatId, "⏳ <b>ИИ анализирует...</b>\n<i>Проверяю логи, ищу аномалии...</i>", { parse_mode: "HTML" });
    
    try {
      const prompt = `ПРОТОКОЛ АВТОЗАЩИТЫ MISTRAL.
Проанализируй инцидент и предоставь подробный отчет строго в следующем формате:

1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
   [Подробное описание, почему включился ИИ-агент безопасности, оценка степени угрозы]

2. ПРЕДШЕСТВУЮЩЕЕ СОБЫТИЕ (ТРИГГЕР):
   [Детальный разбор события, которое вызвало алерт: тип инцидента, источник атаки, время, логи и контекст]

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ И МИТИГАЦИЯ:
   [Какие меры были предприняты или рекомендуются. Если требуется блокировка, укажи [AUTOBAN: ${inc.ip || ''}] и [INCIDENT_ID: ${inc.id}]]

4. РЕКОМЕНДАЦИИ ДЛЯ АДМИНИСТРАТОРА:
   [Дальнейшие шаги по укреплению защиты системы]

Контекст инцидента:
Тип атаки: ${inc.type}
Описание: ${inc.description}
Контекст логов:
${inc.contextBlock || "Нет логов"}`;
      
      const res = await apiRequest("POST", "/api/ai/task", { task: prompt });
      
      if (res.error) {
        await bot.editMessageText(`❌ Ошибка ИИ: ${res.error}`, { chat_id: chatId, message_id: waitMsg.message_id });
      } else {
        const text = `🧠 <b>Ответ ИИ (${res.model}):</b>\n\n${res.result}`;
        // Telegram msg size limit is 4096, split if needed
        if (text.length > 4000) {
          await bot.editMessageText(text.slice(0, 4000) + "...", { chat_id: chatId, message_id: waitMsg.message_id, parse_mode: "HTML" });
        } else {
          await bot.editMessageText(text, { chat_id: chatId, message_id: waitMsg.message_id, parse_mode: "HTML" });
        }
      }
    } catch (e) {
      await bot.editMessageText("⚠️ Ошибка связи с API ИИ", { chat_id: chatId, message_id: waitMsg.message_id });
    }
  }
});

bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  const text = (msg.text || "").trim();
  const state = pending.get(chatId);

  if (text.startsWith("/")) return; // Handled by onText

  if (state && state.step === "login") {
    pending.set(chatId, { step: "password", username: text });
    await reply(chatId, "🔑 Введите пароль:", { reply_markup: { remove_keyboard: true } });
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
      await reply(chatId, "❌ Неверный логин или пароль.\n/start — повторить авторизацию.");
    }
    return;
  }

  if (!sessions.get(chatId)?.authenticated) { await reply(chatId, "🔒 Требуется авторизация.\nНажмите /start"); return; }

  const username = sessions.get(chatId).username;

  if (text === "📊 Статус") {
    try {
      const stats = await apiRequest("GET", "/api/stats");
      const inc = stats.incidents || {}, logs = stats.logs || {};
      const t = `📊 <b>СТАТУС СЕРВЕРА</b>
      
🚨 Критических: <b>${inc.critical||0}</b>
⚠️ Высоких: <b>${inc.high||0}</b>
🟡 Средних: <b>${inc.medium||0}</b>
🟢 Низких: <b>${inc.low||0}</b>

📝 Логов сегодня: <b>${logs.today||0}</b>
👥 Подключено Web-клиентов: <b>${stats.connectedClients||0}</b>`;
      await reply(chatId, t, mainMenu());
    } catch (e) { await reply(chatId, "⚠️ Сервер недоступен", mainMenu()); }
    return;
  }

  if (text === "🚨 Инциденты") {
    try {
      const data = await apiRequest("GET", "/api/incidents?limit=5");
      const list = (data.data || []).slice(0,5).map(i => `• <b>[${i.severity}]</b> ${i.type}\n  <i>${(i.description||"").slice(0,100)}</i>`).join("\n\n") || "Инцидентов нет.";
      await reply(chatId, `🚨 <b>Последние 5 инцидентов:</b>\n\n${list}`, mainMenu());
    } catch (e) { await reply(chatId, "⚠️ Ошибка", mainMenu()); }
    return;
  }

  if (text === "📝 Логи") {
    try {
      const data = await apiRequest("GET", "/api/logs?type=server&limit=10");
      const list = (data.data || []).slice(0,10).map(l => `<code>[${(l.level||"INFO").toUpperCase()}] ${(l.message||"").slice(0,60)}</code>`).join("\n") || "Логов нет.";
      await reply(chatId, `📝 <b>Свежие логи:</b>\n\n${list}`, mainMenu());
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

const botApp = express();
botApp.use(express.json({ limit: "50mb" }));
botApp.post("/api/bot-notify", async (req, res) => {
  const incident = req.body;
  if (incident && incident.severity) await broadcastAlert(incident);
  res.json({ ok: true });
});
botApp.listen(Number(BOT_HTTP_PORT), () => console.log(`[Bot] HTTP listener on port ${BOT_HTTP_PORT}`));