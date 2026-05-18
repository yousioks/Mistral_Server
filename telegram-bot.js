require('dotenv').config();

const http = require('http');
const TelegramBot = require('node-telegram-bot-api');

const API_PORT = process.env.API_PORT || 8080;
const API_KEY = process.env.WSS_SECRET_TOKEN || '';

// ── HTTP API Client (standalone — no require('./server.js')) ──
function apiRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: 'localhost',
      port: API_PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
    };
    if (data) options.headers['Content-Length'] = Buffer.byteLength(data);

    const req = http.request(options, (res) => {
      let raw = '';
      res.on('data', chunk => raw += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); } catch { resolve(raw); }
      });
    });
    req.on('error', (e) => reject(e));
    if (data) req.write(data);
    req.end();
  });
}

const api = {
  addLog: (type, level, message, meta) => apiRequest('POST', '/api/logs', { type, level, message, meta }).catch(() => {}),
  addBotLog: (level, message, meta) => apiRequest('POST', '/api/bot-log', { level, message, meta }).catch(() => {}),
  addIncident: (severity, monitor, type, description, details) => apiRequest('POST', '/api/incidents', { severity, monitor, type, description, details }).catch(() => {}),
  getStats: () => apiRequest('GET', '/api/stats').catch(() => ({})),
  getLogs: (type, limit) => apiRequest('GET', `/api/logs?type=${type}&limit=${limit || 100}`).catch(() => ({ data: [] })),
  getIncidents: (limit) => apiRequest('GET', `/api/incidents?limit=${limit || 100}`).catch(() => ({ data: [] })),
  askAI: (model, task, systemPrompt) => apiRequest('POST', '/api/ai/task', { model, task, systemPrompt, caller: 'bot' }).catch(() => ({ error: 'AI unavailable' })),
  runSemgrep: (targetDir, rules) => apiRequest('POST', '/api/scan/semgrep', { targetDir, rules }).catch(() => ({ error: 'Semgrep failed', findings: [] })),
  runTrivy: (target, scanType) => apiRequest('POST', '/api/scan/trivy', { target, scanType }).catch(() => ({ error: 'Trivy failed', findings: [] })),
};

// In-memory sessions only
const telegramSessions = new Map();
const pending = new Map();

const MODELS = {
  deepseek: { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro', default: true },
  kimi: { id: 'kimi-k2.6', name: 'Kimi K2.6', default: false },
  claude: { id: 'claude-sonnet-4.6', name: 'Claude Sonnet 4.6', default: false },
};

const {
  TELEGRAM_BOT_TOKEN,
  OPERATOR_USERNAME,
  OPERATOR_PASSWORD,
  OPERATOR_NICKNAME = 'Operator',
} = process.env;

if (!TELEGRAM_BOT_TOKEN) {
  console.error('TELEGRAM_BOT_TOKEN is required. Set it in .env');
  process.exit(1);
}

const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });

// ─── Helper: safe reply ────────────────────────────────────────────────────
async function reply(chatId, text, opts = {}) {
  try {
    return await bot.sendMessage(chatId, text, { parse_mode: 'HTML', ...opts });
  } catch (err) {
    console.error('Bot sendMessage error:', err.message);
  }
}

function sendToClient(data) {
  // Bot runs standalone — server handles WS broadcast
  console.log('[Bot] Client action:', data.type);
}

// ─── Auth ──────────────────────────────────────────────────────────────────
function checkAuth(chatId) {
  const session = telegramSessions.get(chatId);
  return session && session.authenticated;
}

function requireAuth(chatId) {
  if (!checkAuth(chatId)) {
    reply(chatId, '🔒 Требуется авторизация. Отправьте /start');
    return false;
  }
  return true;
}

// ─── Menus ────────────────────────────────────────────────────────────────
const mainMenuKeyboard = {
  reply_markup: {
    keyboard: [
      [{ text: '📝 ЛОГИ' }, { text: '🛡️ CVE' }],
      [{ text: '🔎 Semgrep' }, { text: '🔍 Trivy' }],
      [{ text: '🧠 Нейросеть' }],
    ],
    resize_keyboard: true,
  },
};
const logsSubMenu = {
  reply_markup: {
    keyboard: [
      [{ text: '📅 Смотреть логи по датам' }],
      [{ text: '📤 Отправить на рассмотрение в клиент' }],
      [{ text: '🔙 Вернуться в меню логов' }],
    ],
    resize_keyboard: true,
  },
};

const cveSubMenu = {
  reply_markup: {
    keyboard: [
      [{ text: '🔍 Смотреть логи CVE' }],
      [{ text: '📤 Отправить на проверку в клиент' }],
      [{ text: '🔙 Вернуться в меню' }],
    ],
    resize_keyboard: true,
  },
};

const backMenu = {
  reply_markup: {
    keyboard: [[{ text: '🔙 Вернуться в главное меню' }]],
    resize_keyboard: true,
  },
};

const aiWarningMenu = {
  reply_markup: {
    keyboard: [
      [{ text: '⚠️ Я понимаю, продолжить' }],
      [{ text: '🔙 Вернуться в главное меню' }],
    ],
    resize_keyboard: true,
  },
};

const aiModelMenu = {
  reply_markup: {
    keyboard: [
      [{ text: '🚀 DeepSeek V4 Pro' }, { text: '🌙 Kimi K2.6' }],
      [{ text: '🔴 Claude Sonnet 4.6' }],
      [{ text: '🔙 Вернуться назад' }],
    ],
    resize_keyboard: true,
  },
};

// ─── /start ─────────────────────────────────────────────────────────────────
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const session = telegramSessions.get(chatId);
  if (session && session.authenticated) {
    await showMainMenu(chatId, session.nickname);
    return;
  }
  pending.set(chatId, { step: 'await_login' });
  await reply(chatId, '🔐 <b>Авторизация</b>\n\nВведите логин:', { reply_markup: { remove_keyboard: true } });
});

// ─── Main menu ────────────────────────────────────────────────────────────
async function showMainMenu(chatId, nickname) {
  try {
    const statsData = await api.getStats();
    const incidents = statsData.incidents || {};
    const logs = statsData.logs || {};
    const botLogs = statsData.botLogs || {};

    const text = `👋 Приветствую, <b>${nickname || OPERATOR_NICKNAME}</b>!\n\n📊 <b>Сводка уязвимостей:</b>\n` +
      `• Критические: <b>${incidents.critical || 0}</b>\n` +
      `• Высокой опасности: <b>${incidents.high || 0}</b>\n` +
      `• Средней опасности: <b>${incidents.medium || 0}</b>\n` +
      `• Неопасные: <b>${incidents.low || 0}</b>\n\n` +
      `📝 <b>Логи сервера:</b>\n` +
      `• За сегодня: <b>${logs.today || 0}</b>\n` +
      `• За неделю: <b>${logs.week || 0}</b>\n` +
      `• За месяц: <b>${logs.month || 0}</b>\n\n` +
      `🤖 <b>Логи бота:</b>\n` +
      `• За сегодня: <b>${botLogs.today || 0}</b>\n` +
      `• За неделю: <b>${botLogs.week || 0}</b>\n` +
      `• За месяц: <b>${botLogs.month || 0}</b>`;

    await reply(chatId, text, mainMenuKeyboard);
    api.addLog('bot', 'info', 'Operator opened main menu', { chatId, nickname });
    sendToClient({ type: 'menu_open', chatId, nickname });
  } catch (err) {
    console.error('showMainMenu error:', err);
    await reply(chatId, '⚠️ Ошибка получения данных. Попробуйте позже.', mainMenuKeyboard);
  }
}

// ─── Message handler ─────────────────────────────────────────────────────
bot.on('message', async (msg) => {
  const chatId = msg.chat.id;
  const text = msg.text || '';
  const pendingState = pending.get(chatId);

  // Universal back button — must be FIRST to intercept from any pending state
  if (text === '🔙 Вернуться в главное меню') {
    pending.delete(chatId);
    await showMainMenu(chatId, OPERATOR_NICKNAME);
    return;
  }

  // Auth flow  if (pendingState && pendingState.step === 'await_login') {
    pending.set(chatId, { step: 'await_password', login: text.trim() });
    await reply(chatId, 'Введите пароль:', { reply_markup: { remove_keyboard: true } });
    return;
  }

  if (pendingState && pendingState.step === 'await_password') {
    const login = pendingState.login;
    const password = text.trim();
    if (login === OPERATOR_USERNAME && password === OPERATOR_PASSWORD) {
      telegramSessions.set(chatId, { authenticated: true, nickname: OPERATOR_NICKNAME, lastActivity: Date.now() });
      pending.delete(chatId);
      api.addLog('bot', 'info', 'Operator authenticated', { chatId, nickname: OPERATOR_NICKNAME });
      sendToClient({ type: 'auth_success', chatId, nickname: OPERATOR_NICKNAME });
      await showMainMenu(chatId, OPERATOR_NICKNAME);
    } else {
      pending.delete(chatId);
      api.addLog('bot', 'warn', 'Failed authentication attempt', { chatId, login });
      sendToClient({ type: 'auth_fail', chatId, login });
      await reply(chatId, '❌ Неверный логин или пароль. Отправьте /start для повторной попытки.');
    }
    return;
  }

  // Log review date selection
  if (pendingState && pendingState.step === 'await_log_date') {
    if (text === '🔙 Вернуться в меню логов') {
      pending.delete(chatId);
      await reply(chatId, 'Меню логов', logsSubMenu);
      return;
    }
    const dateStr = text.replace(/📅 /, '').trim();
    try {
      const result = await api.getLogs('server', 200);
      const allLogs = result.data || [];
      const logsForDate = allLogs.filter(l => l.timestamp && l.timestamp.startsWith(dateStr));
      const preview = logsForDate.slice(0, 20).map(l => `• [${(l.level || 'info').toUpperCase()}] ${l.message}`).join('\n') || 'Нет логов за эту дату.';
      await reply(chatId, `📅 Логи за <b>${dateStr}</b> (${logsForDate.length} записей):\n\n${preview}`, logsSubMenu);
      api.addLog('bot', 'info', 'Operator viewed logs by date', { chatId, date: dateStr, count: logsForDate.length });
      sendToClient({ type: 'view_logs_date', chatId, date: dateStr, count: logsForDate.length });
    } catch (err) {
      await reply(chatId, '⚠️ Ошибка загрузки логов.', logsSubMenu);
    }
    pending.delete(chatId);
    return;
  }

  // Send log to client review
  if (pendingState && pendingState.step === 'await_log_id') {
    if (text === '🔙 Вернуться в меню логов') {
      pending.delete(chatId);
      await reply(chatId, 'Меню логов', logsSubMenu);
      return;
    }
    const logId = text.trim();
    try {
      const result = await api.getLogs('server', 500);
      const logEntry = (result.data || []).find(l => l.id === logId);
      if (!logEntry) {
        await reply(chatId, `❌ Лог с ID <b>${logId}</b> не найден.`, logsSubMenu);
        return;
      }
      api.addLog('bot', 'info', 'Log sent to client review', { chatId, logId });
      sendToClient({ type: 'log_to_review', chatId, logId, log: logEntry });
      await reply(chatId, `✅ Лог <b>${logId}</b> отправлен на рассмотрение в клиентское приложение.`, logsSubMenu);
    } catch (err) {
      await reply(chatId, '⚠️ Ошибка.', logsSubMenu);
    }
    pending.delete(chatId);
    return;
  }

  // Send CVE to client review
  if (pendingState && pendingState.step === 'await_cve_id') {
    if (text === '🔙 Вернуться в меню') {
      pending.delete(chatId);
      await reply(chatId, 'Меню CVE', cveSubMenu);
      return;
    }
    const cveId = text.trim();
    try {
      const result = await api.getLogs('cve', 500);
      const cveEntry = (result.data || []).find(c => c.id === cveId);
      if (!cveEntry) {
        await reply(chatId, `❌ CVE с ID <b>${cveId}</b> не найден.`, cveSubMenu);
        return;
      }
      api.addLog('bot', 'info', 'CVE sent to client review', { chatId, cveId });
      sendToClient({ type: 'cve_to_review', chatId, cveId, cve: cveEntry });
      await reply(chatId, `✅ CVE <b>${cveId}</b> отправлен на проверку в клиент.`, cveSubMenu);
    } catch (err) {
      await reply(chatId, '⚠️ Ошибка.', cveSubMenu);
    }
    pending.delete(chatId);
    return;
  }

  // AI: nickname input
  if (pendingState && pendingState.step === 'ai_await_nickname') {
    pending.set(chatId, { step: 'ai_await_reason', model: pendingState.model, nickname: text.trim() });
    await reply(chatId, '✏️ Напишите <b>причину</b> и что нужно исправить или проверить:', backMenu);
    return;
  }

  // AI: reason input -> confirmation
  if (pendingState && pendingState.step === 'ai_await_reason') {
    pending.set(chatId, {
      step: 'ai_confirm',
      model: pendingState.model,
      nickname: pendingState.nickname,
      reason: text.trim(),
    });
    const confirmKeyboard = {
      reply_markup: {
        keyboard: [
          [{ text: '✅ Да, включить нейросеть' }],
          [{ text: '🔙 Вернуться в меню нейросетей' }],
        ],
        resize_keyboard: true,
      },
    };
    await reply(chatId, `🧠 <b>Проверьте данные:</b>\nМодель: <b>${pendingState.model}</b>\nОператор: <b>${pendingState.nickname}</b>\nПричина: <i>${text.trim()}</i>\n\nВы уверены?`, confirmKeyboard);
    return;
  }

  // AI: final confirmation
  if (pendingState && pendingState.step === 'ai_confirm') {
    if (text === '✅ Да, включить нейросеть') {
      const { model, nickname, reason } = pendingState;
      pending.delete(chatId);
      await reply(chatId, `⏳ Запускаю <b>${model}</b>...`, backMenu);
      try {
        const systemPrompt = `Ты — защитный ИИ-ассистент MISTRAL Defense. Оператор: ${nickname}. Задача: ${reason}. ` +
          `Строгие правила: НЕ закрывай порт 22, НЕ останавливай nginx, НЕ ломай сертификаты. ` +
          `Всё логируется. Действуй безопасно.`;
        const result = await api.askAI(model, reason, systemPrompt);
        if (result.error) throw new Error(result.error);
        await reply(chatId, `✅ <b>Результат:</b>\n\n${(result.result || 'Нет ответа').slice(0, 3800)}`);
        api.addLog('bot', 'info', 'AI task completed', { chatId, model, nickname });
        sendToClient({ type: 'ai_result', chatId, model, nickname, result: (result.result || '').slice(0, 1000) });
      } catch (err) {
        await reply(chatId, `❌ Ошибка: ${err.message}`);
        api.addLog('bot', 'error', 'AI task failed', { chatId, model, error: err.message });
        sendToClient({ type: 'ai_error', chatId, model, error: err.message });
      }
    } else {
      pending.delete(chatId);
      await reply(chatId, '❌ Отменено.', mainMenuKeyboard);
    }
    return;
  }

  // ─── Main menu actions ────────────────────────────────────────────────────
  if (!requireAuth(chatId)) return;

  if (text === '📝 ЛОГИ') {
    await reply(chatId, '📋 Меню логов', logsSubMenu);
    return;
  }

  if (text === '🛡️ CVE') {
    await reply(chatId, '🛡️ Меню CVE', cveSubMenu);
    return;
  }

  if (text === '🔎 Semgrep') {
    await reply(chatId, '⏳ Запускаю Semgrep SAST...', backMenu);
    try {
      const result = await api.runSemgrep('/var/www/Mistral_Server', 'p/security-audit');
      if (result.error) throw new Error(result.error);
      const findings = result.findings || [];
      const preview = findings.slice(0, 20).map(f => `• <b>${f.check_id || 'rule'}</b>: ${f.message || '—'} (${f.severity || 'info'})`).join('\n') || 'Уязвимостей не найдено.';
      await reply(chatId, `🔎 <b>Semgrep результат:</b> (${findings.length} находок)\n\n${preview}`, mainMenuKeyboard);
      api.addLog('bot', 'info', 'Semgrep scan completed', { chatId, findings: findings.length });
      sendToClient({ type: 'semgrep_scan', chatId, findings: findings.length });
    } catch (err) {
      await reply(chatId, `❌ Ошибка Semgrep: ${err.message}`, mainMenuKeyboard);
      api.addLog('bot', 'error', 'Semgrep scan failed', { chatId, error: err.message });
    }
    return;
  }

  if (text === '🔍 Trivy') {
    await reply(chatId, '⏳ Запускаю Trivy CVE scan...', backMenu);
    try {
      const result = await api.runTrivy('/var/www/Mistral_Server', 'fs');
      if (result.error) throw new Error(result.error);
      const findings = result.findings || [];
      const preview = findings.slice(0, 20).map(f => `• <b>${f.vulnerability_id || f.title || 'CVE'}</b>: ${f.title || '—'} (${f.severity || 'unknown'})`).join('\n') || 'CVE не найдены.';
      await reply(chatId, `🔍 <b>Trivy результат:</b> (${findings.length} находок)\n\n${preview}`, mainMenuKeyboard);
      api.addLog('bot', 'info', 'Trivy scan completed', { chatId, findings: findings.length });
      sendToClient({ type: 'trivy_scan', chatId, findings: findings.length });
    } catch (err) {
      await reply(chatId, `❌ Ошибка Trivy: ${err.message}`, mainMenuKeyboard);
      api.addLog('bot', 'error', 'Trivy scan failed', { chatId, error: err.message });
    }
    return;
  }

  if (text === '🧠 Нейросеть') {
    await reply(chatId, '⚠️ <b>Внимание!</b>\nЛюбой запуск нейросети должен быть обоснован. Нажимая «продолжить», вы берёте на себя ответственность.', aiWarningMenu);
    return;
  }
  if (text === '⚠️ Я понимаю, продолжить') {
    await reply(chatId, 'Выберите модель:', aiModelMenu);
    return;
  }

  // Logs submenu
  if (text === '📅 Смотреть логи по датам') {
    const today = new Date();
    const dates = [];
    for (let i = 0; i < 7; i++) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      dates.push(`📅 ${d.toISOString().slice(0, 10)}`);
    }
    const dateKeyboard = {
      reply_markup: {
        keyboard: [
          ...dates.map(d => [{ text: d }]),
          [{ text: '🔙 Вернуться в меню логов' }],
        ],
        resize_keyboard: true,
      },
    };
    pending.set(chatId, { step: 'await_log_date' });
    await reply(chatId, 'Выберите дату:', dateKeyboard);
    return;
  }

  if (text === '📤 Отправить на рассмотрение в клиент') {
    pending.set(chatId, { step: 'await_log_id' });
    await reply(chatId, 'Введите ID лога для отправки:', logsSubMenu);
    return;
  }

  if (text === '🔙 Вернуться в меню логов') {
    await reply(chatId, '📋 Меню логов', logsSubMenu);
    return;
  }

  // CVE submenu
  if (text === '🔍 Смотреть логи CVE') {
    try {
      const result = await api.getLogs('cve', 15);
      const list = (result.data || []).map(c => `• <b>${c.id}</b> — ${c.message} (${(c.timestamp || '').slice(0, 10)})`).join('\n') || 'CVE-логов пока нет.';
      await reply(chatId, `🛡️ <b>Последние CVE:</b>\n\n${list}`, cveSubMenu);
      api.addLog('bot', 'info', 'Operator viewed CVE logs', { chatId });
      sendToClient({ type: 'view_cve', chatId });
    } catch (err) {
      await reply(chatId, '⚠️ Ошибка загрузки CVE.', cveSubMenu);
    }
    return;
  }

  if (text === '📤 Отправить на проверку в клиент') {
    pending.set(chatId, { step: 'await_cve_id' });
    await reply(chatId, 'Введите ID CVE:', cveSubMenu);
    return;
  }

  if (text === '🔙 Вернуться в меню') {
    await reply(chatId, '🛡️ Меню CVE', cveSubMenu);
    return;
  }

  // AI models
  if (text === '🚀 DeepSeek V4 Pro') {
    pending.set(chatId, { step: 'ai_await_nickname', model: MODELS.deepseek.id });
    await reply(chatId, '✏️ Введите ваш <b>никнейм</b>:', backMenu);
    return;
  }
  if (text === '🌙 Kimi K2.6') {
    pending.set(chatId, { step: 'ai_await_nickname', model: MODELS.kimi.id });
    await reply(chatId, '✏️ Введите ваш <b>никнейм</b>:', backMenu);
    return;
  }
  if (text === '🔴 Claude Sonnet 4.6') {
    pending.set(chatId, { step: 'ai_await_nickname', model: MODELS.claude.id });
    await reply(chatId, '✏️ Введите ваш <b>никнейм</b>:', backMenu);
    return;
  }

  if (text === '🔙 Вернуться назад') {
    await reply(chatId, '⚠️ <b>Внимание!</b>\nЛюбой запуск нейросети должен быть обоснован.', aiWarningMenu);
    return;
  }

  if (text === '🔙 Вернуться в меню нейросетей') {
    await reply(chatId, 'Выберите модель:', aiModelMenu);
    return;
  }
});
console.log('[Telegram Bot] MISTRAL Defense Bot started. Polling...');
