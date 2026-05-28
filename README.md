# MISTRAL Defense — Server

Универсальный сервер агента безопасности для Ubuntu/Debian. Включает REST API, WebSocket Secure (WSS), Telegram-бота, Lua-мониторы, сканеры (Semgrep/Trivy), SQLite-хранилище и интеграцию с нейросетями.

## Быстрый старт

```bash
cp .env.example .env
# Отредактируй .env — укажи AITUNNEL_API_KEY и TELEGRAM_BOT_TOKEN
npm install
chmod +x start.sh monitors/run-monitors.sh
./start.sh
```

## Архитектура и Нововведения (1.1)

- **telegram-bot.js** — Полностью переписан. Теперь сообщения приходят с красивой HTML-разметкой и эмодзи-индикаторами. Для инцидентов HIGH/CRITICAL добавлена кнопка **[ 🧠 АНАЛИЗ ИИ ]**, позволяющая получить ответ от нейросети прямо в Telegram (через локальный bypass API).
- **server.js** — REST API + WSS сервер. Интегрирован bypass локальных запросов ИИ.
- **db.js** — SQLite с WAL, таблицы: incidents, logs, cve_logs, bot_logs
- **scanners.js** — обёртки для Semgrep и Trivy
- **log_forwarder.js** — сбор логов Docker и systemd

## Lua-мониторы

- `monitor_system.lua` — CPU, RAM, диск, темп, Docker, systemd, nginx
- `monitor_auth.lua` — SSH-сессии, sudo, failed logins, authorized_keys
- `monitor_network.lua` — порты, процессы, DDoS-индикаторы
- `monitor_integrity.lua` — целостность файлов, Docker-образы, git-изменения

## Структура

```
.
├── server.js
├── telegram-bot.js
├── db.js
├── scanners.js
├── log_forwarder.js
├── start.sh
├── docker-compose.yml
├── .env.example
├── .gitignore
└── monitors/
```
