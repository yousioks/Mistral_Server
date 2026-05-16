# MISTRAL Defense — Server

Универсальный сервер агента безопасности для Ubuntu/Debian. Включает REST API, WebSocket Secure (WSS), Telegram-бота, Lua-мониторы, сканеры (Semgrep/Trivy), SQLite-хранилище и интеграцию с нейросетями через aitunnel.ru.

## Быстрый старт

```bash
cp .env.example .env
# Отредактируй .env — укажи AITUNNEL_API_KEY и TELEGRAM_BOT_TOKEN
npm install
chmod +x start.sh monitors/run-monitors.sh
./start.sh
```

## Архитектура

- **server.js** — REST API + WSS сервер
- **telegram-bot.js** — Telegram бот оператора (standalone, общается через REST API)
- **db.js** — SQLite с WAL, таблицы: incidents, logs, cve_logs, bot_logs
- **scanners.js** — обёртки для Semgrep и Trivy
- **monitors/lua/** — лёгковесные Lua-скрипты мониторинга

## Lua-мониторы

- `monitor_system.lua` — CPU, RAM, диск, темп, Docker, systemd, nginx
- `monitor_auth.lua` — SSH-сессии, sudo, failed logins, authorized_keys
- `monitor_network.lua` — порты, процессы, DDoS-индикаторы
- `monitor_integrity.lua` — целостность файлов, Docker-образы, git-изменения

## Docker

```bash
docker-compose up -d
```

## Переменные окружения

См. `.env.example` — все ключи, токены, пороги, пути.

## Структура

```
.
├── server.js
├── telegram-bot.js
├── db.js
├── scanners.js
├── start.sh
├── docker-compose.yml
├── .env.example
├── monitors/
│   ├── run-monitors.sh
│   └── lua/
│       ├── monitor_system.lua
│       ├── monitor_auth.lua
│       ├── monitor_network.lua
│       ├── monitor_integrity.lua
│       └── lib/http.lua
└── writeups/
    ├── sql_injection.json
    ├── ddos_attack.json
    └── red_team_v1.json
```
