#!/bin/bash
# MISTRAL Defense - List Users

DB_PATH="./data/mistral.db"

if [ ! -f "$DB_PATH" ]; then
  echo "База данных не найдена: $DB_PATH"
  echo "Запустите сервер хотя бы один раз, чтобы база создалась."
  exit 1
fi

if ! command -v sqlite3 &> /dev/null; then
  echo "Утилита sqlite3 не установлена! Установите её командой: sudo apt install sqlite3"
  exit 1
fi

echo "Список пользователей в MISTRAL Server:"
echo "----------------------------------------------------------------"
sqlite3 -column -header "$DB_PATH" "SELECT id, username, role, chat_id, nickname FROM users;"
echo "----------------------------------------------------------------"
