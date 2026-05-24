#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  MISTRAL Defense — Добавление пользователя в БД
#  Использование: ./add_user.sh <username> <password> [role] [chat_id]
#  role: operator (по умолчанию) | admin
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$#" -lt 2 ]; then
    echo "Использование: $0 <username> <password> [role] [chat_id]"
    echo "  role: operator (по умолчанию) | admin"
    exit 1
fi

USERNAME="$1"
PASSWORD="$2"
ROLE="${3:-operator}"
CHAT_ID="${4:-}"

# Добавляем через db.js (bcrypt хеширование автоматически)
node -e "
const db = require('./db.js');
const ok = db.addUser('$USERNAME', '$PASSWORD', '$CHAT_ID' || null, '$USERNAME', '$ROLE');
if (ok) {
  console.log('[OK] Пользователь \"$USERNAME\" успешно добавлен (роль: $ROLE).');
  process.exit(0);
} else {
  console.error('[ERROR] Пользователь \"$USERNAME\" уже существует.');
  process.exit(1);
}
"
