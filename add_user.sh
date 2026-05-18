#!/bin/bash

# Скрипт для добавления пользователя в БД
if [ "$#" -ne 2 ]; then
    echo "Использование: $0 <username> <password>"
    exit 1
fi

USERNAME=$1
PASSWORD=$2
DB_PATH="data/mistral.db"

if [ ! -f "$DB_PATH" ]; then
    echo "Ошибка: База данных не найдена по пути $DB_PATH"
    exit 1
fi

sqlite3 "$DB_PATH" "INSERT INTO users (username, password) VALUES ('$USERNAME', '$PASSWORD');"

if [ $? -eq 0 ]; then
    echo "Пользователь '$USERNAME' успешно добавлен."
else
    echo "Ошибка при добавлении пользователя (возможно, он уже существует)."
fi
