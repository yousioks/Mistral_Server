# =============================================================================
#  MISTRAL Defense Agent - Production Dockerfile (Non-Isolated Mode)
# =============================================================================
#  Чтобы контейнер мог управлять брандмауэром и правилами блокировки ХОСТА,
#  его необходимо запускать со следующими параметрами:
#
#  docker run -d \
#    --name mistral-server \
#    --network host \
#    --cap-add=NET_ADMIN \
#    -v /var/run/fail2ban/fail2ban.sock:/var/run/fail2ban/fail2ban.sock \
#    -v /etc/ufw:/etc/ufw \
#    -v /var/log:/var/log:ro \
#    -v /proc:/host/proc:ro \
#    --restart unless-stopped \
#    mistral-server
# =============================================================================

FROM node:20-alpine

WORKDIR /app

# Установка системных утилит для управления сетью и брандмауэром хоста
RUN apk add --no-cache \
    iptables \
    iproute2 \
    fail2ban \
    ufw \
    sudo \
    curl

# Установка зависимостей Node.js
COPY package.json ./
RUN npm install --production

# Копирование исходного кода приложения
COPY src/ ./src/
COPY monitors/ ./monitors/
COPY .env.example ./.env.example

# Создание необходимых директорий
RUN mkdir -p data logs certs

# Экспортируем порты (хотя при --network host они будут слушаться напрямую на хосте)
EXPOSE 8080 8443

# Запуск сервера
CMD ["node", "src/server.js"]
