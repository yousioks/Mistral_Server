FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm install --production

# Copy application
COPY server.js db.js scanners.js telegram-bot.js ./
COPY monitors/ ./monitors/
COPY .env.example ./.env.example

# Create directories
RUN mkdir -p data logs certs

# Expose ports
EXPOSE 8080 8443

# Default: start server
CMD ["node", "src/server.js"]
