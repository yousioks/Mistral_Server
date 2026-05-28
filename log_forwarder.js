const { spawn } = require('child_process');
const http = require('http');

const API_PORT = process.env.API_PORT || 8080;

function sendLog(level, message, meta = {}) {
  const body = JSON.stringify({ type: 'server', level, message, meta });
  const req = http.request({
    hostname: 'localhost',
    port: API_PORT,
    path: '/api/logs',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body)
    }
  });
  req.on('error', () => {}); // Ignore connection refused when server is restarting
  req.write(body);
  req.end();
}

function tailCommand(cmd, args, source) {
  const p = spawn(cmd, args);
  p.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) {
        sendLog('info', `[${source}] ${line.trim()}`);
      }
    }
  });
  p.stderr.on('data', (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) {
        sendLog('warn', `[${source}] ${line.trim()}`);
      }
    }
  });
  p.on('close', () => {
    setTimeout(() => tailCommand(cmd, args, source), 5000); // Restart on exit
  });
}

console.log('[LogForwarder] Запуск перехватчика логов...');

// 1. Журнал операционной системы (auth, syslog, kernel)
tailCommand('journalctl', ['-n', '0', '-f'], 'syslog');

// 2. Логи создания, удаления, остановки Docker-контейнеров
tailCommand('docker', ['events'], 'docker-events');
