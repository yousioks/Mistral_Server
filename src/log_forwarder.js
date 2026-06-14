const { spawn } = require('child_process');
const http = require('http');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '../.env') });

const API_PORT = process.env.API_PORT || 8080;

function sendLog(level, message, meta = {}) {
  const body = JSON.stringify({ type: 'server', level, message, meta });
  const token = process.env.WSS_SECRET_TOKEN || '';
  const req = http.request({
    hostname: 'localhost',
    port: API_PORT,
    path: '/api/logs',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      'X-Auth-Token': token,
      'X-API-Key': token
    }
  });
  req.on('error', () => {}); // Ignore connection refused when server is restarting
  req.write(body);
  req.end();
}

function parseDockerEvent(line) {
  try {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) return `[Docker] ${line}`;
    
    const type = parts[1]; // container, network, volume, image, etc.
    const action = parts[2]; // start, stop, create, destroy, connect, disconnect, etc.
    const targetId = parts[3] ? parts[3].slice(0, 12) : '';
    
    const metaStr = parts.slice(4).join(' ');
    const nameMatch = metaStr.match(/name=([^,\s\)]+)/);
    const imageMatch = metaStr.match(/image=([^,\s\)]+)/);
    const containerName = nameMatch ? nameMatch[1] : '';
    const imageName = imageMatch ? imageMatch[1] : '';
    
    let targetDesc = containerName ? `контейнер "${containerName}"` : `контейнер [${targetId}]`;
    if (imageName) targetDesc += ` (образ: ${imageName})`;

    if (type === 'container') {
      switch(action) {
        case 'create':
          return `[Docker] Создан новый ${targetDesc}.`;
        case 'start':
          return `[Docker] Запущен ${targetDesc}.`;
        case 'stop':
          return `[Docker] Остановлен ${targetDesc}.`;
        case 'die':
          const exitCodeMatch = metaStr.match(/exitCode=(\d+)/);
          const code = exitCodeMatch ? ` с кодом ${exitCodeMatch[1]}` : '';
          return `[Docker] Завершил работу ${targetDesc}${code}.`;
        case 'destroy':
          return `[Docker] Удален ${targetDesc}.`;
        case 'kill':
          const signalMatch = metaStr.match(/signal=(\d+)/);
          const sig = signalMatch ? ` (сигнал: ${signalMatch[1]})` : '';
          return `[Docker] Отправлен сигнал принудительной остановки на ${targetDesc}${sig}.`;
        case 'pause':
          return `[Docker] Приостановлен ${targetDesc}.`;
        case 'unpause':
          return `[Docker] Возобновлена работа ${targetDesc}.`;
        default:
          return `[Docker] Событие контейнера: ${action} для ${targetDesc}`;
      }
    } else if (type === 'network') {
      const containerMatch = metaStr.match(/container=([^,\s\)]+)/);
      const cName = containerMatch ? containerMatch[1].slice(0, 12) : '';
      const netName = containerName ? `сеть "${containerName}"` : `сеть [${targetId}]`;
      if (action === 'connect') {
        return `[Docker] Сетевое подключение: контейнер [${cName}] подключен к ${netName}.`;
      } else if (action === 'disconnect') {
        return `[Docker] Сетевое отклонение: контейнер [${cName}] отключен от ${netName}.`;
      }
      return `[Docker] Событие сети: ${action} на ${netName}`;
    }
    
    return `[Docker] ${type} ${action} ${targetId} ${containerName || imageName || ''}`;
  } catch (e) {
    return `[Docker] ${line}`;
  }
}

function tailCommand(cmd, args, source) {
  const p = spawn(cmd, args);
  p.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) {
        let msg = line.trim();
        if (source === 'docker-events') {
          msg = parseDockerEvent(msg);
        } else {
          msg = `[${source}] ${msg}`;
        }
        sendLog('info', msg);
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
