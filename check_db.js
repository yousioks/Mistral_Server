const Database = require('better-sqlite3');
const path = require('path');
const dbPath = path.join(__dirname, 'data/mistral.db');
const db = new Database(dbPath);

console.log("Latest 10 incidents:");
const incidents = db.prepare("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 10").all();
incidents.forEach(i => {
  console.log(`- [${i.timestamp}] [${i.severity}] [${i.type}] ${i.description}`);
});

console.log("\nLatest 10 logs:");
const logs = db.prepare("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10").all();
logs.forEach(l => {
  console.log(`- [${l.timestamp}] [${l.level}] [${l.type}] ${l.message}`);
});
