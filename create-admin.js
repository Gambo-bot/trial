'use strict';
/* Usage: node create-admin.js <username> "<Full name>"
   Creates an administrator with a random one-time password (printed once; must be changed at first sign-in). */
const Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), crypto = require('crypto'), path = require('path'), fs = require('fs');
const [username, ...rest] = process.argv.slice(2);
const full = rest.join(' ') || 'Administrator';
if (!username || !/^[a-z0-9._-]{3,30}$/.test(username)) { console.error('Usage: node create-admin.js <username> "<Full name>"'); process.exit(1); }
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'register.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
if (!db.prepare("SELECT name FROM sqlite_master WHERE name='users'").get()) { console.error('Start the server once first (npm start) so the database is created.'); process.exit(1); }
const words = ['Volta','Tano','Kente','Adinkra','Cocoa','Savanna','Harmattan','Baobab','Sankofa','Ofin','Pra','Densu','Kakum','Mole','Bui','Gold'];
const w = () => words[crypto.randomInt(words.length)];
const pw = `${w()}-${w()}-${crypto.randomInt(10000, 99999)}!`;
try {
  db.prepare("INSERT INTO users(username,full_name,password_hash,role,status,must_change,created_at) VALUES(?,?,?,'admin','active',1,?)")
    .run(username, full, bcrypt.hashSync(pw, 12), Date.now());
  console.log(`Administrator created.\n  Username: ${username}\n  Password: ${pw}\n(You must change it at first sign-in.)`);
} catch (e) { console.error(e.message.includes('UNIQUE') ? 'That username already exists.' : e.message); process.exit(1); }
