'use strict';
/* NPP Constituency Register: backend (Express + SQLite) */
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'register.db');
const SECURE = process.env.COOKIE_SECURE === 'true';          // set true when served over HTTPS
const SESSION_MS = 8 * 60 * 60 * 1000;                         // absolute session limit: 8 hours
const IDLE_MS = 30 * 60 * 1000;                                // idle timeout: 30 minutes
const MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('admin','staff')),
  status TEXT NOT NULL CHECK(status IN('pending','active','disabled')),
  must_change INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, approved_by TEXT, approved_at INTEGER);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, voter_id TEXT, gender TEXT NOT NULL DEFAULT '', dob TEXT NOT NULL DEFAULT '',
  occupation TEXT NOT NULL DEFAULT '', area TEXT NOT NULL, polling_station TEXT NOT NULL, ps_code TEXT NOT NULL DEFAULT '',
  reg_date TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'Active', phone TEXT NOT NULL, phone2 TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
  created_by INTEGER REFERENCES users(id), created_at INTEGER NOT NULL, updated_by INTEGER, updated_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_rec_owner ON records(created_by);
CREATE INDEX IF NOT EXISTS ix_rec_area ON records(area);
CREATE INDEX IF NOT EXISTS ix_rec_ps ON records(polling_station);
CREATE INDEX IF NOT EXISTS ix_rec_name ON records(name COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS ux_rec_voter ON records(voter_id) WHERE voter_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user_id INTEGER, username TEXT, action TEXT NOT NULL, target TEXT, detail TEXT, ip TEXT);
`);

/* ---------- first-run admin accounts (hashes only) ---------- */
if (db.prepare('SELECT COUNT(*) n FROM users').get().n === 0) {
  const f = path.join(__dirname, 'seed-admins.json');
  let seeds = [];
  try { seeds = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { /* none */ }
  const ins = db.prepare(`INSERT INTO users(username,full_name,password_hash,role,status,must_change,created_at)
                          VALUES(?,?,?,'admin','active',1,?)`);
  for (const s of seeds) ins.run(s.username, s.full_name || 'Administrator', s.password_hash, Date.now());
  console.log(seeds.length ? `Created ${seeds.length} administrator account(s) (must change password at first sign-in).`
    : 'No users yet. Run: node create-admin.js <username> "<Full name>"');
}

/* ---------- helpers ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const now = () => Date.now();
const DUMMY = bcrypt.hashSync('not-a-real-password', 12);
const S = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
const ip = req => req.ip || '';
function audit(req, action, target, detail, userOverride) {
  const u = userOverride || req.user || {};
  db.prepare('INSERT INTO audit(ts,user_id,username,action,target,detail,ip) VALUES(?,?,?,?,?,?,?)')
    .run(now(), u.id || null, u.username || null, action, target == null ? null : String(target), detail || null, ip(req));
}
function getCookie(req, name) {
  for (const p of (req.headers.cookie || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0 && p.slice(0, i).trim() === name) { try { return decodeURIComponent(p.slice(i + 1).trim()); } catch (e) { return null; } }
  }
  return null;
}
function setSession(res, token, maxAgeMs) {
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}${SECURE ? '; Secure' : ''}`);
}
function pwProblem(pw, username) {
  if (typeof pw !== 'string' || pw.length < 10) return 'Password must be at least 10 characters.';
  if (pw.length > 72) return 'Password must be 72 characters or fewer.';
  if (username && pw.toLowerCase().includes(username.toLowerCase())) return 'Password must not contain the username.';
  return null;
}
const validUser = u => /^[a-z0-9._-]{3,30}$/.test(u);

/* ---------- records: validation ---------- */
const FIELDS = ['name','voter_id','gender','dob','occupation','area','polling_station','ps_code','reg_date','status','phone','phone2','email','address','notes'];
const STATUSES = ['Active','Relocated','Deceased','Inactive'];
const cap = s => s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : '';
function cleanRecord(b) {
  b = b || {};
  const r = {
    name: S(b.name, 120), voter_id: S(b.voter_id, 40), gender: cap(S(b.gender, 10)), dob: S(b.dob, 10),
    occupation: S(b.occupation, 80), area: S(b.area, 100), polling_station: S(b.polling_station, 120), ps_code: S(b.ps_code, 30),
    reg_date: S(b.reg_date, 10), status: cap(S(b.status || 'Active', 20)), phone: S(b.phone, 20), phone2: S(b.phone2, 20),
    email: S(b.email, 120), address: S(b.address, 200), notes: S(b.notes, 1000)
  };
  if (!r.name) return { err: 'Full name is required.' };
  if (!r.area) return { err: 'Electoral area is required.' };
  if (!r.polling_station) return { err: 'Polling station is required.' };
  if (!/^[0-9+()\-\s]{7,20}$/.test(r.phone)) return { err: 'Enter a valid phone number.' };
  if (r.phone2 && !/^[0-9+()\-\s]{7,20}$/.test(r.phone2)) return { err: 'Alternative phone is not valid.' };
  if (r.gender && !['Male', 'Female'].includes(r.gender)) return { err: 'Gender must be Male or Female.' };
  if (!STATUSES.includes(r.status)) return { err: 'Invalid status.' };
  for (const k of ['dob', 'reg_date']) if (r[k] && !/^\d{4}-\d{2}-\d{2}$/.test(r[k])) return { err: 'Dates must be YYYY-MM-DD.' };
  if (r.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(r.email)) return { err: 'Email is not valid.' };
  r.voter_id = r.voter_id || null;
  return { rec: r };
}

/* ---------- app ---------- */
const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], formAction: ["'self'"], baseUri: ["'self'"],
    upgradeInsecureRequests: SECURE ? [] : null } },
  hsts: SECURE
}));
app.use(express.json({ limit: '6mb' }));
app.use((req, res, next) => { req.body = req.body || {}; next(); });
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.headers['x-requested-with'] !== 'register') return res.status(403).json({ error: 'Forbidden.' });
  next();
});
app.use('/api', (req, res, next) => {            // attach session
  req.user = null;
  const t = getCookie(req, 'sid');
  if (t) {
    const h = sha(t), t0 = now();
    const s = db.prepare(`SELECT s.*, u.username, u.full_name, u.role, u.status, u.must_change
                          FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`).get(h);
    if (s && s.expires_at > t0 && t0 - s.last_seen < IDLE_MS && s.status === 'active') {
      db.prepare('UPDATE sessions SET last_seen=? WHERE token_hash=?').run(t0, h);
      req.user = { id: s.user_id, username: s.username, full_name: s.full_name, role: s.role, must_change: !!s.must_change };
      req.sid = h;
    } else if (s) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(h);
  }
  next();
});
const authOnly = (req, res, next) => req.user ? next() : res.status(401).json({ error: 'Please sign in.' });
const auth = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Please sign in.' });
  if (req.user.must_change) return res.status(403).json({ error: 'password_change_required' });
  next();
};
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Administrators only.' });
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });
const regLimit = rateLimit({ windowMs: 60 * 60 * 1000, limit: 6, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests. Try again later.' } });

/* ---------- auth routes ---------- */
const publicUser = u => ({ username: u.username, full_name: u.full_name, role: u.role, must_change: !!u.must_change });

app.post('/api/auth/login', loginLimit, async (req, res) => {
  const username = S(req.body.username, 30).toLowerCase(), password = String(req.body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  const generic = { error: 'Incorrect username or password, or the account is temporarily locked.' };
  if (!u) { await bcrypt.compare(password, DUMMY); audit(req, 'login_failed', username, 'unknown user'); return res.status(401).json(generic); }
  if (u.locked_until > now()) { audit(req, 'login_blocked', username, 'locked', u); return res.status(401).json(generic); }
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) {
    const f = u.failed + 1;
    db.prepare('UPDATE users SET failed=?, locked_until=? WHERE id=?').run(f >= MAX_FAILS ? 0 : f, f >= MAX_FAILS ? now() + LOCK_MS : 0, u.id);
    audit(req, 'login_failed', username, f >= MAX_FAILS ? 'account locked' : null, u);
    return res.status(401).json(generic);
  }
  if (u.status === 'pending') return res.status(403).json({ error: 'Your registration is still awaiting administrator approval.' });
  if (u.status === 'disabled') return res.status(403).json({ error: 'This account has been disabled. Contact an administrator.' });
  db.prepare('UPDATE users SET failed=0, locked_until=0 WHERE id=?').run(u.id);
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now());
  const token = crypto.randomBytes(32).toString('hex'), t = now();
  db.prepare('INSERT INTO sessions(token_hash,user_id,created_at,last_seen,expires_at) VALUES(?,?,?,?,?)').run(sha(token), u.id, t, t, t + SESSION_MS);
  setSession(res, token, SESSION_MS);
  audit(req, 'login', username, null, u);
  res.json({ user: publicUser(u) });
});
app.post('/api/auth/logout', authOnly, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token_hash=?').run(req.sid);
  audit(req, 'logout', req.user.username);
  setSession(res, '', 0); res.json({ ok: true });
});
app.get('/api/auth/me', authOnly, (req, res) => res.json({ user: req.user }));
app.post('/api/auth/change-password', authOnly, async (req, res) => {
  const cur = String(req.body.current || ''), nw = String(req.body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!(await bcrypt.compare(cur, u.password_hash))) return res.status(400).json({ error: 'Current password is incorrect.' });
  const p = pwProblem(nw, u.username); if (p) return res.status(400).json({ error: p });
  if (nw === cur) return res.status(400).json({ error: 'New password must be different.' });
  db.prepare('UPDATE users SET password_hash=?, must_change=0 WHERE id=?').run(await bcrypt.hash(nw, 12), u.id);
  db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').run(u.id, req.sid);
  audit(req, 'password_changed', u.username);
  res.json({ ok: true });
});
app.post('/api/auth/register', regLimit, async (req, res) => {
  const username = S(req.body.username, 30).toLowerCase(), full = S(req.body.full_name, 80), pw = String(req.body.password || '');
  if (!validUser(username)) return res.status(400).json({ error: 'Username: 3-30 characters; letters, numbers, . _ - only.' });
  if (full.length < 2) return res.status(400).json({ error: 'Enter your full name.' });
  const p = pwProblem(pw, username); if (p) return res.status(400).json({ error: p });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(409).json({ error: 'That username is already taken.' });
  db.prepare(`INSERT INTO users(username,full_name,password_hash,role,status,must_change,created_at) VALUES(?,?,?,'staff','pending',0,?)`)
    .run(username, full, await bcrypt.hash(pw, 12), now());
  audit(req, 'register_request', username, null, { username });
  res.json({ ok: true, message: 'Request submitted. An administrator must approve it before you can sign in.' });
});

/* ---------- user management (admin) ---------- */
app.get('/api/users', auth, admin, (req, res) => {
  res.json({ users: db.prepare(`SELECT id,username,full_name,role,status,created_at,approved_by,approved_at FROM users
                                ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, username`).all() });
});
function userAction(name, fn) {
  app.post('/api/users/:id/' + name, auth, admin, async (req, res) => {
    const t = db.prepare('SELECT * FROM users WHERE id=?').get(Number(req.params.id));
    if (!t) return res.status(404).json({ error: 'User not found.' });
    await fn(req, res, t);
  });
}
userAction('approve', (req, res, t) => {
  if (t.status !== 'pending') return res.status(400).json({ error: 'Not a pending request.' });
  db.prepare("UPDATE users SET status='active', approved_by=?, approved_at=? WHERE id=?").run(req.user.username, now(), t.id);
  audit(req, 'user_approved', t.username); res.json({ ok: true });
});
userAction('reject', (req, res, t) => {
  if (t.status !== 'pending') return res.status(400).json({ error: 'Not a pending request.' });
  db.prepare('DELETE FROM users WHERE id=?').run(t.id);
  audit(req, 'user_rejected', t.username); res.json({ ok: true });
});
userAction('disable', (req, res, t) => {
  if (t.id === req.user.id) return res.status(400).json({ error: 'You cannot disable your own account.' });
  db.prepare("UPDATE users SET status='disabled' WHERE id=? AND status='active'").run(t.id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(t.id);
  audit(req, 'user_disabled', t.username); res.json({ ok: true });
});
userAction('enable', (req, res, t) => {
  db.prepare("UPDATE users SET status='active' WHERE id=? AND status='disabled'").run(t.id);
  audit(req, 'user_enabled', t.username); res.json({ ok: true });
});
userAction('reset-password', async (req, res, t) => {
  const pw = String(req.body.password || ''), p = pwProblem(pw, t.username);
  if (p) return res.status(400).json({ error: p });
  db.prepare('UPDATE users SET password_hash=?, must_change=1, failed=0, locked_until=0 WHERE id=?').run(await bcrypt.hash(pw, 12), t.id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(t.id);
  audit(req, 'password_reset', t.username); res.json({ ok: true });
});
app.post('/api/users', auth, admin, async (req, res) => {
  const username = S(req.body.username, 30).toLowerCase(), full = S(req.body.full_name, 80), pw = String(req.body.password || '');
  const role = req.body.role === 'admin' ? 'admin' : 'staff';
  if (!validUser(username)) return res.status(400).json({ error: 'Username: 3-30 characters; letters, numbers, . _ - only.' });
  if (full.length < 2) return res.status(400).json({ error: 'Enter the full name.' });
  const p = pwProblem(pw, username); if (p) return res.status(400).json({ error: p });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(409).json({ error: 'That username already exists.' });
  db.prepare(`INSERT INTO users(username,full_name,password_hash,role,status,must_change,created_at,approved_by,approved_at)
              VALUES(?,?,?,?, 'active',1,?,?,?)`).run(username, full, await bcrypt.hash(pw, 12), role, now(), req.user.username, now());
  audit(req, 'user_created', username, role); res.json({ ok: true });
});

/* ---------- records ---------- */
function scope(req, q) {
  const w = [], p = {};
  if (req.user.role !== 'admin') { w.push('r.created_by=@uid'); p.uid = req.user.id; }
  if (q.q) {
    p.q = '%' + String(q.q).slice(0, 100).replace(/[\\%_]/g, '\\$&') + '%';
    w.push(['r.name', 'r.voter_id', 'r.phone', 'r.phone2', 'r.email', 'r.address'].map(c => `${c} LIKE @q ESCAPE '\\'`).join(' OR ').replace(/^/, '(') + ')');
  }
  for (const [k, col] of [['area', 'r.area'], ['polling_station', 'r.polling_station'], ['status', 'r.status'], ['gender', 'r.gender']])
    if (q[k]) { w.push(`${col}=@${k}`); p[k] = String(q[k]); }
  if (req.user.role === 'admin' && q.created_by) { w.push('u.username=@cb'); p.cb = String(q.created_by); }
  return { where: w.length ? 'WHERE ' + w.join(' AND ') : '', p };
}
const FROM = 'FROM records r LEFT JOIN users u ON u.id=r.created_by';

app.get('/api/records', auth, (req, res) => {
  const { where, p } = scope(req, req.query);
  const size = Math.min(100, Math.max(1, parseInt(req.query.size) || 50));
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const total = db.prepare(`SELECT COUNT(*) n ${FROM} ${where}`).get(p).n;
  const rows = db.prepare(`SELECT r.*, u.username AS created_by_name ${FROM} ${where}
                           ORDER BY r.name COLLATE NOCASE, r.id LIMIT ${size} OFFSET ${(page - 1) * size}`).all(p);
  res.json({ rows, total, page, size });
});
app.get('/api/stats', auth, (req, res) => {
  const { where, p } = scope(req, {});
  res.json(db.prepare(`SELECT COUNT(*) total, COALESCE(SUM(r.status='Active'),0) active, COALESCE(SUM(r.gender='Male'),0) male,
    COALESCE(SUM(r.gender='Female'),0) female, COUNT(DISTINCT r.area) areas, COUNT(DISTINCT r.polling_station) stations ${FROM} ${where}`).get(p));
});
app.get('/api/meta', auth, (req, res) => {
  const { where, p } = scope(req, {});
  const col = c => db.prepare(`SELECT DISTINCT r.${c} v ${FROM} ${where} ORDER BY r.${c} COLLATE NOCASE`).all(p).map(x => x.v);
  const out = { areas: col('area'), stations: col('polling_station') };
  if (req.user.role === 'admin') out.users = db.prepare('SELECT username FROM users ORDER BY username').all().map(x => x.username);
  res.json(out);
});

function dupVoter(vid, exceptId) {
  return vid && db.prepare('SELECT 1 FROM records WHERE voter_id=? AND id<>?').get(vid, exceptId || 0);
}
app.post('/api/records', auth, (req, res) => {
  const { rec, err } = cleanRecord(req.body); if (err) return res.status(400).json({ error: err });
  if (dupVoter(rec.voter_id)) return res.status(409).json({ error: 'A record with this Voter ID already exists.' });
  const info = db.prepare(`INSERT INTO records(${FIELDS.join(',')},created_by,created_at) VALUES(${FIELDS.map(f => '@' + f).join(',')},@cb,@at)`)
    .run({ ...rec, cb: req.user.id, at: now() });
  audit(req, 'record_created', info.lastInsertRowid, rec.name);
  res.json({ ok: true, id: info.lastInsertRowid });
});
app.put('/api/records/:id', auth, (req, res) => {
  const id = Number(req.params.id), old = db.prepare('SELECT * FROM records WHERE id=?').get(id);
  if (!old || (req.user.role !== 'admin' && old.created_by !== req.user.id)) return res.status(404).json({ error: 'Record not found.' });
  const { rec, err } = cleanRecord(req.body); if (err) return res.status(400).json({ error: err });
  if (dupVoter(rec.voter_id, id)) return res.status(409).json({ error: 'A record with this Voter ID already exists.' });
  db.prepare(`UPDATE records SET ${FIELDS.map(f => f + '=@' + f).join(',')}, updated_by=@ub, updated_at=@at WHERE id=@id`)
    .run({ ...rec, ub: req.user.id, at: now(), id });
  audit(req, 'record_updated', id, 'fields: ' + FIELDS.filter(f => (old[f] || null) !== (rec[f] || null)).join(', '));
  res.json({ ok: true });
});
app.delete('/api/records/:id', auth, admin, (req, res) => {
  const id = Number(req.params.id), old = db.prepare('SELECT name FROM records WHERE id=?').get(id);
  if (!old) return res.status(404).json({ error: 'Record not found.' });
  db.prepare('DELETE FROM records WHERE id=?').run(id);
  audit(req, 'record_deleted', id, old.name); res.json({ ok: true });
});

const LABELS = ['Full name','Voter ID','Gender','Date of birth','Occupation','Electoral area','Polling station','Polling station code','Registration date','Status','Phone','Alt phone','Email','Address','Notes'];
const csvCell = v => {
  let s = String(v == null ? '' : v);
  if (/^[=+\-@\t\r]/.test(s) && !/^\+[0-9 ()\-]{6,}$/.test(s)) s = "'" + s;   // block spreadsheet formula injection
  return '"' + s.replace(/"/g, '""') + '"';
};
app.get('/api/export.csv', auth, (req, res) => {
  const { where, p } = scope(req, req.query);
  const rows = db.prepare(`SELECT r.*, u.username AS created_by_name ${FROM} ${where} ORDER BY r.name COLLATE NOCASE`).all(p);
  const lines = [LABELS.concat('Added by').join(',')].concat(rows.map(r => FIELDS.map(f => csvCell(r[f])).concat(csvCell(r.created_by_name)).join(',')));
  audit(req, 'export', rows.length + ' records');
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="constituency-register.csv"' });
  res.send('\uFEFF' + lines.join('\r\n'));
});
app.post('/api/import', auth, admin, (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows.slice(0, 5000) : [];
  const ins = db.prepare(`INSERT INTO records(${FIELDS.join(',')},created_by,created_at) VALUES(${FIELDS.map(f => '@' + f).join(',')},@cb,@at)`);
  let imported = 0, skipped = 0; const errors = [];
  db.transaction(() => rows.forEach((raw, i) => {
    const b = {}; for (const f of FIELDS) b[f] = typeof raw[f] === 'string' ? raw[f].replace(/^'(?=[=+\-@])/, '') : raw[f];
    const { rec, err } = cleanRecord(b);
    if (err) { skipped++; if (errors.length < 20) errors.push(`Row ${i + 1}: ${err}`); return; }
    if (dupVoter(rec.voter_id)) { skipped++; if (errors.length < 20) errors.push(`Row ${i + 1}: duplicate Voter ID`); return; }
    ins.run({ ...rec, cb: req.user.id, at: now() }); imported++;
  }))();
  audit(req, 'import', `${imported} imported, ${skipped} skipped`);
  res.json({ imported, skipped, errors });
});

/* ---------- audit log (admin) ---------- */
app.get('/api/audit', auth, admin, (req, res) => {
  const size = 50, page = Math.max(1, parseInt(req.query.page) || 1);
  const total = db.prepare('SELECT COUNT(*) n FROM audit').get().n;
  res.json({ total, size, page, rows: db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?').all(size, (page - 1) * size) });
});

/* ---------- static + errors ---------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad request.' });
  console.error(err); res.status(500).json({ error: 'Server error.' });
});
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now()), 60 * 60 * 1000).unref();
app.listen(PORT, () => console.log(`NPP Constituency Register running on port ${PORT}`));
