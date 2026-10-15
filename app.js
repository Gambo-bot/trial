'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const FIELDS = ['name','voter_id','gender','dob','occupation','area','polling_station','ps_code','reg_date','status','phone','phone2','email','address','notes'];
let me = null, page = 1, pages = 1, cache = [], aPage = 1, aPages = 1, forced = false, tab = 'records';

async function api(path, method = 'GET', body) {
  const r = await fetch('/api' + path, {
    method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'register' },
    body: body ? JSON.stringify(body) : undefined
  });
  let d = {}; try { d = await r.json(); } catch (e) { /* no body */ }
  if (r.status === 401 && me) { me = null; view('login'); $('lerr').textContent = 'Your session has ended. Please sign in again.'; }
  if (r.status === 403 && d.error === 'password_change_required') { forced = true; view('force'); }
  if (!r.ok) throw Object.assign(new Error(d.error || 'Request failed.'), { status: r.status });
  return d;
}
function view(v) {
  for (const k of ['login', 'force', 'app']) $('v-' + k).hidden = k !== v;
  if (v === 'force') { $('cCancelWrap').hidden = forced; $('forceMsg').textContent = forced ? 'You must choose a new password before continuing.' : ''; $('cerr').textContent = ''; $('cf').reset(); }
}

/* ---------- start / auth ---------- */
async function boot() {
  try { me = (await api('/auth/me')).user; route(); } catch (e) { view('login'); }
}
function route() {
  if (me.must_change) { forced = true; view('force'); return; }
  forced = false; view('app');
  document.body.dataset.role = me.role;
  $('who').textContent = `${me.full_name} (${me.role})`;
  showTab('records');
}
$('toReg').onclick = e => { e.preventDefault(); $('lf').hidden = true; $('rf').hidden = false; $('rerr').textContent = ''; };
$('toLog').onclick = e => { e.preventDefault(); $('rf').hidden = true; $('lf').hidden = false; };
$('lf').onsubmit = async e => {
  e.preventDefault(); $('lerr').textContent = '';
  try { me = (await api('/auth/login', 'POST', { username: $('lu').value, password: $('lp').value })).user; $('lf').reset(); route(); }
  catch (x) { $('lerr').textContent = x.message; }
};
$('rf').onsubmit = async e => {
  e.preventDefault(); $('rerr').textContent = '';
  if ($('rp').value !== $('rc').value) return $('rerr').textContent = 'Passwords do not match.';
  try {
    const d = await api('/auth/register', 'POST', { username: $('ru').value, full_name: $('rn').value, password: $('rp').value });
    $('rf').reset(); $('rf').hidden = true; $('lf').hidden = false; $('lerr').textContent = ''; alert(d.message);
  } catch (x) { $('rerr').textContent = x.message; }
};
$('cf').onsubmit = async e => {
  e.preventDefault(); $('cerr').textContent = '';
  if ($('cn').value !== $('cn2').value) return $('cerr').textContent = 'Passwords do not match.';
  try { await api('/auth/change-password', 'POST', { current: $('cc').value, password: $('cn').value }); me.must_change = false; alert('Password changed.'); route(); }
  catch (x) { $('cerr').textContent = x.message; }
};
$('cCancel').onclick = e => { e.preventDefault(); view('app'); };
$('bPw').onclick = () => { forced = false; view('force'); };
$('bOut').onclick = async () => { try { await api('/auth/logout', 'POST'); } catch (e) { /* ignore */ } me = null; delete document.body.dataset.role; view('login'); };

/* ---------- tabs ---------- */
document.querySelectorAll('nav button').forEach(b => b.onclick = () => showTab(b.dataset.tab));
function showTab(t) {
  tab = t;
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  for (const k of ['records', 'users', 'audit']) $('t-' + k).hidden = k !== t;
  if (t === 'records') { loadMeta(); loadStats(); loadRecords(); }
  if (t === 'users') loadUsers();
  if (t === 'audit') loadAudit();
  if (me.role === 'admin') refreshPending();
}
$('pendGo').onclick = e => { e.preventDefault(); showTab('users'); };

/* ---------- records ---------- */
const fillSel = (id, vals, first) => { const el = $(id), cur = el.value; el.innerHTML = `<option value="">${first}</option>` + vals.map(v => `<option>${esc(v)}</option>`).join(''); el.value = vals.includes(cur) ? cur : ''; };
async function loadMeta() {
  try {
    const m = await api('/meta');
    fillSel('f_area', m.areas, 'All electoral areas'); fillSel('f_polling_station', m.stations, 'All polling stations');
    $('dlAreas').innerHTML = m.areas.map(v => `<option value="${esc(v)}">`).join(''); $('dlPs').innerHTML = m.stations.map(v => `<option value="${esc(v)}">`).join('');
    if (m.users) fillSel('f_created_by', m.users, 'Added by: anyone');
  } catch (e) { /* handled in api() */ }
}
async function loadStats() {
  try {
    const s = await api('/stats');
    $('sT').textContent = s.total; $('sAc').textContent = s.active; $('sA').textContent = s.areas; $('sP').textContent = s.stations; $('sM').textContent = s.male; $('sF').textContent = s.female;
  } catch (e) { /* ignore */ }
}
function filters() {
  const q = new URLSearchParams();
  for (const k of ['q', 'area', 'polling_station', 'status', 'gender', 'created_by']) { const v = $('f_' + k).value.trim(); if (v) q.set(k, v); }
  return q;
}
async function loadRecords() {
  const q = filters(); q.set('page', page); q.set('size', 50);
  try {
    const d = await api('/records?' + q); cache = d.rows; pages = Math.max(1, Math.ceil(d.total / d.size));
    $('tb').innerHTML = d.rows.map((r, i) => `<tr>
      <td>${(d.page - 1) * d.size + i + 1}</td>
      <td>${esc(r.name)}<small>${esc([r.gender, r.dob].filter(Boolean).join(' · '))}</small></td>
      <td>${esc(r.voter_id)}</td><td>${esc(r.area)}</td>
      <td>${esc(r.polling_station)}<small>${esc(r.ps_code)}</small></td>
      <td>${esc(r.phone)}<small>${esc(r.email)}</small></td>
      <td><span class="tag ${r.status === 'Deceased' || r.status === 'Inactive' ? 'x' : ''}">${esc(r.status)}</span></td>
      <td class="adm">${esc(r.created_by_name || '—')}</td>
      <td style="white-space:nowrap"><button class="s" data-act="edit" data-id="${r.id}">Edit</button><button class="d adm" data-act="del" data-id="${r.id}">Delete</button></td></tr>`).join('');
    $('emptyMsg').hidden = d.rows.length > 0;
    $('cnt').textContent = `${d.total} record${d.total === 1 ? '' : 's'} · page ${d.page} of ${pages}`;
    $('pPrev').disabled = page <= 1; $('pNext').disabled = page >= pages;
  } catch (e) { /* handled */ }
}
$('tb').onclick = async e => {
  const b = e.target.closest('button[data-act]'); if (!b) return;
  const id = Number(b.dataset.id);
  if (b.dataset.act === 'edit') {
    const r = cache.find(x => x.id === id); if (!r) return;
    const f = $('rec'); f.elements.id.value = r.id;
    for (const k of FIELDS) f.elements[k].value = r[k] || '';
    $('recTitle').textContent = 'Edit record'; $('recSave').textContent = 'Update record'; scrollTo(0, 0);
  } else if (b.dataset.act === 'del' && confirm('Delete this record permanently?')) {
    try { await api('/records/' + id, 'DELETE'); refresh(); } catch (x) { alert(x.message); }
  }
};
function clearForm() { $('rec').reset(); $('rec').elements.id.value = ''; $('recTitle').textContent = 'Add a record'; $('recSave').textContent = 'Add record'; $('recErr').textContent = ''; }
$('recClear').onclick = clearForm;
$('rec').onsubmit = async e => {
  e.preventDefault(); $('recErr').textContent = '';
  const f = $('rec'), body = {}; for (const k of FIELDS) body[k] = f.elements[k].value;
  const id = f.elements.id.value;
  try { await (id ? api('/records/' + id, 'PUT', body) : api('/records', 'POST', body)); clearForm(); refresh(); }
  catch (x) { $('recErr').textContent = x.message; }
};
function refresh() { loadMeta(); loadStats(); loadRecords(); }
let timer; const again = () => { page = 1; loadRecords(); };
$('f_q').oninput = () => { clearTimeout(timer); timer = setTimeout(again, 300); };
for (const k of ['area', 'polling_station', 'status', 'gender', 'created_by']) $('f_' + k).onchange = again;
$('pPrev').onclick = () => { if (page > 1) { page--; loadRecords(); } };
$('pNext').onclick = () => { if (page < pages) { page++; loadRecords(); } };
$('bExp').onclick = () => { location.href = '/api/export.csv?' + filters(); };

/* ---------- CSV import (admin) ---------- */
const LABEL2FIELD = { 'full name': 'name', 'voter id': 'voter_id', 'gender': 'gender', 'date of birth': 'dob', 'occupation': 'occupation', 'electoral area': 'area', 'polling station': 'polling_station', 'polling station code': 'ps_code', 'registration date': 'reg_date', 'status': 'status', 'phone': 'phone', 'alt phone': 'phone2', 'email': 'email', 'address': 'address', 'notes': 'notes' };
function parseCSV(t) {
  const out = []; let row = [], c = '', q = false;
  for (let i = 0; i < t.length; i++) {
    const ch = t[i];
    if (q) { if (ch === '"' && t[i + 1] === '"') { c += '"'; i++; } else if (ch === '"') q = false; else c += ch; }
    else if (ch === '"') q = true;
    else if (ch === ',') { row.push(c); c = ''; }
    else if (ch === '\n' || ch === '\r') { if (ch === '\r' && t[i + 1] === '\n') i++; row.push(c); c = ''; if (row.some(x => x.trim())) out.push(row); row = []; }
    else c += ch;
  }
  row.push(c); if (row.some(x => x.trim())) out.push(row); return out;
}
$('bImp').onclick = () => $('file').click();
$('file').onchange = e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f) return;
  const rd = new FileReader();
  rd.onload = async () => {
    const data = parseCSV(String(rd.result).replace(/^\uFEFF/, '')); if (data.length < 2) return alert('No data rows found.');
    const head = data.shift().map(h => LABEL2FIELD[h.trim().toLowerCase()] || h.trim().toLowerCase());
    if (!head.includes('name')) return alert('The first row must contain column headings such as "Full name", "Electoral area", "Polling station", "Phone".');
    const rows = data.map(d => { const o = {}; head.forEach((k, i) => { if (FIELDS.includes(k)) o[k] = (d[i] || '').trim(); }); return o; });
    let imp = 0, skip = 0, errs = [];
    try {
      for (let i = 0; i < rows.length; i += 1000) { const r = await api('/import', 'POST', { rows: rows.slice(i, i + 1000) }); imp += r.imported; skip += r.skipped; errs = errs.concat(r.errors); }
    } catch (x) { return alert(x.message); }
    alert(`${imp} imported, ${skip} skipped.` + (errs.length ? '\n\n' + errs.slice(0, 10).join('\n') : '')); refresh();
  };
  rd.readAsText(f);
};

/* ---------- users & approvals (admin) ---------- */
const fmt = t => t ? new Date(t).toLocaleString() : '';
async function refreshPending() {
  try {
    const n = (await api('/users')).users.filter(u => u.status === 'pending').length;
    $('pendCount').textContent = n ? `(${n})` : ''; $('pendBanner').hidden = !n;
    $('pendMsg').textContent = `${n} staff registration${n === 1 ? '' : 's'} awaiting your approval.`;
  } catch (e) { /* ignore */ }
}
async function loadUsers() {
  try {
    const us = (await api('/users')).users, P = us.filter(u => u.status === 'pending');
    $('pendBox').hidden = !P.length;
    $('pb').innerHTML = P.map(u => `<tr><td>${esc(u.full_name)}</td><td>${esc(u.username)}</td><td>${esc(fmt(u.created_at))}</td><td style="white-space:nowrap"><button data-u="approve" data-id="${u.id}">Approve</button> <button class="d" data-u="reject" data-id="${u.id}">Reject</button></td></tr>`).join('');
    $('ub').innerHTML = us.filter(u => u.status !== 'pending').map(u => `<tr><td>${esc(u.username)}</td><td>${esc(u.full_name)}</td><td>${esc(u.role)}</td><td><span class="tag ${u.status === 'disabled' ? 'x' : ''}">${esc(u.status)}</span></td><td>${esc(u.approved_by || '')}</td>
      <td style="white-space:nowrap">${u.username === me.username ? '<small>(you)</small>' : `<button class="s" data-u="reset" data-id="${u.id}" data-name="${esc(u.username)}">Reset password</button> ` + (u.status === 'active' ? `<button class="d" data-u="disable" data-id="${u.id}">Disable</button>` : `<button class="s" data-u="enable" data-id="${u.id}">Enable</button>`)}</td></tr>`).join('');
    $('pendCount').textContent = P.length ? `(${P.length})` : ''; $('pendBanner').hidden = !P.length;
    $('pendMsg').textContent = `${P.length} staff registration${P.length === 1 ? '' : 's'} awaiting your approval.`;
  } catch (e) { /* handled */ }
}
$('t-users').onclick = async e => {
  const b = e.target.closest('button[data-u]'); if (!b) return;
  const id = b.dataset.id, act = b.dataset.u;
  try {
    if (act === 'reject' && !confirm('Reject and delete this request?')) return;
    if (act === 'disable' && !confirm('Disable this account? They will be signed out.')) return;
    if (act === 'reset') {
      const pw = prompt(`Temporary password for ${b.dataset.name} (min 10 characters). They must change it at next sign-in:`); if (!pw) return;
      await api(`/users/${id}/reset-password`, 'POST', { password: pw });
    } else await api(`/users/${id}/${act}`, 'POST');
    loadUsers();
  } catch (x) { alert(x.message); }
};
$('uf').onsubmit = async e => {
  e.preventDefault(); $('uErr').textContent = '';
  const f = $('uf').elements;
  try { await api('/users', 'POST', { username: f.username.value, full_name: f.full_name.value, password: f.password.value, role: f.role.value }); $('uf').reset(); loadUsers(); }
  catch (x) { $('uErr').textContent = x.message; }
};

/* ---------- audit log (admin) ---------- */
async function loadAudit() {
  try {
    const d = await api('/audit?page=' + aPage); aPages = Math.max(1, Math.ceil(d.total / d.size));
    $('ab').innerHTML = d.rows.map(r => `<tr><td>${esc(fmt(r.ts))}</td><td>${esc(r.username || '')}</td><td>${esc(r.action)}</td><td>${esc(r.target || '')}</td><td>${esc(r.detail || '')}</td><td>${esc(r.ip || '')}</td></tr>`).join('');
    $('aCnt').textContent = `${d.total} entries · page ${d.page} of ${aPages}`; $('aPrev').disabled = aPage <= 1; $('aNext').disabled = aPage >= aPages;
  } catch (e) { /* handled */ }
}
$('aPrev').onclick = () => { if (aPage > 1) { aPage--; loadAudit(); } };
$('aNext').onclick = () => { if (aPage < aPages) { aPage++; loadAudit(); } };

boot();
