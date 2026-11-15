// Readiness assessment on Cloudflare: Worker + D1 (state) + R2 (evidence files).
// A port of live/server.js: same API, same role rules, same validation. The page itself is public/index.html (built by scripts/build.mjs).
import BANK from './generated/bank.js';
import * as SC from './generated/scoring.js';
import { DEFAULT_PW } from './generated/config.js';

const MAX_FILE = 50 * 1024 * 1024;
const MAX_ROW = 1_900_000; // D1 refuses values/rows of about 2 MB
const SESSION_MS = 12 * 3600 * 1000;
const QIDS = new Set(BANK.questions.map(q => q.id));
const DECISIONS = ['YES', 'CORRECTIVE', 'NO'];
const LEVELS = ['YES', 'PARTIAL', 'NO'];
const STATUSES = ['DRAFT', 'SUBMITTED', 'IN_REVIEW', 'READY_TO_FINALIZE', 'FINALIZED'];
const ROLES = ['ADMIN', 'ASSESSOR', 'ASSESSEE'];

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const isObj = v => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
const omit = (o, keys) => Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));
const iso = () => new Date().toISOString();
const replaceAssessment = (st, a) => ({ ...st, assessments: st.assessments.map(x => (x.id === a.id ? a : x)) });

// ---------- Results (identical to live/server.js) ----------
function computeResults(reviews) {
  const dec = {}; for (const k in reviews) dec[k] = reviews[k].decision;
  const score = SC.scoreAssessment(BANK, dec);
  const counts = { YES: 0, CORRECTIVE: 0, NO: 0 }, crit = [], lost = [];
  for (const q of BANK.questions) {
    const d = dec[q.id]; if (!d) continue; counts[d]++;
    if (q.priority === 3 && d !== 'YES') crit.push({ id: q.id, decision: d });
    const l = 3 * q.priority - SC.DECISION_POINTS[d] * q.priority;
    if (l > 0) lost.push({ id: q.id, lost: l, decision: d });
  }
  lost.sort((x, y) => y.lost - x.lost);
  return { score, counts, crit, lost };
}

// ---------- D1 helpers ----------
const first = (env, sql, ...b) => env.DB.prepare(sql).bind(...b).first();
const all = async (env, sql, ...b) => (await env.DB.prepare(sql).bind(...b).all()).results;
const run = (env, sql, ...b) => env.DB.prepare(sql).bind(...b).run();

// ---------- Passwords (PBKDF2 via Web Crypto; scrypt is not available in Workers) ----------
const te = new TextEncoder();
const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
const randHex = n => toHex(crypto.getRandomValues(new Uint8Array(n)));
const iterOf = env => Math.min(100000, Math.max(1000, Number(env.PBKDF2_ITER) || 100000));
async function pbkdf2(pw, saltHex, iter) {
  const key = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return toHex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: iter }, key, 256));
}
function same(a, b) { // constant-time string comparison
  const x = te.encode(String(a)), y = te.encode(String(b));
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}
async function credentialRow(env, username, pw) { // [username, salt, "iter:hash"]
  const salt = randHex(16), iter = iterOf(env);
  return [username, salt, iter + ':' + await pbkdf2(pw, salt, iter)];
}
async function setPassword(env, username, pw) {
  await run(env, 'INSERT OR REPLACE INTO credentials VALUES (?,?,?)', ...await credentialRow(env, username, pw));
}
async function checkPassword(env, username, pw) {
  const r = await first(env, 'SELECT salt, hash FROM credentials WHERE username = ?', username);
  if (!r) {
    // First login of the built-in admin: the password comes from the ADMIN_PASSWORD secret, then it is stored hashed.
    if (username === 'admin' && env.ADMIN_PASSWORD) {
      if (!same(pw, env.ADMIN_PASSWORD)) return false;
      await setPassword(env, 'admin', pw);
      return true;
    }
    await pbkdf2(pw, 'ab'.repeat(16), iterOf(env)); // similar timing for unknown users
    return false;
  }
  const [iter, hash] = r.hash.includes(':') ? r.hash.split(':') : [iterOf(env), r.hash];
  return same(await pbkdf2(pw, r.salt, Number(iter)), hash);
}

const sha = async s => toHex(await crypto.subtle.digest('SHA-256', te.encode(s)));
const cookieOf = req => Object.fromEntries((req.headers.get('Cookie') || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]));
async function newSession(env, username) {
  const sid = randHex(32);
  await run(env, 'DELETE FROM sessions WHERE expires < ?', Date.now());
  await run(env, 'INSERT INTO sessions VALUES (?,?,?)', await sha(sid), username, Date.now() + SESSION_MS);
  return sid;
}

// ---------- State storage ----------
const stateEmpty = async env => {
  const r = await first(env, 'SELECT (SELECT COUNT(*) FROM companies) AS c, (SELECT COUNT(*) FROM users) AS u');
  return !r.c && !r.u;
};

async function load(env) {
  const [c, u, a] = (await env.DB.batch([
    env.DB.prepare('SELECT * FROM companies'), env.DB.prepare('SELECT * FROM users'), env.DB.prepare('SELECT * FROM assessments')
  ])).map(r => r.results);
  if (!c.length && !u.length) return null;
  return {
    raw: { companies: c, users: u, assessments: a },
    st: {
      companies: c.map(r => ({ ...JSON.parse(r.extra), id: r.id, name: r.name, sector: r.sector, location: r.location })),
      users: u.map(r => ({ ...JSON.parse(r.extra), id: r.id, username: r.username, displayName: r.display_name, role: r.role, companyId: r.company_id, active: !!r.active })),
      assessments: a.map(r => ({
        ...JSON.parse(r.extra), id: r.id, companyId: r.company_id, assessorId: r.assessor_id, status: r.status,
        submittedAt: r.submitted_at, finalizedAt: r.finalized_at, updatedAt: r.updated_at,
        responses: JSON.parse(r.responses), evidence: JSON.parse(r.evidence), reviews: JSON.parse(r.reviews), revComments: JSON.parse(r.rev_comments),
        ...(r.snapshot ? { snapshot: JSON.parse(r.snapshot) } : {})
      }))
    }
  };
}

const companyTuple = x => [x.id, x.name, x.sector ?? null, x.location ?? null, JSON.stringify(omit(x, ['id', 'name', 'sector', 'location']))];
const userTuple = x => [x.id, x.username, x.displayName ?? null, x.role, x.companyId ?? null, x.active ? 1 : 0, JSON.stringify(omit(x, ['id', 'username', 'displayName', 'role', 'companyId', 'active']))];
const assessTuple = x => [
  x.id, x.companyId, x.assessorId ?? null, x.status, x.submittedAt ?? null, x.finalizedAt ?? null, x.updatedAt ?? null,
  JSON.stringify(x.responses || {}), JSON.stringify(x.evidence || {}), JSON.stringify(x.reviews || {}), JSON.stringify(x.revComments || {}),
  x.snapshot ? JSON.stringify(x.snapshot) : null,
  JSON.stringify(omit(x, ['id', 'companyId', 'assessorId', 'status', 'submittedAt', 'finalizedAt', 'updatedAt', 'responses', 'evidence', 'reviews', 'revComments', 'snapshot']))
];

// Writes only the rows that changed (D1 limits the number of queries per request), all in one atomic batch.
function diff(env, table, existing, tuples, marks) {
  const old = new Map(existing.map(r => [r.id, JSON.stringify(Object.values(r))]));
  const deletes = [], writes = [], keep = new Set();
  for (const t of tuples) {
    if (t.some(v => typeof v === 'string' && v.length > MAX_ROW)) throw bad('حجم داده‌ی این مورد از حد مجاز بیشتر است', 413);
    keep.add(t[0]);
    if (old.get(t[0]) !== JSON.stringify(t)) writes.push(env.DB.prepare(`INSERT OR REPLACE INTO ${table} VALUES (${marks})`).bind(...t));
  }
  for (const id of old.keys()) if (!keep.has(id)) deletes.push(env.DB.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id));
  return { deletes, writes };
}

async function save(env, state, raw) {
  const c = diff(env, 'companies', raw.companies, state.companies.map(companyTuple), '?,?,?,?,?');
  const u = diff(env, 'users', raw.users, state.users.map(userTuple), '?,?,?,?,?,?,?');
  const a = diff(env, 'assessments', raw.assessments, state.assessments.map(assessTuple), '?,?,?,?,?,?,?,?,?,?,?,?,?');
  const stmts = [...a.deletes, ...u.deletes, ...c.deletes, ...c.writes, ...u.writes, ...a.writes];
  if (u.writes.length) { // new users get the default password
    const have = new Set((await all(env, 'SELECT username FROM credentials')).map(r => r.username));
    for (const x of state.users) if (!have.has(x.username)) stmts.push(env.DB.prepare('INSERT OR IGNORE INTO credentials VALUES (?,?,?)').bind(...await credentialRow(env, x.username, DEFAULT_PW)));
  }
  // D1 batches are transactions: a failure leaves the previous state untouched.
  for (let i = 0; i < stmts.length; i += 90) await env.DB.batch(stmts.slice(i, i + 90));
}

// ---------- Who is calling ----------
async function principalOf(env, username) {
  if (!username) return null;
  const row = await first(env, 'SELECT * FROM users WHERE username = ?', username);
  if (row) return row.active ? { username, role: row.role, id: row.id, companyId: row.company_id } : null;
  if (username === 'admin' && await stateEmpty(env)) return { username, role: 'ADMIN', id: null, companyId: null }; // bootstrap after a reset
  return null;
}
async function sessionPrincipal(env, req) {
  const sid = cookieOf(req).sid;
  if (!sid) return null;
  const h = await sha(sid);
  const s = await first(env, 'SELECT username, expires FROM sessions WHERE sid_hash = ?', h);
  if (!s) return null;
  if (s.expires < Date.now()) { await run(env, 'DELETE FROM sessions WHERE sid_hash = ?', h); return null; }
  return principalOf(env, s.username);
}

// ---------- Per-role read view ----------
function viewFor(p, st) {
  if (p.role === 'ADMIN') return st;
  if (p.role === 'ASSESSEE') {
    const mine = st.assessments.filter(a => a.companyId === p.companyId).map(a =>
      a.status === 'FINALIZED' ? a : { ...omit(a, ['snapshot']), reviews: {}, revComments: {} });
    const assessorIds = new Set(mine.map(a => a.assessorId));
    return {
      companies: st.companies.filter(c => c.id === p.companyId),
      users: st.users.filter(u => u.id === p.id || assessorIds.has(u.id)),
      assessments: mine
    };
  }
  const mine = st.assessments.filter(a => a.assessorId === p.id && a.status !== 'DRAFT');
  const cids = new Set(mine.map(a => a.companyId));
  return {
    companies: st.companies.filter(c => cids.has(c.id)),
    users: st.users.filter(u => u.id === p.id || (u.role === 'ASSESSEE' && cids.has(u.companyId))),
    assessments: mine
  };
}

// ---------- Sanitizers (everything coming from the client is untrusted) ----------
function cleanResponses(inc) {
  const out = {};
  if (!isObj(inc)) return out;
  for (const [qid, r] of Object.entries(inc)) {
    if (!QIDS.has(qid) || !isObj(r)) continue;
    const o = {};
    for (const k of ['level', 'answer']) if (LEVELS.includes(r[k])) o[k] = r[k];
    if (typeof r.text === 'string') o.text = r.text.slice(0, 5000);
    if (typeof r.comment === 'string') o.comment = r.comment.slice(0, 2000);
    out[qid] = o;
  }
  return out;
}
// fidx: Map "assessmentId|questionId|fileId" -> files row (loaded once, D1 limits queries per request)
function cleanEvidence(inc, aid, allowSample, fidx) {
  const out = {};
  if (!isObj(inc)) return out;
  for (const [qid, list] of Object.entries(inc)) {
    if (!QIDS.has(qid) || !Array.isArray(list)) continue;
    const kept = [];
    for (const f of list.slice(0, 10)) {
      if (!isObj(f)) continue;
      if (f.sample === true && allowSample) kept.push({ id: str(f.id, 40), name: str(f.name, 200), size: Math.max(0, Number(f.size) | 0), at: str(f.at, 40), sample: true });
      else { const r = fidx.get(`${aid}|${qid}|${str(f.id, 60)}`); if (r) kept.push({ id: r.id, name: r.name, size: r.size, at: r.created_at }); }
    }
    if (kept.length) out[qid] = kept;
  }
  return out;
}
const filesIndex = async (env, aid) => new Map((aid
  ? await all(env, 'SELECT id, assessment_id, question_id, name, size, created_at FROM files WHERE assessment_id = ?', aid)
  : await all(env, 'SELECT id, assessment_id, question_id, name, size, created_at FROM files')).map(r => [`${r.assessment_id}|${r.question_id}|${r.id}`, r]));
function cleanReviews(inc) {
  const out = {};
  if (!isObj(inc)) return out;
  for (const [qid, r] of Object.entries(inc)) if (QIDS.has(qid) && isObj(r) && DECISIONS.includes(r.decision)) out[qid] = { decision: r.decision };
  return out;
}
function cleanComments(inc) {
  const out = {};
  if (!isObj(inc)) return out;
  for (const [qid, t] of Object.entries(inc)) if (QIDS.has(qid) && typeof t === 'string' && t.trim()) out[qid] = t.slice(0, 2000);
  return out;
}

// ---------- Write rules per role ----------
async function mergeAssessee(env, cur, inc, p) {
  const A = cur.assessments.find(a => a.companyId === p.companyId);
  const B = isObj(inc) && Array.isArray(inc.assessments) && A ? inc.assessments.find(a => isObj(a) && a.id === A.id) : null;
  if (!A || !B) return null;
  if (A.status !== 'DRAFT') return null; // after submission the questionnaire is read-only
  const next = { ...A, responses: cleanResponses(B.responses), evidence: cleanEvidence(B.evidence, A.id, true, await filesIndex(env, A.id)), updatedAt: iso() };
  if (B.status === 'SUBMITTED') {
    if (!BANK.questions.every(q => SC.isComplete(next.responses[q.id]))) throw bad('پرسش‌نامه کامل نیست؛ همه‌ی بندها باید پاسخ داده شوند', 409);
    next.status = 'SUBMITTED'; next.submittedAt = iso();
  }
  return replaceAssessment(cur, next);
}

function mergeAssessor(cur, inc, p) {
  let st = cur, changed = false;
  for (const A of cur.assessments) {
    if (A.assessorId !== p.id || !['SUBMITTED', 'IN_REVIEW', 'READY_TO_FINALIZE'].includes(A.status)) continue;
    const B = Array.isArray(inc.assessments) ? inc.assessments.find(a => isObj(a) && a.id === A.id) : null;
    if (!B) continue;
    const next = { ...A, reviews: cleanReviews(B.reviews), revComments: cleanComments(B.revComments), updatedAt: iso() };
    for (const k of Object.keys(A.reviews)) if (!next.reviews[k]) next.reviews[k] = A.reviews[k]; // decisions can be changed, never removed
    const n = Object.keys(next.reviews).length;
    if (next.status === 'SUBMITTED' && n > 0) { next.status = 'IN_REVIEW'; next.reviewStartedAt = iso(); }
    if (next.status === 'IN_REVIEW' && n === BANK.questions.length) next.status = 'READY_TO_FINALIZE';
    if (B.status === 'FINALIZED') {
      if (next.status !== 'READY_TO_FINALIZE') throw bad('برای نهایی‌سازی همه‌ی بندها باید نمره‌دهی شده باشند', 409);
      next.status = 'FINALIZED'; next.finalizedAt = iso(); next.snapshot = computeResults(next.reviews); // snapshot is computed here, never trusted from the client
    }
    st = replaceAssessment(st, next); changed = true;
  }
  return changed ? st : null;
}

function mergeAdmin(cur, inc) {
  const out = { companies: [...cur.companies], users: [...cur.users], assessments: [...cur.assessments] };
  for (const c of Array.isArray(inc.companies) ? inc.companies : []) {
    if (!isObj(c) || typeof c.id !== 'string') continue;
    const clean = { id: str(c.id, 60), name: str(c.name, 200).trim(), sector: str(c.sector, 100), location: str(c.location, 100) };
    if (!clean.name || !/^[\w-]+$/.test(clean.id)) throw bad('نام شرکت الزامی است');
    const i = out.companies.findIndex(x => x.id === clean.id);
    if (i >= 0) out.companies[i] = { ...out.companies[i], ...clean }; else out.companies.push(clean);
  }
  for (const u of Array.isArray(inc.users) ? inc.users : []) {
    if (!isObj(u) || typeof u.id !== 'string') continue;
    const i = out.users.findIndex(x => x.id === u.id);
    if (i >= 0) {
      const ex = out.users[i];
      out.users[i] = { ...ex, displayName: str(u.displayName, 200) || ex.displayName, title: str(u.title, 200) || ex.title, active: ex.username === 'admin' ? true : !!u.active };
    } else {
      const username = str(u.username, 40).trim();
      if (!/^[A-Za-z0-9_.-]{3,40}$/.test(username) || !/^[\w-]+$/.test(u.id)) throw bad('نام کاربری نامعتبر است');
      if (out.users.some(x => x.username === username)) throw bad('این نام کاربری قبلاً ثبت شده است', 409);
      if (!ROLES.includes(u.role)) throw bad('نقش نامعتبر است');
      if (u.role === 'ASSESSEE' && !out.companies.some(c => c.id === u.companyId)) throw bad('برای ارزیابی‌شونده انتخاب شرکت الزامی است');
      out.users.push({ id: u.id, username, displayName: str(u.displayName, 200).trim(), title: str(u.title, 200), role: u.role, companyId: u.role === 'ASSESSEE' ? u.companyId : null, active: true });
    }
  }
  const isAssessor = id => out.users.some(x => x.id === id && x.role === 'ASSESSOR' && x.active);
  for (const a of Array.isArray(inc.assessments) ? inc.assessments : []) {
    if (!isObj(a) || typeof a.id !== 'string') continue;
    const i = out.assessments.findIndex(x => x.id === a.id);
    if (i >= 0) {
      const ex = out.assessments[i];
      if (a.assessorId !== ex.assessorId) {
        if (ex.status === 'FINALIZED') throw bad('ارزیابی نهایی‌شده قابل تغییر نیست', 409);
        if (!isAssessor(a.assessorId)) throw bad('ارزیاب نامعتبر است');
        out.assessments[i] = { ...ex, assessorId: a.assessorId, updatedAt: iso() };
      }
    } else {
      if (!/^[\w-]+$/.test(a.id) || !out.companies.some(c => c.id === a.companyId)) throw bad('شرکت نامعتبر است');
      if (out.assessments.some(x => x.companyId === a.companyId)) throw bad('برای این شرکت قبلاً ارزیابی ایجاد شده است', 409);
      if (!isAssessor(a.assessorId)) throw bad('ارزیاب نامعتبر است');
      out.assessments.push({ id: a.id, companyId: a.companyId, assessorId: a.assessorId, status: 'DRAFT', submittedAt: null, reviewStartedAt: null, finalizedAt: null, updatedAt: iso(), responses: {}, evidence: {}, reviews: {}, revComments: {} });
    }
  }
  return out;
}

// First save into an empty database (after a reset the admin re-creates the initial state).
async function bootstrap(env, inc) {
  if (!isObj(inc) || !Array.isArray(inc.companies) || !Array.isArray(inc.users) || !Array.isArray(inc.assessments)) throw bad('ساختار داده نامعتبر است');
  const companies = inc.companies.map(c => ({ id: str(c.id, 60), name: str(c.name, 200), sector: str(c.sector, 100), location: str(c.location, 100) }));
  const users = inc.users.map(u => ({ id: str(u.id, 60), username: str(u.username, 40), displayName: str(u.displayName, 200), title: str(u.title, 200), role: u.role, companyId: u.companyId || null, active: !!u.active }));
  if (users.some(u => !ROLES.includes(u.role) || !/^[A-Za-z0-9_.-]{3,40}$/.test(u.username)) || new Set(users.map(u => u.username)).size !== users.length)
    throw bad('داده‌ی کاربران نامعتبر است');
  if (!users.some(u => u.username === 'admin' && u.role === 'ADMIN' && u.active)) throw bad('حساب admin باید وجود داشته باشد');
  const fidx = inc.assessments.length ? await filesIndex(env) : new Map();
  const assessments = inc.assessments.map(a => {
    if (!isObj(a) || !STATUSES.includes(a.status) || !companies.some(c => c.id === a.companyId)) throw bad('داده‌ی ارزیابی نامعتبر است');
    const x = {
      id: str(a.id, 60), companyId: a.companyId, assessorId: a.assessorId || null, status: a.status,
      submittedAt: str(a.submittedAt, 40) || null, reviewStartedAt: str(a.reviewStartedAt, 40) || null, finalizedAt: str(a.finalizedAt, 40) || null, updatedAt: iso(),
      responses: cleanResponses(a.responses), evidence: cleanEvidence(a.evidence, a.id, true, fidx), reviews: cleanReviews(a.reviews), revComments: cleanComments(a.revComments)
    };
    if (x.status === 'FINALIZED') x.snapshot = computeResults(x.reviews);
    return x;
  });
  return { companies, users, assessments };
}

async function applyWrite(env, p, inc) {
  const cur = await load(env);
  if (p.role === 'ADMIN') {
    if (!cur) return { next: await bootstrap(env, inc), raw: { companies: [], users: [], assessments: [] } };
    if (!isObj(inc)) throw bad('ساختار داده نامعتبر است');
    return { next: mergeAdmin(cur.st, inc), raw: cur.raw };
  }
  if (!cur || !isObj(inc)) return null;
  const next = p.role === 'ASSESSEE' ? await mergeAssessee(env, cur.st, inc, p) : mergeAssessor(cur.st, inc, p);
  return next ? { next, raw: cur.raw } : null;
}

async function dropOrphanFiles(env, st) {
  const used = new Set();
  for (const a of st.assessments) for (const list of Object.values(a.evidence)) for (const f of list) used.add(f.id);
  const old = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const gone = (await all(env, 'SELECT id, stored_name FROM files WHERE created_at < ?', old)).filter(f => !used.has(f.id));
  if (!gone.length) return;
  await env.DB.batch(gone.slice(0, 90).map(f => env.DB.prepare('DELETE FROM files WHERE id = ?').bind(f.id)));
  await env.FILES.delete(gone.slice(0, 90).map(f => f.stored_name));
}

// ---------- Files ----------
const VIEW_TYPES = { pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg', mp4: 'video/mp4', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };
const VIEW_BY_FETCH = ['pdf', 'docx']; // rendered in the page by pdf.js / docx-preview; requires the X-Viewer header
const ALLOWED_EXT = ['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'mp4', 'zip'];
function magicOk(ext, b) {
  const h = (...xs) => xs.every((x, i) => b[i] === x);
  return { pdf: h(0x25, 0x50, 0x44, 0x46), jpg: h(0xFF, 0xD8, 0xFF), jpeg: h(0xFF, 0xD8, 0xFF), zip: h(0x50, 0x4B), docx: h(0x50, 0x4B), doc: h(0xD0, 0xCF, 0x11, 0xE0), mp4: b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70 }[ext];
}
function canReadAssessment(p, a) {
  if (p.role === 'ADMIN') return true;
  if (p.role === 'ASSESSEE') return a.company_id === p.companyId;
  return a.assessor_id === p.id && a.status !== 'DRAFT';
}
async function purgeFiles(env) {
  let cursor;
  do {
    const l = await env.FILES.list({ cursor, limit: 1000 });
    if (l.objects.length) await env.FILES.delete(l.objects.map(o => o.key));
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
}

// ---------- HTTP ----------
const SEC = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };
const json = (code, body, extra = {}) => new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json', ...SEC, ...extra } });
const noContent = () => new Response(null, { status: 204 });
async function readJson(req) {
  const buf = await req.arrayBuffer();
  if (buf.byteLength > 30e6) throw bad('درخواست بسیار بزرگ است', 413);
  try { return JSON.parse(new TextDecoder().decode(buf) || '{}'); } catch { throw bad('JSON نامعتبر است'); }
}

async function handle(req, env) {
  const url = new URL(req.url), pathname = url.pathname;
  const secure = url.protocol === 'https:' ? '; Secure' : '';

  if (req.method === 'GET' && pathname === '/') {
    const r = await env.ASSETS.fetch(new Request(new URL('/index.html', url), { method: 'GET' }));
    return new Response(r.body, { status: r.status, headers: { 'Content-Type': 'text/html; charset=utf-8', ...SEC, 'X-Frame-Options': 'DENY' } });
  }
  if (!pathname.startsWith('/api/')) return new Response('Not found', { status: 404 });
  if (pathname === '/api/health' && req.method === 'GET') return json(200, { ok: true });

  // CSRF: browsers always send Origin on cross-site writes; refuse any that is not this host.
  if (req.method !== 'GET' && req.headers.get('Origin')) {
    let host = ''; try { host = new URL(req.headers.get('Origin')).host; } catch {}
    if (host !== url.host) return json(403, { error: 'درخواست نامعتبر است' });
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    const ip = req.headers.get('CF-Connecting-IP') || 'local';
    const at = (await first(env, 'SELECT n, until FROM login_attempts WHERE ip = ?', ip)) || { n: 0, until: 0 };
    if (at.until > Date.now()) return json(429, { error: 'تلاش‌های ناموفق زیاد بود؛ یک دقیقه صبر کنید' });
    const { username, password } = await readJson(req);
    const ok = typeof username === 'string' && typeof password === 'string' && await checkPassword(env, username, password);
    const p = ok ? await principalOf(env, username) : null;
    if (!p) {
      let n = at.n + 1, until = 0; if (n >= 8) { n = 0; until = Date.now() + 60000; }
      await run(env, 'INSERT OR REPLACE INTO login_attempts VALUES (?,?,?)', ip, n, until);
      return json(401, { error: 'نام کاربری یا رمز عبور نادرست است' });
    }
    await run(env, 'DELETE FROM login_attempts WHERE ip = ?', ip);
    if (p.role !== 'ADMIN' && await stateEmpty(env)) return json(403, { error: 'سامانه هنوز راه‌اندازی نشده است' });
    return json(200, { username, role: p.role }, { 'Set-Cookie': `sid=${await newSession(env, username)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
  }
  if (pathname === '/api/logout' && req.method === 'POST') {
    const sid = cookieOf(req).sid;
    if (sid) await run(env, 'DELETE FROM sessions WHERE sid_hash = ?', await sha(sid));
    return json(200, {}, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' + secure });
  }

  const p = await sessionPrincipal(env, req);
  if (!p) return json(401, { error: 'ابتدا وارد شوید' });

  if (pathname === '/api/me' && req.method === 'GET') return json(200, { username: p.username, role: p.role });

  if (pathname === '/api/password' && req.method === 'POST') {
    const { oldPassword, newPassword } = await readJson(req);
    if (typeof newPassword !== 'string' || newPassword.length < 8) return json(400, { error: 'رمز جدید باید حداقل ۸ نویسه باشد' });
    if (typeof oldPassword !== 'string' || !await checkPassword(env, p.username, oldPassword)) return json(403, { error: 'رمز فعلی نادرست است' });
    await setPassword(env, p.username, newPassword);
    await run(env, 'DELETE FROM sessions WHERE username = ? AND sid_hash <> ?', p.username, await sha(cookieOf(req).sid)); // end every other session
    return json(200, {});
  }

  if (pathname === '/api/db' && req.method === 'GET') {
    const cur = await load(env);
    if (!cur) return noContent();
    return json(200, viewFor(p, cur.st));
  }
  if (pathname === '/api/db' && req.method === 'PUT') {
    const w = await applyWrite(env, p, await readJson(req));
    if (w) { await save(env, w.next, w.raw); await dropOrphanFiles(env, w.next); }
    return noContent();
  }

  if (pathname === '/api/reset' && req.method === 'POST') {
    if (p.role !== 'ADMIN') return json(403, { error: 'فقط مدیر سامانه' });
    await env.DB.batch([
      env.DB.prepare('DELETE FROM companies'), env.DB.prepare('DELETE FROM users'), env.DB.prepare('DELETE FROM assessments'), env.DB.prepare('DELETE FROM files'),
      env.DB.prepare("DELETE FROM credentials WHERE username <> 'admin'"), env.DB.prepare("DELETE FROM sessions WHERE username <> 'admin'")
    ]);
    await purgeFiles(env);
    return noContent();
  }

  const reset = pathname.match(/^\/api\/users\/([^/]+)\/reset-password$/);
  if (reset && req.method === 'POST') {
    if (p.role !== 'ADMIN') return json(403, { error: 'فقط مدیر سامانه' });
    let name; try { name = decodeURIComponent(reset[1]); } catch { return json(400, { error: 'نام کاربری نامعتبر است' }); }
    if (!await first(env, 'SELECT 1 FROM users WHERE username = ?', name)) return json(404, { error: 'کاربر پیدا نشد' });
    await setPassword(env, name, DEFAULT_PW);
    await run(env, 'DELETE FROM sessions WHERE username = ?', name);
    return json(200, {});
  }

  if (pathname === '/api/files' && req.method === 'POST') {
    if (p.role !== 'ASSESSEE') return json(403, { error: 'فقط ارزیابی‌شونده می‌تواند مدرک بارگذاری کند' });
    const aid = String(req.headers.get('x-assessment') || ''), qid = String(req.headers.get('x-question') || '');
    let name; try { name = decodeURIComponent(String(req.headers.get('x-name') || '')); } catch { name = ''; }
    name = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').trim().slice(0, 200);
    const A = await first(env, 'SELECT company_id, status FROM assessments WHERE id = ?', aid);
    if (!A || A.company_id !== p.companyId) return json(403, { error: 'دسترسی مجاز نیست' });
    if (A.status !== 'DRAFT') return json(409, { error: 'ارزیابی ارسال شده و قابل ویرایش نیست' });
    if (!QIDS.has(qid)) return json(400, { error: 'بند نامعتبر است' });
    const ext = (name.split('.').pop() || '').toLowerCase();
    if (!name || !ALLOWED_EXT.includes(ext)) return json(400, { error: 'قالب فایل مجاز نیست. قالب‌های مجاز: pdf، doc، docx، jpg، jpeg، mp4، zip' });
    if (Number(req.headers.get('content-length') || 0) > MAX_FILE) return json(413, { error: 'حجم فایل از ۵۰ مگابایت بیشتر است' });
    if ((await first(env, 'SELECT COUNT(*) AS n FROM files WHERE assessment_id = ? AND question_id = ?', aid, qid)).n >= 10) return json(400, { error: 'حداکثر ۱۰ فایل برای هر بند مجاز است' });
    const body = await req.arrayBuffer();
    if (body.byteLength > MAX_FILE) return json(413, { error: 'حجم فایل از ۵۰ مگابایت بیشتر است' });
    if (!body.byteLength) return json(400, { error: 'فایل خالی است' });
    if (!magicOk(ext, new Uint8Array(body, 0, Math.min(12, body.byteLength)))) return json(400, { error: 'محتوای فایل با پسوند آن همخوانی ندارد' });
    const id = 'f' + randHex(8), stored = randHex(24), at = iso();
    await env.FILES.put(stored, body);
    try { await run(env, 'INSERT INTO files VALUES (?,?,?,?,?,?,?,?)', id, aid, qid, name, body.byteLength, stored, p.username, at); }
    catch (e) { await env.FILES.delete(stored); throw e; }
    return json(200, { id, name, size: body.byteLength, at });
  }

  const dl = pathname.match(/^\/api\/files\/([\w-]+)$/);
  if (dl && req.method === 'GET') {
    const f = await first(env, 'SELECT * FROM files WHERE id = ?', dl[1]);
    const A = f && await first(env, 'SELECT company_id, assessor_id, status FROM assessments WHERE id = ?', f.assessment_id);
    if (!f || !A || !canReadAssessment(p, A)) return json(404, { error: 'فایل پیدا نشد' });
    const view = url.searchParams.get('view') === '1';
    const ext = (f.name.split('.').pop() || '').toLowerCase();
    if (p.role === 'ASSESSOR' && !view) return json(403, { error: 'ارزیاب فقط می‌تواند فایل را مشاهده کند؛ دانلود مجاز نیست' });
    if (!view) {
      const o = await env.FILES.get(f.stored_name);
      if (!o) return json(404, { error: 'فایل پیدا نشد' });
      return new Response(o.body, { status: 200, headers: {
        'Content-Type': 'application/octet-stream', 'Content-Length': String(f.size), ...SEC,
        'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(f.name)}`
      } });
    }
    // inline view: only types a browser can show safely (content already verified by magic bytes at upload)
    const type = VIEW_TYPES[ext];
    if (!type) return json(415, { error: 'پیش‌نمایش این نوع فایل ممکن نیست' });
    if (VIEW_BY_FETCH.includes(ext) && req.headers.get('x-viewer') !== '1') return json(400, { error: 'این فایل فقط از داخل سامانه قابل مشاهده است' });
    const head = { 'Content-Type': type, ...SEC, 'X-Frame-Options': 'SAMEORIGIN', 'Accept-Ranges': 'bytes' };
    // no Content-Disposition on pdf/docx: Chrome turns such a fetch() into an empty 204 (treated as a download)
    if (!VIEW_BY_FETCH.includes(ext)) head['Content-Disposition'] = `inline; filename*=UTF-8''${encodeURIComponent(f.name)}`;
    const m = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.get('range') || '')); // lets videos seek
    if (m && (m[1] || m[2])) {
      const start = m[1] ? Number(m[1]) : f.size - Number(m[2]);
      let end = m[1] && m[2] ? Number(m[2]) : f.size - 1;
      end = Math.min(end, f.size - 1);
      if (!(start >= 0 && start <= end)) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${f.size}` } });
      const o = await env.FILES.get(f.stored_name, { range: { offset: start, length: end - start + 1 } });
      if (!o) return json(404, { error: 'فایل پیدا نشد' });
      return new Response(o.body, { status: 206, headers: { ...head, 'Content-Range': `bytes ${start}-${end}/${f.size}`, 'Content-Length': String(end - start + 1) } });
    }
    const o = await env.FILES.get(f.stored_name);
    if (!o) return json(404, { error: 'فایل پیدا نشد' });
    return new Response(o.body, { status: 200, headers: { ...head, 'Content-Length': String(f.size) } });
  }

  return json(404, { error: 'پیدا نشد' });
}

export default {
  async fetch(req, env) {
    try { return await handle(req, env); }
    catch (e) {
      if (e.status && e.status < 500) return json(e.status, { error: e.message });
      console.error(e);
      return json(500, { error: 'خطای داخلی سرور' });
    }
  }
};
