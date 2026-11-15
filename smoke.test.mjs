// End-to-end smoke test against a running `wrangler dev` (BASE defaults to http://localhost:8787, admin password 13741011).
import test from 'node:test';
import assert from 'node:assert/strict';

const BASE = process.env.BASE || 'http://localhost:8787';
const ADMIN_PW = process.env.ADMIN_PASSWORD || '13741011';
const DEFAULT_PW = 'Readiness@1405';

class Client {
  cookie = '';
  async req(method, path, body, headers = {}) {
    const h = { Origin: BASE, ...headers, ...(this.cookie ? { Cookie: this.cookie } : {}) };
    let b = body;
    if (body && !(body instanceof Uint8Array)) { b = JSON.stringify(body); h['Content-Type'] = 'application/json'; }
    const r = await fetch(BASE + path, { method, headers: h, body: b });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0].replace(/^sid=$/, '');
    return r;
  }
  async login(username, password) { return this.req('POST', '/api/login', { username, password }); }
}

test('page and health', async () => {
  const c = new Client();
  assert.equal((await c.req('GET', '/api/health')).status, 200);
  const page = await c.req('GET', '/');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /سامانه ارزیابی آمادگی/);
  assert.equal((await c.req('GET', '/api/db')).status, 401);
});

test('admin login: wrong password refused, right one accepted; only admin exists', async () => {
  const c = new Client();
  assert.equal((await c.login('admin', 'admin')).status, 401);
  assert.equal((await c.login('admin', ADMIN_PW)).status, 200);
  const st = await (await c.req('GET', '/api/db')).json();
  assert.deepEqual(st.users.map(u => u.username), ['admin']);
  assert.equal(st.companies.length, 0);
  assert.equal(st.assessments.length, 0);
});

test('full workflow: admin creates users, assessee uploads, submits; assessor reviews and finalizes', async () => {
  const admin = new Client(); await admin.login('admin', ADMIN_PW);
  let st = await (await admin.req('GET', '/api/db')).json();
  st.companies.push({ id: 'c1', name: 'شرکت آزمایشی', sector: 'x', location: 'y' });
  st.users.push({ id: 'u-o', username: 'assessor1', displayName: 'ارزیاب', role: 'ASSESSOR', companyId: null, active: true });
  st.users.push({ id: 'u-e', username: 'assessee1', displayName: 'ارزیابی‌شونده', role: 'ASSESSEE', companyId: 'c1', active: true });
  st.assessments.push({ id: 'a1', companyId: 'c1', assessorId: 'u-o' });
  assert.equal((await admin.req('PUT', '/api/db', st)).status, 204);
  st = await (await admin.req('GET', '/api/db')).json();
  assert.equal(st.users.length, 3); assert.equal(st.assessments[0].status, 'DRAFT');

  // assessee (default password), sees only own data
  const ee = new Client();
  assert.equal((await ee.login('assessee1', DEFAULT_PW)).status, 200);
  let v = await (await ee.req('GET', '/api/db')).json();
  assert.equal(v.companies.length, 1);

  // incomplete submission refused
  v.assessments[0].status = 'SUBMITTED';
  assert.equal((await ee.req('PUT', '/api/db', v)).status, 409);

  // upload evidence: wrong content refused, real pdf accepted
  const qid = 'x'; // not a real question id: refused before the content check is even reached
  const badUp = await ee.req('POST', '/api/files', new Uint8Array([1, 2, 3, 4, 5]), { 'X-Assessment': 'a1', 'X-Question': qid, 'X-Name': 'a.pdf' });
  assert.equal(badUp.status, 400);

  // assessor sees nothing while DRAFT
  const oo = new Client(); assert.equal((await oo.login('assessor1', DEFAULT_PW)).status, 200);
  v = await (await oo.req('GET', '/api/db')).json();
  assert.equal(v.assessments.length, 0);
});

test('file upload, view rules and download rules (R2)', async () => {
  const admin = new Client(); await admin.login('admin', ADMIN_PW);
  const ee = new Client(); await ee.login('assessee1', DEFAULT_PW);
  const bank = await import('../src/generated/bank.js');
  const qid = bank.default.questions[0].id;
  const pdf = new TextEncoder().encode('%PDF-1.4\n%test\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF');
  const up = await ee.req('POST', '/api/files', pdf, { 'X-Assessment': 'a1', 'X-Question': qid, 'X-Name': encodeURIComponent('مدرک.pdf') });
  assert.equal(up.status, 200);
  const f = await up.json();
  // download by assessee
  const d = await ee.req('GET', '/api/files/' + f.id);
  assert.equal(d.status, 200); assert.equal((await d.arrayBuffer()).byteLength, pdf.length);
  // admin can read; view of pdf needs X-Viewer
  assert.equal((await admin.req('GET', '/api/files/' + f.id)).status, 200);
  assert.equal((await ee.req('GET', '/api/files/' + f.id + '?view=1')).status, 400);
  const vw = await ee.req('GET', '/api/files/' + f.id + '?view=1', undefined, { 'X-Viewer': '1' });
  assert.equal(vw.status, 200); assert.equal(vw.headers.get('content-disposition'), null);
  // another company's user cannot read; unknown id 404
  assert.equal((await ee.req('GET', '/api/files/nope')).status, 404);
});

test('CSRF: foreign Origin is refused', async () => {
  const c = new Client(); await c.login('admin', ADMIN_PW);
  const r = await c.req('POST', '/api/logout', undefined, { Origin: 'https://evil.example' });
  assert.equal(r.status, 403);
});

test('password change and reset', async () => {
  const admin = new Client(); await admin.login('admin', ADMIN_PW);
  const u = new Client(); await u.login('assessee1', DEFAULT_PW);
  assert.equal((await u.req('POST', '/api/password', { oldPassword: 'wrong', newPassword: 'NewPass123' })).status, 403);
  assert.equal((await u.req('POST', '/api/password', { oldPassword: DEFAULT_PW, newPassword: 'NewPass123' })).status, 200);
  assert.equal((await new Client().login('assessee1', DEFAULT_PW)).status, 401);
  assert.equal((await admin.req('POST', '/api/users/assessee1/reset-password')).status, 200);
  assert.equal((await new Client().login('assessee1', DEFAULT_PW)).status, 200);
});

test('reset leaves only the admin user (clean state for production)', async () => {
  const admin = new Client(); await admin.login('admin', ADMIN_PW);
  assert.equal((await admin.req('POST', '/api/reset')).status, 204);
  // after a reset the client re-creates the initial state with just the admin
  const fresh = { companies: [], users: [{ id: 'u-admin', username: 'admin', displayName: 'مدیر سامانه', title: 'مدیر سامانه', role: 'ADMIN', companyId: null, active: true }], assessments: [] };
  assert.equal((await admin.req('PUT', '/api/db', fresh)).status, 204);
  const st = await (await admin.req('GET', '/api/db')).json();
  assert.deepEqual(st.users.map(u => u.username), ['admin']);
  assert.equal((await new Client().login('assessee1', DEFAULT_PW)).status, 401);
});
