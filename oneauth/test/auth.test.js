'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { defineAuth, hashers, AuthError } = require('..');

const SECRET = 'x'.repeat(48);
const PW = 'correct-horse-battery';

async function boot(overrides = {}) {
  const mails = [];
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async (m) => { mails.push(m); },
    rateLimit: false,
    seedUsers: [{ email: 'boss@example.com', password: PW, roles: ['admin'] }],
    ...overrides,
  });
  const app = express();
  app.use(auth);
  app.get('/private', auth.protect, (req, res) => res.json({ id: req.user.id, roles: req.auth.roles }));
  app.get('/admin', auth.requireRole('admin'), (req, res) => res.json({ ok: true }));
  app.get('/verified', auth.requireVerified, (req, res) => res.json({ ok: true }));
  app.get('/maybe', auth.optional, (req, res) => res.json({ anon: !req.user }));
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, { token, headers = {} } = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    const text = await res.text();
    let json; try { json = JSON.parse(text); } catch { json = text; }
    return { status: res.status, json, headers: res.headers };
  };
  const signup = async (email, password = PW, extra = {}) => {
    await call('POST', '/auth/register', { email, password, ...extra });
    return call('POST', '/auth/login', { email, password });
  };
  return { auth, mails, call, signup, close: async () => { await auth.close(); server.close(); } };
}

test('register -> login -> me -> protected route', async () => {
  const t = await boot();
  const reg = await t.call('POST', '/auth/register', { email: 'A@Example.com', password: PW });
  assert.equal(reg.status, 202);
  assert.equal(reg.json.accessToken, undefined);
  const login = await t.call('POST', '/auth/login', { email: 'a@example.com', password: PW });
  assert.equal(login.status, 200);
  assert.deepEqual(login.json.user.roles, ['user']);
  const me = await t.call('GET', '/auth/me', undefined, { token: login.json.accessToken });
  assert.equal(me.json.user.email, 'a@example.com');
  assert.equal(me.json.user.passwordHash, undefined);
  const priv = await t.call('GET', '/private', undefined, { token: login.json.accessToken });
  assert.equal(priv.status, 200);
  assert.equal((await t.call('GET', '/private')).status, 401);
  assert.equal((await t.call('GET', '/private', undefined, { token: 'garbage' })).status, 401);
  assert.equal((await t.call('GET', '/maybe')).json.anon, true);
  await t.close();
});

test('duplicate registration is indistinguishable and wrong logins are generic', async () => {
  const t = await boot();
  const a = await t.call('POST', '/auth/register', { email: 'dup@example.com', password: PW });
  const b = await t.call('POST', '/auth/register', { email: 'dup@example.com', password: 'another-long-pass' });
  assert.equal(a.status, 202); assert.equal(b.status, 202); assert.deepEqual(a.json, b.json);
  const bad1 = await t.call('POST', '/auth/login', { email: 'dup@example.com', password: 'nope-nope-nope' });
  const bad2 = await t.call('POST', '/auth/login', { email: 'ghost@example.com', password: 'nope-nope-nope' });
  assert.equal(bad1.status, 401); assert.deepEqual(bad1.json, bad2.json);
  await t.close();
});

test('mass assignment: roles from the request body are ignored; seeded admin works', async () => {
  const t = await boot();
  const s = await t.signup('evil@example.com', PW, { roles: ['admin'], role: 'admin', emailVerified: true });
  assert.deepEqual(s.json.user.roles, ['user']);
  assert.equal(s.json.user.emailVerified, false);
  assert.equal((await t.call('GET', '/admin', undefined, { token: s.json.accessToken })).status, 403);
  const boss = await t.call('POST', '/auth/login', { email: 'boss@example.com', password: PW });
  assert.equal((await t.call('GET', '/admin', undefined, { token: boss.json.accessToken })).status, 200);
  await t.close();
});

test('input hardening: NoSQL-style objects, bad JSON, weak passwords', async () => {
  const t = await boot();
  assert.equal((await t.call('POST', '/auth/login', { email: { $gt: '' }, password: { $gt: '' } })).status, 401);
  assert.equal((await t.call('POST', '/auth/register', { email: { $ne: 1 }, password: PW })).status, 400);
  assert.equal((await t.call('POST', '/auth/register', '{not json')).status, 400);
  assert.equal((await t.call('POST', '/auth/register', { email: 'w@example.com', password: 'short' })).status, 400);
  assert.equal((await t.call('POST', '/auth/register', { email: 'not-an-email', password: PW })).status, 400);
  await t.close();
});

test('refresh rotates tokens; reusing an old one revokes the whole session', async () => {
  const t = await boot({ session: { transport: 'bearer', refreshReuseGrace: 0 } });
  const s = await t.signup('r@example.com');
  const r1 = await t.call('POST', '/auth/refresh', { refreshToken: s.json.refreshToken });
  assert.equal(r1.status, 200);
  assert.notEqual(r1.json.refreshToken, s.json.refreshToken);
  await new Promise((r) => setTimeout(r, 5));
  const replay = await t.call('POST', '/auth/refresh', { refreshToken: s.json.refreshToken });
  assert.equal(replay.status, 401);
  assert.equal(replay.json.error.code, 'refresh_reuse_detected');
  assert.equal((await t.call('POST', '/auth/refresh', { refreshToken: r1.json.refreshToken })).status, 401);
  assert.equal((await t.call('GET', '/private', undefined, { token: r1.json.accessToken })).status, 401);
  await t.close();
});

test('concurrent refresh (two tabs) inside the grace window does not kill the session', async () => {
  const t = await boot();
  const s = await t.signup('tabs@example.com');
  const [a, b] = await Promise.all([
    t.call('POST', '/auth/refresh', { refreshToken: s.json.refreshToken }),
    t.call('POST', '/auth/refresh', { refreshToken: s.json.refreshToken }),
  ]);
  const ok = [a, b].filter((x) => x.status === 200);
  assert.equal(ok.length, 1);
  assert.equal((await t.call('GET', '/private', undefined, { token: ok[0].json.accessToken })).status, 200);
  await t.close();
});

test('logout ends the session immediately, even for a still-valid access token', async () => {
  const t = await boot();
  const s = await t.signup('out@example.com');
  assert.equal((await t.call('POST', '/auth/logout', { refreshToken: s.json.refreshToken }, { token: s.json.accessToken })).status, 200);
  assert.equal((await t.call('GET', '/private', undefined, { token: s.json.accessToken })).status, 401);
  assert.equal((await t.call('POST', '/auth/refresh', { refreshToken: s.json.refreshToken })).status, 401);
  await t.close();
});

test('password reset: single use, revokes sessions, does not leak account existence', async () => {
  const t = await boot();
  const s = await t.signup('reset@example.com');
  const ghost = await t.call('POST', '/auth/forgot-password', { email: 'ghost@example.com' });
  const real = await t.call('POST', '/auth/forgot-password', { email: 'reset@example.com' });
  assert.deepEqual(ghost.json, real.json);
  await new Promise((r) => setTimeout(r, 20));
  const mail = t.mails.filter((m) => m.type === 'reset').pop();
  assert.ok(mail && mail.to === 'reset@example.com');
  const NEW = 'brand-new-password-1';
  assert.equal((await t.call('POST', '/auth/reset-password', { token: mail.token, password: NEW })).status, 200);
  assert.equal((await t.call('POST', '/auth/reset-password', { token: mail.token, password: 'yet-another-pass-2' })).status, 400);
  assert.equal((await t.call('GET', '/private', undefined, { token: s.json.accessToken })).status, 401);
  assert.equal((await t.call('POST', '/auth/login', { email: 'reset@example.com', password: PW })).status, 401);
  assert.equal((await t.call('POST', '/auth/login', { email: 'reset@example.com', password: NEW })).status, 200);
  await t.close();
});

test('email verification can be required before login', async () => {
  const t = await boot({ emailVerification: { required: true } });
  await t.call('POST', '/auth/register', { email: 'v@example.com', password: PW });
  const blocked = await t.call('POST', '/auth/login', { email: 'v@example.com', password: PW });
  assert.equal(blocked.status, 403);
  assert.equal(blocked.json.error.code, 'email_not_verified');
  await new Promise((r) => setTimeout(r, 20));
  const mail = t.mails.find((m) => m.type === 'verify');
  assert.equal((await t.call('POST', '/auth/verify-email', { token: mail.token })).status, 200);
  const ok = await t.call('POST', '/auth/login', { email: 'v@example.com', password: PW });
  assert.equal(ok.status, 200);
  assert.equal((await t.call('GET', '/verified', undefined, { token: ok.json.accessToken })).status, 200);
  await t.close();
});

test('account lockout after repeated failures', async () => {
  const t = await boot({ lockout: { maxAttempts: 3, duration: '5m' } });
  await t.signup('lock@example.com');
  for (let i = 0; i < 3; i++) await t.call('POST', '/auth/login', { email: 'lock@example.com', password: 'wrong-wrong-wrong' });
  const locked = await t.call('POST', '/auth/login', { email: 'lock@example.com', password: PW });
  assert.equal(locked.status, 429);
  assert.equal(locked.json.error.code, 'account_locked');
  await t.close();
});

test('change password keeps the current session, signs out the others', async () => {
  const t = await boot();
  const a = await t.signup('cp@example.com');
  const b = await t.call('POST', '/auth/login', { email: 'cp@example.com', password: PW });
  const res = await t.call('POST', '/auth/change-password', { currentPassword: PW, newPassword: 'a-completely-new-pass' }, { token: a.json.accessToken });
  assert.equal(res.status, 200);
  assert.equal((await t.call('GET', '/private', undefined, { token: a.json.accessToken })).status, 200);
  assert.equal((await t.call('GET', '/private', undefined, { token: b.json.accessToken })).status, 401);
  assert.equal((await t.call('POST', '/auth/change-password', { currentPassword: 'wrong-wrong-wrong', newPassword: 'zzzzzzzzzzzz1' }, { token: a.json.accessToken })).status, 403);
  await t.close();
});

test('sessions can be listed and revoked', async () => {
  const t = await boot();
  const a = await t.signup('s@example.com');
  const b = await t.call('POST', '/auth/login', { email: 's@example.com', password: PW });
  const list = await t.call('GET', '/auth/sessions', undefined, { token: a.json.accessToken });
  assert.equal(list.json.sessions.length, 2);
  const other = list.json.sessions.find((x) => !x.current);
  assert.equal((await t.call('DELETE', `/auth/sessions/${other.id}`, undefined, { token: a.json.accessToken })).status, 200);
  assert.equal((await t.call('GET', '/private', undefined, { token: b.json.accessToken })).status, 401);
  await t.close();
});

test('rate limiting returns 429 with Retry-After', async () => {
  const t = await boot({ rateLimit: { rules: { login: { max: 2, windowMs: 60000 } } } });
  for (let i = 0; i < 2; i++) await t.call('POST', '/auth/login', { email: 'x@example.com', password: 'nope-nope-nope' });
  const res = await t.call('POST', '/auth/login', { email: 'x@example.com', password: 'nope-nope-nope' });
  assert.equal(res.status, 429);
  assert.ok(res.headers.get('retry-after'));
  await t.close();
});

test('cookie transport: httpOnly cookies, no tokens in body, hostile origins rejected', async () => {
  const t = await boot({ session: { transport: 'cookie' } });
  await t.call('POST', '/auth/register', { email: 'c@example.com', password: PW });
  const login = await t.call('POST', '/auth/login', { email: 'c@example.com', password: PW });
  assert.equal(login.json.accessToken, undefined);
  const cookies = login.headers.getSetCookie();
  assert.equal(cookies.length, 2);
  assert.ok(cookies.every((c) => /HttpOnly/.test(c) && /SameSite=Lax/.test(c)));
  assert.ok(cookies.find((c) => c.startsWith('oa_refresh=')).includes('Path=/auth'));
  const jar = cookies.map((c) => c.split(';')[0]).join('; ');
  assert.equal((await t.call('GET', '/private', undefined, { headers: { cookie: jar } })).status, 200);
  const evil = await t.call('POST', '/auth/logout-all', undefined, { headers: { cookie: jar, origin: 'https://evil.example' } });
  assert.equal(evil.status, 403);
  assert.equal(evil.json.error.code, 'origin_not_allowed');
  assert.equal((await t.call('POST', '/auth/refresh', {}, { headers: { cookie: jar } })).status, 200);
  await t.close();
});

test('third-party middleware and per-route middleware plug in via the config file', async () => {
  const seen = [];
  const t = await boot({
    use: [(req, res, next) => { seen.push(req.path); next(); }],
    routeMiddleware: { register: [(req, res) => res.status(418).json({ blocked: 'captcha' })] },
  });
  assert.equal((await t.call('POST', '/auth/register', { email: 'k@example.com', password: PW })).status, 418);
  await t.call('POST', '/auth/login', { email: 'k@example.com', password: PW });
  assert.deepEqual(seen, ['/register', '/login']);
  await t.close();
});

test('hooks: beforeRegister can veto; extra user fields are stored and whitelisted', async () => {
  const t = await boot({
    user: { fields: { name: { type: String }, plan: { type: String } }, registerFields: ['name'] },
    hooks: { beforeRegister: ({ email }) => { if (email.endsWith('@blocked.com')) throw new AuthError(403, 'domain_blocked', 'This email domain is not allowed.'); } },
  });
  const s = await t.signup('n@example.com', PW, { name: '  Sumit ', plan: 'enterprise' });
  assert.equal(s.json.user.name, 'Sumit');
  assert.equal(s.json.user.plan, undefined);
  const veto = await t.call('POST', '/auth/register', { email: 'a@blocked.com', password: PW });
  assert.equal(veto.status, 403);
  assert.equal(veto.json.error.code, 'domain_blocked');
  await t.close();
});

test('any hasher / signer with the same shape can be plugged in (bcrypt-style, jsonwebtoken-style)', async () => {
  const calls = { hash: 0, sign: 0 };
  const fakeBcrypt = { hash: async (p, r) => { calls.hash++; return `$2b$${r}$` + Buffer.from(p).toString('hex'); }, compare: async (p, h) => h.endsWith(Buffer.from(p).toString('hex')) };
  const store = {};
  const fakeJwt = {
    sign: (claims, secret, o) => { calls.sign++; const id = 'tok' + calls.sign; store[id] = claims; return id; },
    verify: (token) => { if (!store[token]) throw new Error('bad'); return store[token]; },
  };
  const { jwt } = require('..');
  const t = await boot({
    password: { hasher: hashers.bcrypt(fakeBcrypt, { rounds: 4 }) },
    tokens: { adapter: jwt.jsonwebtoken(fakeJwt, { secret: 'whatever' }) },
    secret: undefined,
  });
  const s = await t.signup('p@example.com');
  assert.equal(s.status, 200);
  assert.ok(calls.hash >= 1 && calls.sign >= 1);
  assert.equal((await t.call('GET', '/private', undefined, { token: s.json.accessToken })).status, 200);
  await t.close();
});

test('startup fails loudly with helpful messages', () => {
  const base = { secret: SECRET, database: 'memory' };
  assert.throws(() => defineAuth({ database: 'memory' }), /`secret` is required/);
  assert.throws(() => defineAuth({ ...base, secret: 'short' }), /at least 32/);
  assert.throws(() => defineAuth({ secret: SECRET }), /`database` is required/);
  assert.throws(() => defineAuth({ ...base, sesion: {} }), /Did you mean `session`/);
  assert.throws(() => defineAuth({ ...base, session: { transport: 'smoke' } }), /"cookie", "bearer" or "both"/);
  assert.throws(() => defineAuth({ ...base, tokens: { accessTtl: 'soon' } }), /tokens.accessTtl/);
  assert.throws(() => defineAuth({ ...base, password: { hasher: {} } }), /hasher/);
  assert.doesNotThrow(() => defineAuth({ ...base, use: [(req, res, next) => next()] }).close());
});
