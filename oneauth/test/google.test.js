'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const { SignJWT, exportJWK, generateKeyPair } = require('jose');
const { defineAuth, hashers, AuthError } = require('..');

const SECRET = 'x'.repeat(48);
const PW = 'correct-horse-battery';

// ---- Fake Google JWKS + ID token signing ----
let testKeyPair;
let testJwk;
async function getTestKey() {
  if (!testKeyPair) {
    testKeyPair = await generateKeyPair('RS256');
    testJwk = await exportJWK(testKeyPair.publicKey);
    testJwk.kid = 'test-kid-1';
    testJwk.alg = 'RS256';
    testJwk.use = 'sig';
  }
  return testKeyPair;
}

async function fakeJwks() {
  const kp = await getTestKey();
  // Return a function that mimics createRemoteJWKSet — jose's jwtVerify accepts this
  return async (protectedHeader) => {
    return kp.publicKey;
  };
}

async function signGoogleIdToken(claims, { expiresIn = '5m' } = {}) {
  const kp = await getTestKey();
  return new SignJWT({
    iss: 'https://accounts.google.com',
    email_verified: true,
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-kid-1', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .setAudience(claims.aud || 'test-google-client-id')
    .sign(kp.privateKey);
}

// ---- Fake fetch for Google token exchange ----
function createFakeFetch(idToken) {
  return async (url, opts) => {
    if (url.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({
          access_token: 'fake-access-token',
          id_token: idToken,
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      };
    }
    throw new Error(`Unexpected fetch to ${url}`);
  };
}

async function bootGoogle(overrides = {}) {
  const mails = [];
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'both' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async (m) => { mails.push(m); },
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
        redirectUri: 'http://localhost:0/auth/google/callback',
        successRedirect: '/dashboard',
        errorRedirect: '/login?error=google',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }), // default placeholder (overridden per test)
        ...overrides.google,
      },
    },
    ...overrides,
  });
  const app = express();
  app.use(auth);
  app.get('/private', auth.protect, (req, res) => res.json({ id: req.user.id, roles: req.auth.roles }));
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, { token, headers = {}, redirect = 'manual' } = {}) => {
    const res = await fetch(base + path, {
      method,
      redirect,
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    const text = await res.text();
    let json; try { json = JSON.parse(text); } catch { json = text; }
    return { status: res.status, json, headers: res.headers, url: res.url };
  };
  return { auth, mails, call, base, close: async () => { await auth.close(); server.close(); } };
}

// ---- TESTS ----

test('Google one-tap: new user is created and session returned', async () => {
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async () => {},
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
        redirectUri: 'http://localhost:0/auth/google/callback',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, { token } = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json(), headers: res.headers };
  };

  const credential = await signGoogleIdToken({
    sub: 'google-uid-001',
    email: 'newgoogle@example.com',
    name: 'Test User',
    picture: 'https://example.com/photo.jpg',
  });

  const r = await call('POST', '/auth/google/one-tap', { credential });
  assert.equal(r.status, 200);
  assert.equal(r.json.user.email, 'newgoogle@example.com');
  assert.ok(r.json.accessToken);
  assert.ok(r.json.refreshToken);
  assert.equal(r.json.user.emailVerified, true);
  assert.ok(r.json.user.providers?.includes('google'));

  await auth.close();
  server.close();
});

test('Google one-tap: returning user logs in via identity', async () => {
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async () => {},
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  };

  const cred1 = await signGoogleIdToken({ sub: 'google-returning-001', email: 'returning@example.com' });
  const r1 = await call('POST', '/auth/google/one-tap', { credential: cred1 });
  assert.equal(r1.status, 200);
  const userId1 = r1.json.user.id;

  // Login again with same sub → same user
  const cred2 = await signGoogleIdToken({ sub: 'google-returning-001', email: 'returning@example.com' });
  const r2 = await call('POST', '/auth/google/one-tap', { credential: cred2 });
  assert.equal(r2.status, 200);
  assert.equal(r2.json.user.id, userId1);

  await auth.close();
  server.close();
});

test('Google one-tap: links to verified local account', async () => {
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async () => {},
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, { token } = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  };

  // Create verified local account first
  const localUser = await auth.api.createUser({ email: 'linked@example.com', password: PW, emailVerified: true });
  const localUserId = localUser.id;

  // Google login with same email should link
  const cred = await signGoogleIdToken({ sub: 'google-link-001', email: 'linked@example.com' });
  const r = await call('POST', '/auth/google/one-tap', { credential: cred });
  assert.equal(r.status, 200);
  assert.equal(r.json.user.id, localUserId); // same user
  assert.ok(r.json.user.providers?.includes('google'));

  // Can still password login
  const pw = await call('POST', '/auth/login', { email: 'linked@example.com', password: PW });
  assert.equal(pw.status, 200);

  await auth.close();
  server.close();
});

test('Google one-tap: pre-registered unverified account gets password wiped and sessions revoked', async () => {
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async () => {},
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  app.get('/private', auth.protect, (req, res) => res.json({ ok: true }));
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, { token } = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  };

  // Attacker pre-registers the victim's email (unverified)
  await call('POST', '/auth/register', { email: 'victim@example.com', password: PW });
  const attackerLogin = await call('POST', '/auth/login', { email: 'victim@example.com', password: PW });
  const attackerToken = attackerLogin.json.accessToken;

  // Victim logs in via Google with the same email
  const cred = await signGoogleIdToken({ sub: 'google-victim-001', email: 'victim@example.com' });
  const r = await call('POST', '/auth/google/one-tap', { credential: cred });
  assert.equal(r.status, 200);
  assert.equal(r.json.user.emailVerified, true); // now verified

  // Attacker's old session is revoked
  const priv = await call('GET', '/private', undefined, { token: attackerToken });
  assert.equal(priv.status, 401);

  // Attacker's password no longer works
  const pwLogin = await call('POST', '/auth/login', { email: 'victim@example.com', password: PW });
  assert.equal(pwLogin.status, 401);

  await auth.close();
  server.close();
});

test('Google one-tap: email_verified=false is rejected', async () => {
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async () => {},
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  };

  const cred = await signGoogleIdToken({ sub: 'unverified-001', email: 'unv@example.com', email_verified: false });
  const r = await call('POST', '/auth/google/one-tap', { credential: cred });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, 'google_email_not_verified');

  await auth.close();
  server.close();
});

test('Google one-tap: wrong aud is rejected', async () => {
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async () => {},
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  };

  const cred = await signGoogleIdToken({ sub: 'wrong-aud-001', email: 'wa@example.com', aud: 'wrong-client-id' });
  const r = await call('POST', '/auth/google/one-tap', { credential: cred });
  // jose throws on aud mismatch → 500 or 403
  assert.ok(r.status >= 400);

  await auth.close();
  server.close();
});

test('Google one-tap: expired token is rejected', async () => {
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async () => {},
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  };

  // Create an already-expired token (expiresIn: -1h won't work, use a manual past exp)
  const kp = await getTestKey();
  const pastTime = Math.floor(Date.now() / 1000) - 3600;
  const cred = await new SignJWT({
    iss: 'https://accounts.google.com',
    email_verified: true,
    sub: 'expired-001',
    email: 'exp@example.com',
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-kid-1', typ: 'JWT' })
    .setIssuedAt(pastTime - 60)
    .setExpirationTime(pastTime)
    .setAudience('test-google-client-id')
    .sign(kp.privateKey);

  const r = await call('POST', '/auth/google/one-tap', { credential: cred });
  assert.ok(r.status >= 400);

  await auth.close();
  server.close();
});

test('Google: bearer transport + redirect flow throws ConfigError', () => {
  assert.throws(() => defineAuth({
    secret: SECRET,
    database: 'memory',
    session: { transport: 'bearer' },
    providers: {
      google: {
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
      },
    },
  }), /redirect flow/);
});

test('Google: bearer transport with one-tap only (redirect routes disabled) works', () => {
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    session: { transport: 'bearer' },
    providers: {
      google: {
        clientId: 'test-google-client-id',
        // no clientSecret needed when redirect routes are disabled
      },
    },
    routes: { google: false, googleCallback: false },
  });
  auth.close();
});

test('Google: social-only user cannot password-login but can set a password through reset', async () => {
  const jwksResolver = await fakeJwks();
  const mails = [];
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async (m) => { mails.push(m); },
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, { token } = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  };

  // Create social user via one-tap
  const cred = await signGoogleIdToken({ sub: 'social-only-001', email: 'socialonly@example.com' });
  const r = await call('POST', '/auth/google/one-tap', { credential: cred });
  assert.equal(r.status, 200);

  // Password login fails generically
  const pwLogin = await call('POST', '/auth/login', { email: 'socialonly@example.com', password: PW });
  assert.equal(pwLogin.status, 401);
  assert.equal(pwLogin.json.error.code, 'invalid_credentials');

  // Forgot password sends a reset email
  await call('POST', '/auth/forgot-password', { email: 'socialonly@example.com' });
  await new Promise((r) => setTimeout(r, 50));
  const mail = mails.find((m) => m.type === 'reset' && m.to === 'socialonly@example.com');
  assert.ok(mail, 'Reset email should have been sent');

  // Reset password sets one
  const resetRes = await call('POST', '/auth/reset-password', { token: mail.token, password: 'brand-new-password-1' });
  assert.equal(resetRes.status, 200);

  // Now password login works
  const pwLogin2 = await call('POST', '/auth/login', { email: 'socialonly@example.com', password: 'brand-new-password-1' });
  assert.equal(pwLogin2.status, 200);

  await auth.close();
  server.close();
});

test('Google: unlinkIdentity refuses to unlink the last login method', async () => {
  const jwksResolver = await fakeJwks();
  const auth = defineAuth({
    secret: SECRET,
    database: 'memory',
    logger: { info() {}, warn() {}, error() {} },
    session: { transport: 'bearer' },
    password: { hasher: hashers.scrypt({ N: 2 ** 12 }) },
    email: async () => {},
    rateLimit: false,
    providers: {
      google: {
        clientId: 'test-google-client-id',
        jwks: jwksResolver,
        fetch: async () => ({ ok: false }),
      },
    },
    routes: { google: false, googleCallback: false },
  });
  const app = express();
  app.use(auth);
  const server = await new Promise((ok) => { const s = app.listen(0, '127.0.0.1', () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  };

  // Create social-only user
  const cred = await signGoogleIdToken({ sub: 'unlink-001', email: 'unlink@example.com' });
  const r = await call('POST', '/auth/google/one-tap', { credential: cred });
  const userId = r.json.user.id;

  // Trying to unlink the only provider without a password should fail
  await assert.rejects(
    () => auth.api.unlinkIdentity(userId, 'google'),
    (err) => err.code === 'last_login_method',
  );

  // List identities works
  const ids = await auth.api.listIdentities(userId);
  assert.equal(ids.length, 1);
  assert.equal(ids[0].provider, 'google');

  await auth.close();
  server.close();
});

test('Google redirect: GET /auth/google redirects to Google with correct params', async () => {
  const t = await bootGoogle();
  const r = await t.call('GET', '/auth/google', undefined, { redirect: 'manual' });
  assert.equal(r.status, 302);
  const location = r.headers.get('location');
  assert.ok(location.startsWith('https://accounts.google.com/o/oauth2/v2/auth'));
  const url = new URL(location);
  assert.equal(url.searchParams.get('client_id'), 'test-google-client-id');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('state'));
  assert.ok(url.searchParams.get('nonce'));
  assert.ok(url.searchParams.get('code_challenge'));

  // State cookie should be set
  const setCookies = r.headers.getSetCookie();
  const stateCookie = setCookies.find((c) => c.startsWith('__oa_google_state='));
  assert.ok(stateCookie, 'State cookie must be set');
  assert.ok(stateCookie.includes('HttpOnly'));

  await t.close();
});

test('Google redirect: open redirectTo is rejected (silently ignored)', async () => {
  const t = await bootGoogle();
  const r = await t.call('GET', '/auth/google?redirectTo=https://evil.example/steal', undefined, { redirect: 'manual' });
  assert.equal(r.status, 302);
  const location = r.headers.get('location');
  // The redirectTo should NOT appear in the state cookie at all
  // (we can't easily inspect cookie contents here, but the evil URL must not be in the redirect)
  assert.ok(!location.includes('evil.example'));
  await t.close();
});

test('Google callback: missing state cookie is rejected', async () => {
  const t = await bootGoogle();
  const r = await t.call('GET', '/auth/google/callback?state=fake&code=fake', undefined, { redirect: 'manual' });
  assert.equal(r.status, 302);
  const location = r.headers.get('location');
  assert.ok(location.includes('/login'));
  assert.ok(location.includes('error='));
  await t.close();
});

test('Google: one-tap returns cookies when transport is cookie or both', async () => {
  const t = await bootGoogle();
  const cred = await signGoogleIdToken({ sub: 'cookie-001', email: 'cookie@example.com' });
  const r = await t.call('POST', '/auth/google/one-tap', { credential: cred });
  assert.equal(r.status, 200);
  assert.ok(r.json.accessToken); // 'both' transport includes body tokens
  const setCookies = r.headers.getSetCookie();
  assert.ok(setCookies.length >= 2, 'Should set access and refresh cookies');
  await t.close();
});

test('all existing tests (register/login/refresh/me) still work with google provider configured', async () => {
  const t = await bootGoogle();
  // Register + login + me flow
  await t.call('POST', '/auth/register', { email: 'trad@example.com', password: PW });
  const login = await t.call('POST', '/auth/login', { email: 'trad@example.com', password: PW });
  assert.equal(login.status, 200);
  assert.ok(login.json.accessToken);
  const me = await t.call('GET', '/auth/me', undefined, { token: login.json.accessToken });
  assert.equal(me.json.user.email, 'trad@example.com');
  // No providers for a password-only user
  assert.equal(me.json.user.providers, undefined);

  // Refresh works
  const ref = await t.call('POST', '/auth/refresh', { refreshToken: login.json.refreshToken });
  assert.equal(ref.status, 200);

  await t.close();
});
