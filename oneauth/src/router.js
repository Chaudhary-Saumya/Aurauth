'use strict';
const { ConfigError, E, toAuthError, sendError } = require('./errors');
const { serializeCookie, parseCookies } = require('./utils');
const { normalizeEmail } = require('./utils');
const {
  generateCodeVerifier, generateCodeChallenge,
  STATE_COOKIE_NAME, STATE_TTL_MS,
  signStateCookie, verifyStateCookie,
  verifyGoogleIdToken, safeRedirectTo,
  GOOGLE_AUTH_URL, GOOGLE_TOKEN_URL,
} = require('./google');

function createRouter(cfg, service, mw, log) {
  let express;
  try { express = require('express'); } catch {
    throw new ConfigError('express is not installed. Run `npm i express`.');
  }
  const { transport, cookies } = cfg.session;
  const useCookies = transport === 'cookie' || transport === 'both';
  const useBody = transport === 'bearer' || transport === 'both';
  const limiter = cfg.rateLimit && cfg.rateLimit.limiter;

  const outer = express.Router();
  const r = express.Router();
  let warnedProxy = false;

  const meta = (req) => ({ ip: req.ip, userAgent: req.headers['user-agent'], req });
  const body = (req) => (req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {});

  async function limit(name, key) {
    const rule = cfg.rateLimit && cfg.rateLimit.rules[name];
    if (!limiter || !rule) return;
    const res = await limiter.hit(`${name}:${key}`, rule);
    if (!res.allowed) throw E.tooMany(res.retryAfterSec);
  }

  function setCookies(res, s) {
    const base = { secure: cookies.secure, sameSite: cookies.sameSite, domain: cookies.domain };
    res.append('Set-Cookie', serializeCookie(mw.cookieNames.access, s.accessToken, { ...base, path: '/', maxAgeMs: s.expiresIn * 1000 }));
    res.append('Set-Cookie', serializeCookie(mw.cookieNames.refresh, s.refreshToken, { ...base, path: cfg.basePath, maxAgeMs: s.refreshMaxAgeMs }));
  }
  function clearCookies(res) {
    const base = { secure: cookies.secure, sameSite: cookies.sameSite, domain: cookies.domain, maxAgeMs: 0 };
    res.append('Set-Cookie', serializeCookie(mw.cookieNames.access, '', { ...base, path: '/' }));
    res.append('Set-Cookie', serializeCookie(mw.cookieNames.refresh, '', { ...base, path: cfg.basePath }));
  }
  function sendSession(res, s, status = 200) {
    if (useCookies) setCookies(res, s);
    const out = { user: s.user, expiresIn: s.expiresIn };
    if (useBody) { out.accessToken = s.accessToken; out.refreshToken = s.refreshToken; }
    res.status(status).json(out);
  }

  // ---- pipeline shared by every auth route
  r.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    if (cfg.isProd && !warnedProxy && req.headers['x-forwarded-for'] && !req.app.get('trust proxy')) {
      warnedProxy = true;
      log.warn('[oneauth] X-Forwarded-For seen but `app.set("trust proxy", 1)` is not set: rate limiting will see the proxy IP for every user.');
    }
    mw.waitReady().then(() => next(), (e) => next(e));
  });
  for (const fn of cfg.use) r.use(fn); // third-party middleware (helmet, cors, captcha, ...)
  r.use((req, res, next) => (req.body !== undefined ? next() : express.json({ limit: '10kb', strict: true })(req, res, next)));
  r.use((req, res, next) => { try { mw.checkOrigin(req); next(); } catch (e) { next(e); } });

  const enabled = (name) => {
    if (!cfg.routes[name]) return false;
    if (name === 'register') return cfg.registration.enabled;
    if (name === 'forgotPassword' || name === 'resetPassword') return cfg.passwordReset.enabled;
    if (name === 'verifyEmail' || name === 'resendVerification') return cfg.emailVerification.enabled;
    if (name === 'google' || name === 'googleCallback' || name === 'googleOneTap') return !!cfg.providers.google;
    return true;
  };

  function route(method, path, name, { auth = false } = {}, handler) {
    if (!enabled(name)) return;
    const chain = [
      (req, res, next) => limit(name, req.ip).then(() => next(), next),
      ...(cfg.routeMiddleware[name] || []),
      ...(auth ? [mw.protect] : []),
      (req, res, next) => Promise.resolve(handler(req, res)).catch(next),
    ];
    r[method](path, ...chain);
  }

  route('post', '/register', 'register', {}, async (req, res) => {
    const out = await service.register(body(req), meta(req));
    if (out.session) return sendSession(res, out.session, 201);
    res.status(202).json({ ok: true, message: 'Registration received. If verification is required, check your email, then sign in.' });
  });

  route('post', '/login', 'login', {}, async (req, res) => sendSession(res, await service.login(body(req), meta(req))));

  route('post', '/refresh', 'refresh', {}, async (req, res) => {
    try {
      sendSession(res, await service.refresh(mw.extractRefresh(req), meta(req)));
    } catch (e) {
      if (e && e.status === 401 && e.code !== 'refresh_in_progress' && useCookies) clearCookies(res);
      throw e;
    }
  });

  route('post', '/logout', 'logout', {}, async (req, res) => {
    let familyId;
    try {
      const cred = req.headers.authorization && /^Bearer\s+\S/i.test(req.headers.authorization);
      if (cred) familyId = (await service.authenticate(req.headers.authorization.replace(/^Bearer\s+/i, '').trim())).claims.sid;
    } catch { /* an expired access token must not block logout */ }
    await service.logout({ refreshToken: mw.extractRefresh(req), familyId });
    if (useCookies) clearCookies(res);
    res.json({ ok: true });
  });

  route('post', '/logout-all', 'logoutAll', { auth: true }, async (req, res) => {
    await service.api.revokeSessions(req.auth.userId);
    if (useCookies) clearCookies(res);
    res.json({ ok: true });
  });

  route('get', '/me', 'me', { auth: true }, async (req, res) => {
    const user = cfg.session.loadUser ? req.user : await service.api.findUserById(req.auth.userId);
    res.json({ user });
  });

  route('patch', '/me', 'updateProfile', { auth: true }, async (req, res) => {
    const user = await service.updateProfile(req.auth.userId, body(req), meta(req));
    res.json({ user });
  });

  route('delete', '/me', 'deleteAccount', { auth: true }, async (req, res) => {
    await service.deleteAccount(req.auth.userId, body(req), meta(req));
    if (useCookies) clearCookies(res);
    res.json({ ok: true, message: 'Account deleted.' });
  });

  route('get', '/sessions', 'sessions', { auth: true }, async (req, res) =>
    res.json({ sessions: await service.listSessions(req.auth.userId, req.auth.sessionId) }));

  route('delete', '/sessions/:id', 'revokeSession', { auth: true }, async (req, res) => {
    await service.revokeSession(req.auth.userId, req.params.id);
    res.json({ ok: true });
  });

  route('post', '/change-password', 'changePassword', { auth: true }, async (req, res) => {
    await service.changePassword(req.auth.userId, body(req), req.auth.sessionId);
    res.json({ ok: true });
  });

  route('post', '/forgot-password', 'forgotPassword', {}, async (req, res) => {
    const email = normalizeEmail(body(req).email);
    if (email) await limit('forgotPassword', `email:${email}`); // stops mail-bombing one address
    await service.forgotPassword(body(req));
    res.json({ ok: true, message: 'If that email is registered, a reset link has been sent.' });
  });

  route('post', '/reset-password', 'resetPassword', {}, async (req, res) => {
    await service.resetPassword(body(req), meta(req));
    if (useCookies) clearCookies(res);
    res.json({ ok: true });
  });

  route('post', '/verify-email', 'verifyEmail', {}, async (req, res) => {
    await service.verifyEmail(body(req), meta(req));
    res.json({ ok: true });
  });

  route('post', '/resend-verification', 'resendVerification', {}, async (req, res) => {
    const email = normalizeEmail(body(req).email);
    if (email) await limit('resendVerification', `email:${email}`);
    await service.resendVerification(body(req));
    res.json({ ok: true, message: 'If that account needs verification, an email has been sent.' });
  });

  // ---- Google OAuth routes ----
  const google = cfg.providers.google;

  // GET /google — start the redirect flow
  route('get', '/google', 'google', {}, async (req, res) => {
    const state = require('node:crypto').randomBytes(16).toString('base64url');
    const nonce = require('node:crypto').randomBytes(16).toString('base64url');
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Optional ?redirectTo= (validated against trusted origins)
    const redirectTo = safeRedirectTo(req.query.redirectTo, cfg.security.trustedOrigins);

    // Store state, nonce, code_verifier in a signed cookie
    const cookiePayload = { state, nonce, cv: codeVerifier, exp: Date.now() + STATE_TTL_MS };
    if (redirectTo) cookiePayload.redirectTo = redirectTo;
    const signed = signStateCookie(cookiePayload, cfg.secrets[0]);
    res.append('Set-Cookie', serializeCookie(STATE_COOKIE_NAME, signed, {
      maxAgeMs: STATE_TTL_MS,
      path: cfg.basePath + '/google',
      secure: cookies.secure,
      sameSite: 'lax',
    }));

    // Build Google OAuth URL
    const params = new URLSearchParams({
      client_id: google.clientId,
      redirect_uri: google.redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      access_type: 'online',
      prompt: 'select_account',
    });
    res.redirect(302, `${GOOGLE_AUTH_URL}?${params}`);
  });

  // GET /google/callback — finish the redirect flow
  route('get', '/google/callback', 'googleCallback', {}, async (req, res) => {
    const errorUrl = google.errorRedirect;
    try {
      // Verify state cookie
      const rawCookie = parseCookies(req.headers.cookie)[STATE_COOKIE_NAME];
      const cookieData = verifyStateCookie(rawCookie, cfg.secrets[0]);
      if (!cookieData) throw E.forbidden('Invalid or expired Google login state.', 'google_invalid_state');

      // Constant-time state comparison
      const reqState = String(req.query.state || '');
      if (reqState.length !== cookieData.state.length ||
        !require('node:crypto').timingSafeEqual(Buffer.from(reqState), Buffer.from(cookieData.state)))
        throw E.forbidden('State mismatch.', 'google_invalid_state');

      // Check for error from Google
      if (req.query.error) throw E.forbidden('Google login was denied.', 'google_denied');

      // Exchange code for tokens
      const tokenRes = await google.fetch(GOOGLE_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code: String(req.query.code || ''),
          client_id: google.clientId,
          client_secret: google.clientSecret,
          redirect_uri: google.redirectUri,
          grant_type: 'authorization_code',
          code_verifier: cookieData.cv,
        }),
      });
      if (!tokenRes.ok) throw E.forbidden('Failed to exchange Google authorization code.', 'google_token_exchange_failed');
      const tokenData = await tokenRes.json();

      // Verify the ID token
      const profile = await verifyGoogleIdToken(tokenData.id_token, { google, expectedNonce: cookieData.nonce });

      // Clear the state cookie
      res.append('Set-Cookie', serializeCookie(STATE_COOKIE_NAME, '', { maxAgeMs: 0, path: cfg.basePath + '/google', secure: cookies.secure, sameSite: 'lax' }));

      // Login / create user via service
      const session = await service.loginWithProvider({ provider: 'google', ...profile }, meta(req));

      // Set session cookies and redirect
      setCookies(res, session);
      res.redirect(302, cookieData.redirectTo || google.successRedirect);
    } catch (e) {
      // Clear state cookie on any failure
      res.append('Set-Cookie', serializeCookie(STATE_COOKIE_NAME, '', { maxAgeMs: 0, path: cfg.basePath + '/google', secure: cookies.secure, sameSite: 'lax' }));
      log.error('[oneauth] Google callback error:', e);
      const code = (e && e.code) || 'google_error';
      res.redirect(302, `${errorUrl}${errorUrl.includes('?') ? '&' : '?'}error=${encodeURIComponent(code)}`);
    }
  });

  // POST /google/one-tap — verify Google Identity Services credential
  route('post', '/google/one-tap', 'googleOneTap', {}, async (req, res) => {
    const credential = body(req).credential;
    if (typeof credential !== 'string' || !credential)
      throw E.invalidInput('`credential` (Google ID token) is required.');

    const profile = await verifyGoogleIdToken(credential, { google, expectedNonce: null });
    const session = await service.loginWithProvider({ provider: 'google', ...profile }, meta(req));
    sendSession(res, session);
  });

  // ---- error boundary for everything above
  r.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const ae = toAuthError(err);
    if (ae) return sendError(res, ae);
    log.error('[oneauth] unexpected error:', err);
    res.status(500).json({ error: { code: 'internal_error', message: 'Something went wrong.' } });
  });

  outer.use(cfg.basePath, r);
  return outer;
}

module.exports = { createRouter };
