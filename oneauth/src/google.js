'use strict';
const crypto = require('node:crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const { ConfigError, E } = require('./errors');
const { randomToken, sha256, serializeCookie, parseCookies, isPlainObject, checkKeys } = require('./utils');

// ---- constants ----
const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

const ALLOWED_GOOGLE_KEYS = [
  'clientId', 'clientSecret', 'redirectUri', 'successRedirect', 'errorRedirect',
  'linkExistingAccounts', 'allowedDomains', 'fetch', 'jwks',
];

// ---- config validation ----
function resolveGoogleProvider(google, { basePath, appUrl, frontendUrl, session, routes, isProd, logger }) {
  if (!google) return null;
  if (!isPlainObject(google)) throw new ConfigError('`providers.google` must be an object.');
  checkKeys(google, ALLOWED_GOOGLE_KEYS, 'providers.google');

  const clientId = google.clientId;
  if (!clientId || typeof clientId !== 'string')
    throw new ConfigError('`providers.google.clientId` is required. Get it from the Google Cloud Console → APIs & Services → Credentials → OAuth 2.0 Client IDs.');

  const needsSecret = routes.googleCallback !== false;
  const clientSecret = google.clientSecret;
  if (needsSecret && (!clientSecret || typeof clientSecret !== 'string'))
    throw new ConfigError('`providers.google.clientSecret` is required for the redirect flow (GET /google/callback). If you only use the one-tap/POST flow, set `routes: { google: false, googleCallback: false }` and omit clientSecret.');

  const redirectUri = google.redirectUri || `${appUrl}${basePath}/google/callback`;
  if (isProd) {
    try {
      const u = new URL(redirectUri);
      if (u.protocol !== 'https:' && u.hostname !== 'localhost' && u.hostname !== '127.0.0.1')
        throw new ConfigError('`providers.google.redirectUri` must use HTTPS in production (HTTP is only allowed for localhost).');
    } catch (e) {
      if (e instanceof ConfigError) throw e;
      throw new ConfigError(`\`providers.google.redirectUri\` is not a valid URL: ${redirectUri}`);
    }
  }

  // warn if redirectUri path does not match basePath
  try {
    const u = new URL(redirectUri);
    if (!u.pathname.startsWith(basePath + '/google/callback'))
      logger.warn(`[oneauth] providers.google.redirectUri path "${u.pathname}" does not match basePath "${basePath}/google/callback". Requests may not reach the callback handler.`);
  } catch { /* ignore parse errors in dev */ }

  // redirect flow requires cookie transport
  if (needsSecret && session.transport === 'bearer')
    throw new ConfigError('The Google redirect flow (GET /google, GET /google/callback) requires cookie-based sessions (session.transport "cookie" or "both"). With session.transport "bearer", only the one-tap/POST flow is available. Either change session.transport, or disable the redirect routes: `routes: { google: false, googleCallback: false }`.');

  const successRedirect = google.successRedirect || frontendUrl || '/';
  const errorRedirect = google.errorRedirect || `${frontendUrl || ''}/login`;
  const linkExistingAccounts = google.linkExistingAccounts !== false;
  const allowedDomains = Array.isArray(google.allowedDomains) ? google.allowedDomains.map((d) => String(d).toLowerCase()) : [];

  // injectable for testing
  const fetchFn = google.fetch || globalThis.fetch;
  const jwks = google.jwks || createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));

  return { clientId, clientSecret, redirectUri, successRedirect, errorRedirect, linkExistingAccounts, allowedDomains, fetch: fetchFn, jwks };
}

// ---- PKCE helpers ----
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// ---- state cookie (HMAC-signed JSON) ----
const STATE_COOKIE_NAME = '__oa_google_state';
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function signStateCookie(payload, secret) {
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

function verifyStateCookie(raw, secret) {
  if (typeof raw !== 'string') return null;
  const dot = raw.lastIndexOf('.');
  if (dot < 1) return null;
  const b64 = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = crypto.createHmac('sha256', secret).update(b64).digest('base64url');
  // constant-time compare
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
    if (!payload || typeof payload !== 'object') return null;
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ---- Google ID token verification ----
async function verifyGoogleIdToken(idToken, { google, expectedNonce }) {
  const { payload } = await jwtVerify(idToken, google.jwks, {
    algorithms: ['RS256'],
    audience: google.clientId,
    clockTolerance: 30,
  });

  // iss check
  if (!GOOGLE_ISSUERS.includes(payload.iss))
    throw E.forbidden('Invalid Google ID token issuer.', 'google_invalid_token');

  // email_verified
  if (payload.email_verified !== true)
    throw E.forbidden('Google account email is not verified. Only verified Google emails are accepted.', 'google_email_not_verified');

  // nonce (redirect flow)
  if (expectedNonce) {
    if (!payload.nonce || !crypto.timingSafeEqual(Buffer.from(payload.nonce), Buffer.from(expectedNonce)))
      throw E.forbidden('Invalid Google ID token nonce.', 'google_invalid_token');
  }

  // allowed domains
  if (google.allowedDomains.length > 0) {
    const hd = String(payload.hd || '').toLowerCase();
    if (!google.allowedDomains.includes(hd))
      throw E.forbidden('This Google Workspace domain is not allowed.', 'google_domain_not_allowed');
  }

  return {
    sub: payload.sub,               // stable Google account ID
    email: String(payload.email).toLowerCase(),
    name: payload.name || null,
    picture: payload.picture || null,
  };
}

// ---- redirect flow: validate redirectTo ----
function safeRedirectTo(redirectTo, trustedOrigins) {
  if (!redirectTo || typeof redirectTo !== 'string') return null;
  // Only allow absolute URLs to trusted origins, or relative paths starting with /
  if (redirectTo.startsWith('/') && !redirectTo.startsWith('//')) return redirectTo;
  try {
    const u = new URL(redirectTo);
    if (trustedOrigins.has(u.origin)) return redirectTo;
  } catch { /* not a valid URL */ }
  return null; // silently ignore unsafe redirectTo
}

module.exports = {
  resolveGoogleProvider,
  generateCodeVerifier, generateCodeChallenge,
  STATE_COOKIE_NAME, STATE_TTL_MS,
  signStateCookie, verifyStateCookie,
  verifyGoogleIdToken,
  safeRedirectTo,
  GOOGLE_AUTH_URL, GOOGLE_TOKEN_URL,
};
