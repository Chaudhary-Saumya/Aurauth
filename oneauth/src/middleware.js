'use strict';
const { AuthError, E, toAuthError, sendError } = require('./errors');
const { parseCookies } = require('./utils');

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

function createMiddleware(cfg, service, ready) {
  const cookieNames = { access: `${cfg.session.cookies.prefix}_access`, refresh: `${cfg.session.cookies.prefix}_refresh` };

  const waitReady = () => ready.catch(() => { throw new AuthError(503, 'service_unavailable', 'Authentication service is not ready.'); });

  function extractAccess(req) {
    const h = req.headers.authorization;
    if (h && /^Bearer\s+\S/i.test(h)) return { token: h.replace(/^Bearer\s+/i, '').trim(), from: 'header' };
    const c = parseCookies(req.headers.cookie)[cookieNames.access];
    return c ? { token: c, from: 'cookie' } : null;
  }

  function extractRefresh(req) {
    const b = req.body && typeof req.body === 'object' ? req.body.refreshToken : undefined;
    if (typeof b === 'string' && b) return b;
    return parseCookies(req.headers.cookie)[cookieNames.refresh] || null;
  }

  /** CSRF defence for browsers: state-changing requests must come from our own origin or a trusted one. */
  function checkOrigin(req) {
    if (SAFE.has(req.method)) return;
    const origin = req.headers.origin;
    if (origin) {
      if (origin === `${req.protocol}://${req.get('host')}` || cfg.security.trustedOrigins.has(origin)) return;
      throw E.forbidden(`Origin "${origin}" is not allowed. Add it to \`security.trustedOrigins\`.`, 'origin_not_allowed');
    }
    if (req.headers['sec-fetch-site'] === 'cross-site') throw E.forbidden('Cross-site request blocked.', 'origin_not_allowed');
  }

  async function attach(req, claims, user) {
    const roles = user ? user.roles : Array.isArray(claims.roles) ? claims.roles : [];
    req.auth = { userId: claims.sub, sessionId: claims.sid, roles, claims };
    req.user = user ? await service.publicUser(user) : { id: claims.sub, roles };
  }

  function fail(res, next, err) {
    const ae = toAuthError(err);
    return ae ? sendError(res, ae) : next(err);
  }

  async function protect(req, res, next) {
    try {
      await waitReady();
      const cred = extractAccess(req);
      if (!cred) throw E.unauthorized();
      if (cred.from === 'cookie') checkOrigin(req);
      const { claims, user } = await service.authenticate(cred.token);
      await attach(req, claims, user);
    } catch (err) { return fail(res, next, err); }
    next();
  }

  async function optional(req, res, next) {
    try {
      await waitReady();
      const cred = extractAccess(req);
      if (cred && (cred.from !== 'cookie' || SAFE.has(req.method))) {
        const { claims, user } = await service.authenticate(cred.token);
        await attach(req, claims, user);
      }
    } catch (err) {
      if (!(toAuthError(err))) return next(err); // bad/expired token => treated as anonymous
    }
    next();
  }

  function requireRole(...wanted) {
    const roles = wanted.flat();
    if (!roles.length || roles.some((r) => typeof r !== 'string')) throw new Error('[oneauth] requireRole("admin", ...) needs at least one role name.');
    return (req, res, next) => protect(req, res, (err) => {
      if (err) return next(err);
      if (!roles.some((r) => req.auth.roles.includes(r))) return sendError(res, E.forbidden(`Requires one of these roles: ${roles.join(', ')}.`, 'insufficient_role'));
      next();
    });
  }

  function requireVerified(req, res, next) {
    protect(req, res, async (err) => {
      if (err) return next(err);
      try {
        let verified = req.user.emailVerified;
        if (verified === undefined) verified = (await service.api.findUserById(req.auth.userId) || {}).emailVerified;
        if (!verified) return sendError(res, E.forbidden('Please verify your email first.', 'email_not_verified'));
      } catch (e) { return fail(res, next, e); }
      next();
    });
  }

  return { protect, optional, requireRole, requireVerified, checkOrigin, cookieNames, extractRefresh, waitReady, fail };
}

module.exports = { createMiddleware };
