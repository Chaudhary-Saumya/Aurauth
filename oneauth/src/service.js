'use strict';
const { E } = require('./errors');
const { randomToken, sha256, normalizeEmail } = require('./utils');
const { defaultTemplates } = require('./mailers');

const time = (d) => (d instanceof Date ? d.getTime() : d ? new Date(d).getTime() : 0);

function createService(cfg, { store, signer, log }) {
  const hasher = cfg.password.hasher;
  const now = () => Date.now();
  const extraKeys = Object.keys(cfg.user.fields);
  let dummyHash;
  const getDummy = async () => (dummyHash = dummyHash || (await hasher.hash('oneauth-timing-equalizer-password')));

  // ---------------------------------------------------------------- helpers
  async function publicUser(u) {
    if (!u) return null;
    const out = { id: u.id, email: u.email, roles: [...(u.roles || [])], emailVerified: !!u.emailVerified, createdAt: u.createdAt };
    for (const k of extraKeys) if (u[k] !== undefined) out[k] = u[k];
    // attach linked provider names
    try {
      const ids = await store.identities.listForUser(u.id);
      if (ids.length) out.providers = ids.map((i) => i.provider);
    } catch { /* identities store may not be ready yet during startup */ }
    return out;
  }

  async function hook(name, ctx, { swallow = true } = {}) {
    const fn = cfg.hooks[name];
    if (!fn) return;
    if (!swallow) return fn(ctx);
    try { await fn(ctx); } catch (e) { log.error(`[oneauth] hook "${name}" threw:`, e); }
  }

  async function validatePassword(pw, email) {
    if (typeof pw !== 'string' || !pw) throw E.invalidInput('Password is required.');
    const { minLength, maxLength } = cfg.password;
    if (pw.length < minLength) throw E.invalidInput(`Password must be at least ${minLength} characters.`);
    if (pw.length > maxLength) throw E.invalidInput(`Password must be at most ${maxLength} characters.`);
    if (hasher.maxBytes && Buffer.byteLength(pw) > hasher.maxBytes)
      throw E.invalidInput(`Password must be at most ${hasher.maxBytes} bytes (${hasher.name} limit).`);
    if (email && (pw.toLowerCase() === email || pw.toLowerCase() === email.split('@')[0]))
      throw E.invalidInput('Password must not be your email.');
    if (cfg.password.validate) {
      const r = await cfg.password.validate(pw, { email });
      if (r === false) throw E.invalidInput('This password is not allowed.');
      if (typeof r === 'string') throw E.invalidInput(r);
    }
  }

  function pickFields(input) {
    const out = {};
    for (const key of cfg.user.registerFields) {
      const v = input[key];
      if (v === undefined) continue;
      const okPrimitive = (x) => x === null || ['string', 'number', 'boolean'].includes(typeof x);
      const ok = okPrimitive(v) || (Array.isArray(v) && v.length <= 50 && v.every(okPrimitive));
      if (!ok || (typeof v === 'string' && v.length > 2000)) throw E.invalidInput(`Field "${key}" has an invalid value.`);
      out[key] = typeof v === 'string' ? v.trim() : v;
    }
    return out;
  }

  function checkRoles(list) {
    if (!Array.isArray(list) || !list.length || list.some((r) => !cfg.roles.list.includes(r)))
      throw E.invalidInput(`Roles must be a non-empty subset of: ${cfg.roles.list.join(', ')}.`);
    return [...new Set(list)];
  }

  async function issueSession(user, meta, prev) {
    const familyId = prev ? prev.familyId : randomToken(16);
    const startedAt = prev ? time(prev.startedAt) : now();
    const expiresAt = Math.min(now() + cfg.tokens.refreshTtl, startedAt + cfg.tokens.absoluteTtl);
    const refreshToken = randomToken(32);
    await store.sessions.create({
      userId: user.id, familyId, tokenHash: sha256(refreshToken),
      startedAt: new Date(startedAt), expiresAt: new Date(expiresAt),
      ip: meta.ip, userAgent: meta.userAgent ? String(meta.userAgent).slice(0, 300) : undefined,
    });
    const expiresIn = Math.floor(cfg.tokens.accessTtl / 1000);
    const accessToken = await signer.sign({ sub: user.id, sid: familyId, roles: user.roles }, { expiresInSeconds: expiresIn });
    return { user: await publicUser(user), accessToken, refreshToken, expiresIn, refreshMaxAgeMs: expiresAt - now(), familyId };
  }

  async function issueOneTimeToken(user, type, ttl) {
    await store.tokens.deleteForUser(user.id, type);
    const raw = randomToken(32);
    await store.tokens.create({ userId: user.id, type, hash: sha256(raw), expiresAt: new Date(now() + ttl) });
    return raw;
  }

  async function sendMail(kind, user, token) {
    const section = kind === 'verify' ? cfg.emailVerification : cfg.passwordReset;
    const url = section.url(token);
    const tpl = (cfg.templates[kind] || defaultTemplates[kind])({ user: await publicUser(user), url, token, appName: cfg.appName });
    // Fire and forget: response time must not reveal whether an account exists.
    Promise.resolve(cfg.mailer.send({ to: user.email, type: kind, url, token, ...tpl }))
      .catch((e) => log.error(`[oneauth] failed to send "${kind}" email:`, e));
  }

  async function revokeEverywhere(userId, exceptFamilyId) {
    await store.sessions.revokeAllForUser(userId, { exceptFamilyId });
  }

  // ---------------------------------------------------------------- flows
  async function register(input, meta) {
    const email = normalizeEmail(input.email);
    if (!email) throw E.invalidInput('A valid email is required.');
    await validatePassword(input.password, email);
    const fields = pickFields(input);
    await hook('beforeRegister', { email, fields, req: meta.req }, { swallow: false });

    const passwordHash = await hasher.hash(input.password);
    let user;
    try {
      user = await store.users.create({
        ...fields, email, passwordHash, roles: [cfg.roles.default], emailVerified: false,
        failedLogins: 0, lockUntil: null, disabled: false, passwordChangedAt: new Date(),
      });
    } catch (e) {
      if (e && e.code === 'DUPLICATE_EMAIL') {
        if (cfg.registration.autoLogin) throw E.emailTaken();
        return { accepted: true }; // identical response: does not reveal that the email exists
      }
      throw e;
    }
    if (cfg.emailVerification.enabled) sendMail('verify', user, await issueOneTimeToken(user, 'verify', cfg.emailVerification.ttl));
    await hook('afterRegister', { user: await publicUser(user), req: meta.req });
    if (cfg.registration.autoLogin) return { accepted: true, session: await issueSession(user, meta) };
    return { accepted: true };
  }

  async function login(input, meta) {
    const email = normalizeEmail(input.email);
    const pw = input.password;
    if (!email || typeof pw !== 'string' || !pw || pw.length > 1024) throw E.invalidCredentials();

    const user = await store.users.findByEmail(email);
    if (!user) {
      await hasher.verify(pw, await getDummy()); // same work as a real login: no timing signal
      await hook('onLoginFailed', { email, req: meta.req });
      throw E.invalidCredentials();
    }
    if (time(user.lockUntil) > now())
      throw E.tooMany(Math.ceil((time(user.lockUntil) - now()) / 1000), 'account_locked');

    if (!(await hasher.verify(pw, user.passwordHash || ''))) {
      if (!user.passwordHash) {
        // social-only user: still do the timing-equalised work, then fail generically
        await hasher.verify(pw, await getDummy());
        await hook('onLoginFailed', { email, req: meta.req });
        throw E.invalidCredentials();
      }
      const n = await store.users.incrementFailedLogins(user.id);
      if (n >= cfg.lockout.maxAttempts)
        await store.users.update(user.id, { lockUntil: new Date(now() + cfg.lockout.duration), failedLogins: 0 });
      await hook('onLoginFailed', { email, req: meta.req });
      throw E.invalidCredentials();
    }
    if (user.disabled) throw E.forbidden('This account is disabled.', 'account_disabled');
    if (cfg.emailVerification.required && !user.emailVerified)
      throw E.forbidden('Please verify your email before signing in.', 'email_not_verified');

    const patch = {};
    if (user.failedLogins || user.lockUntil) { patch.failedLogins = 0; patch.lockUntil = null; }
    try {
      if (hasher.needsRehash && (await hasher.needsRehash(user.passwordHash))) patch.passwordHash = await hasher.hash(pw);
    } catch (e) { log.warn('[oneauth] rehash skipped:', e.message); }
    const fresh = Object.keys(patch).length ? await store.users.update(user.id, patch) : user;

    const session = await issueSession(fresh, meta);
    await hook('afterLogin', { user: session.user, req: meta.req });
    return session;
  }

  // ---------------------------------------------------------------- social / provider login
  async function loginWithProvider({ provider, providerId, email, name, picture }, meta) {
    // 1. Look up by (provider, providerId)
    const identity = await store.identities.find(provider, providerId);
    if (identity) {
      const user = await store.users.findById(identity.userId);
      if (!user) throw E.unauthorized('Account not found.', 'account_not_found');
      if (user.disabled) throw E.forbidden('This account is disabled.', 'account_disabled');
      const session = await issueSession(user, meta);
      await hook('afterLogin', { user: session.user, provider, req: meta.req });
      return session;
    }

    // 2. Look up by email
    const existing = await store.users.findByEmail(email);
    if (existing) {
      const googleCfg = cfg.providers && cfg.providers.google;
      const linkExisting = googleCfg ? googleCfg.linkExistingAccounts : true;
      if (!linkExisting)
        throw E.forbidden('An account with this email already exists. Social login linking is disabled.', 'account_exists_no_link');

      // If the local account was NOT email-verified, it could be a pre-registration attack.
      // Wipe its password, revoke sessions, and set it verified before linking.
      if (!existing.emailVerified) {
        await store.users.update(existing.id, { passwordHash: null, emailVerified: true });
        await revokeEverywhere(existing.id);
      }

      if (existing.disabled) throw E.forbidden('This account is disabled.', 'account_disabled');

      // Link identity to existing user
      await store.identities.create({ userId: existing.id, provider, providerId, email });
      const fresh = await store.users.findById(existing.id);
      const session = await issueSession(fresh, meta);
      await hook('afterLogin', { user: session.user, provider, req: meta.req });
      return session;
    }

    // 3. Create a new user (social-only: no password)
    let user;
    try {
      user = await store.users.create({
        email, passwordHash: null, roles: [cfg.roles.default], emailVerified: true,
        failedLogins: 0, lockUntil: null, disabled: false, passwordChangedAt: null,
      });
    } catch (e) {
      if (e && e.code === 'DUPLICATE_EMAIL') {
        // Race: another request just created the user between our findByEmail and create.
        // Look them up and link.
        const raced = await store.users.findByEmail(email);
        if (raced) {
          await store.identities.create({ userId: raced.id, provider, providerId, email });
          const session = await issueSession(raced, meta);
          await hook('afterLogin', { user: session.user, provider, req: meta.req });
          return session;
        }
      }
      throw e;
    }

    await store.identities.create({ userId: user.id, provider, providerId, email });
    await hook('afterRegister', { user: await publicUser(user), provider, req: meta.req });
    const session = await issueSession(user, meta);
    await hook('afterLogin', { user: session.user, provider, req: meta.req });
    return session;
  }

  async function refresh(raw, meta) {
    if (typeof raw !== 'string' || !raw || raw.length > 200) throw E.unauthorized('Refresh token required.', 'invalid_refresh_token');
    const row = await store.sessions.findByTokenHash(sha256(raw));
    if (!row || row.revokedAt) throw E.unauthorized('Invalid refresh token.', 'invalid_refresh_token');
    if (time(row.expiresAt) <= now()) throw E.unauthorized('Session expired. Please sign in again.', 'session_expired');

    if (row.usedAt) {
      // A rotated token was presented again. Within the grace window it is a harmless race (two tabs);
      // otherwise it is treated as theft and the whole session family is revoked.
      if (now() - time(row.usedAt) <= cfg.session.refreshReuseGrace)
        throw E.unauthorized('Refresh already in progress. Retry with the newest token.', 'refresh_in_progress');
      await store.sessions.revokeFamily(row.familyId);
      await hook('onRefreshReuse', { userId: row.userId, req: meta.req });
      throw E.unauthorized('Refresh token reuse detected. Please sign in again.', 'refresh_reuse_detected');
    }
    const user = await store.users.findById(row.userId);
    if (!user || user.disabled) {
      await store.sessions.revokeFamily(row.familyId);
      throw E.unauthorized('Invalid refresh token.', 'invalid_refresh_token');
    }
    if (!(await store.sessions.consume(row.id))) throw E.unauthorized('Refresh already in progress. Retry with the newest token.', 'refresh_in_progress');
    return issueSession(user, meta, { familyId: row.familyId, startedAt: row.startedAt });
  }

  async function logout({ refreshToken, familyId }) {
    let fid = familyId;
    if (!fid && typeof refreshToken === 'string' && refreshToken.length <= 200) {
      const row = await store.sessions.findByTokenHash(sha256(refreshToken));
      if (row) fid = row.familyId;
    }
    if (fid) await store.sessions.revokeFamily(fid);
  }

  async function forgotPassword(input) {
    const email = normalizeEmail(input.email);
    if (!email) return; // same silent success for anything we cannot act on
    const user = await store.users.findByEmail(email);
    if (!user || user.disabled) return;
    sendMail('reset', user, await issueOneTimeToken(user, 'reset', cfg.passwordReset.ttl));
  }

  async function resetPassword(input, meta) {
    const { token, password } = input;
    if (typeof token !== 'string' || !token || token.length > 200) throw E.invalidToken();
    await validatePassword(password, null);
    const row = await store.tokens.consume('reset', sha256(token));
    if (!row) throw E.invalidToken();
    const user = await store.users.findById(row.userId);
    if (!user) throw E.invalidToken();
    if (String(user.email).toLowerCase() === password.toLowerCase()) throw E.invalidInput('Password must not be your email.');
    const updated = await store.users.update(user.id, {
      passwordHash: await hasher.hash(password), passwordChangedAt: new Date(),
      failedLogins: 0, lockUntil: null, emailVerified: true, // clicking the emailed link proves ownership
    });
    await revokeEverywhere(user.id);
    await hook('afterPasswordReset', { user: await publicUser(updated), req: meta.req });
  }

  async function verifyEmail(input, meta) {
    const { token } = input;
    if (typeof token !== 'string' || !token || token.length > 200) throw E.invalidToken();
    const row = await store.tokens.consume('verify', sha256(token));
    if (!row) throw E.invalidToken();
    const user = await store.users.update(row.userId, { emailVerified: true });
    if (!user) throw E.invalidToken();
    await hook('afterEmailVerified', { user: await publicUser(user), req: meta.req });
  }

  async function resendVerification(input) {
    const email = normalizeEmail(input.email);
    if (!email) return;
    const user = await store.users.findByEmail(email);
    if (!user || user.emailVerified || user.disabled) return;
    sendMail('verify', user, await issueOneTimeToken(user, 'verify', cfg.emailVerification.ttl));
  }

  async function changePassword(userId, input, familyId) {
    const { currentPassword, newPassword } = input;
    const user = await store.users.findById(userId);
    if (!user) throw E.unauthorized();
    if (typeof currentPassword !== 'string' || !(await hasher.verify(currentPassword, user.passwordHash || '')))
      throw E.forbidden('Current password is incorrect.', 'wrong_password');
    await validatePassword(newPassword, user.email);
    if (newPassword === currentPassword) throw E.invalidInput('New password must be different from the current one.');
    await store.users.update(user.id, { passwordHash: await hasher.hash(newPassword), passwordChangedAt: new Date() });
    await revokeEverywhere(user.id, familyId); // sign out every other device, keep this one
  }

  async function authenticate(token) {
    let claims;
    try {
      claims = await signer.verify(token);
    } catch (e) {
      const expired = e && (e.code === 'ERR_JWT_EXPIRED' || e.name === 'TokenExpiredError');
      throw E.unauthorized(expired ? 'Access token expired.' : 'Invalid access token.', expired ? 'token_expired' : 'invalid_token');
    }
    if (!claims || typeof claims.sub !== 'string') throw E.unauthorized('Invalid access token.', 'invalid_token');
    if (cfg.session.checkOnRequest && !(await store.sessions.isFamilyActive(claims.sid)))
      throw E.unauthorized('This session has ended. Please sign in again.', 'session_ended');
    let user = null;
    if (cfg.session.loadUser) {
      user = await store.users.findById(claims.sub);
      if (!user || user.disabled) throw E.unauthorized('Account not available.', 'invalid_token');
    }
    return { claims, user };
  }

  async function listSessions(userId, currentFamilyId) {
    const rows = await store.sessions.listActiveForUser(userId);
    return rows.map((r) => ({ id: r.familyId, ip: r.ip, userAgent: r.userAgent, startedAt: r.startedAt, expiresAt: r.expiresAt, current: r.familyId === currentFamilyId }));
  }

  async function revokeSession(userId, familyId) {
    const rows = await store.sessions.listActiveForUser(userId);
    if (typeof familyId !== 'string' || !rows.some((r) => r.familyId === familyId)) throw E.notFound('Session not found.');
    await store.sessions.revokeFamily(familyId);
  }

  async function updateProfile(userId, input, meta) {
    const user = await store.users.findById(userId);
    if (!user) throw E.unauthorized();
    const fields = pickFields(input);
    if (!Object.keys(fields).length) throw E.invalidInput('No updatable fields provided.');
    await hook('beforeProfileUpdate', { user: await publicUser(user), fields, req: meta.req }, { swallow: false });
    try {
      const updated = await store.users.update(userId, fields);
      return publicUser(updated);
    } catch (e) {
      if (e && (e.code === 11000 || e.code === 'DUPLICATE_FIELD'))
        throw E.invalidInput('A unique field value is already taken.');
      throw e;
    }
  }

  async function deleteAccount(userId, input, meta) {
    const user = await store.users.findById(userId);
    if (!user) throw E.unauthorized();
    if (typeof input.password !== 'string' || !(await hasher.verify(input.password, user.passwordHash || '')))
      throw E.forbidden('Password is incorrect.', 'wrong_password');
    await hook('beforeAccountDelete', { user: await publicUser(user), req: meta.req }, { swallow: false });
    await revokeEverywhere(userId);
    await store.tokens.deleteForUser(userId, 'verify');
    await store.tokens.deleteForUser(userId, 'reset');
    await store.users.delete(userId);
  }

  // ---------------------------------------------------------------- programmatic API (auth.api)
  const api = {
    async createUser({ email, password, roles, emailVerified = false, ...fields }) {
      const e = normalizeEmail(email);
      if (!e) throw E.invalidInput('A valid email is required.');
      await validatePassword(password, e);
      const extra = {};
      for (const k of extraKeys) if (fields[k] !== undefined) extra[k] = fields[k];
      try {
        const u = await store.users.create({
          ...extra, email: e, passwordHash: await hasher.hash(password), roles: roles ? checkRoles(roles) : [cfg.roles.default],
          emailVerified: !!emailVerified, failedLogins: 0, lockUntil: null, disabled: false, passwordChangedAt: new Date(),
        });
        return publicUser(u);
      } catch (err) {
        if (err && err.code === 'DUPLICATE_EMAIL') throw E.emailTaken();
        throw err;
      }
    },
    async findUserByEmail(email) { const e = normalizeEmail(email); return e ? publicUser(await store.users.findByEmail(e)) : null; },
    async findUserById(id) { return publicUser(await store.users.findById(id)); },
    async setRoles(userId, roles) { return publicUser(await store.users.update(userId, { roles: checkRoles(roles) })); },
    async setDisabled(userId, disabled) {
      const u = await store.users.update(userId, { disabled: !!disabled });
      if (disabled) await revokeEverywhere(userId);
      return publicUser(u);
    },
    async revokeSessions(userId) { await revokeEverywhere(userId); },
    async deleteUser(userId) {
      const user = await store.users.findById(userId);
      if (!user) return;
      await revokeEverywhere(userId);
      await store.tokens.deleteForUser(userId, 'verify');
      await store.tokens.deleteForUser(userId, 'reset');
      await store.users.delete(userId);
    },
    async listIdentities(userId) {
      return store.identities.listForUser(userId);
    },
    async unlinkIdentity(userId, provider) {
      const user = await store.users.findById(userId);
      if (!user) throw E.notFound('User not found.');
      const identities = await store.identities.listForUser(userId);
      const target = identities.find((i) => i.provider === provider);
      if (!target) throw E.notFound('Identity not found.');
      // refuse to unlink the last login method if the user has no password
      if (!user.passwordHash && identities.length <= 1)
        throw E.forbidden('Cannot unlink the only login method. Set a password first.', 'last_login_method');
      await store.identities.delete(provider, target.providerId);
    },
  };

  return {
    publicUser, register, login, refresh, logout, forgotPassword, resetPassword, verifyEmail, resendVerification,
    changePassword, updateProfile, deleteAccount, authenticate, listSessions, revokeSession, loginWithProvider, api,
  };
}

module.exports = { createService };
