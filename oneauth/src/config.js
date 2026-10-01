'use strict';
const { ConfigError } = require('./errors');
const { resolveGoogleProvider } = require('./google');
const { duration, isPlainObject, checkKeys } = require('./utils');
const { scrypt, bcrypt: createBcryptHasher, argon2: createArgon2Hasher, assertHasher } = require('./hashers');
const { assertSigner, jsonwebtoken: createJwtSigner } = require('./tokens');
const { consoleMailer } = require('./mailers');
const { memoryLimiter } = require('./ratelimit');

const TOP = ['secret', 'database', 'appName', 'appUrl', 'frontendUrl', 'basePath', 'roles', 'fields', 'user', 'password', 'tokens', 'session',
  'emailVerification', 'passwordReset', 'email', 'registration', 'lockout', 'rateLimit', 'security', 'use', 'routeMiddleware',
  'routes', 'hooks', 'seedUsers', 'logger', 'providers'];
const ROUTES = ['register', 'login', 'refresh', 'logout', 'logoutAll', 'me', 'updateProfile', 'deleteAccount', 'forgotPassword', 'resetPassword', 'verifyEmail',
  'resendVerification', 'changePassword', 'sessions', 'revokeSession', 'google', 'googleCallback', 'googleOneTap'];
const HOOKS = ['beforeRegister', 'afterRegister', 'afterLogin', 'onLoginFailed', 'onRefreshReuse', 'afterPasswordReset', 'afterEmailVerified',
  'beforeProfileUpdate', 'beforeAccountDelete'];
const STORE_METHODS = {
  users: ['create', 'findById', 'findByEmail', 'update', 'delete', 'incrementFailedLogins'],
  sessions: ['create', 'findByTokenHash', 'consume', 'revokeFamily', 'revokeAllForUser', 'isFamilyActive', 'listActiveForUser'],
  tokens: ['create', 'consume', 'deleteForUser'],
  identities: ['create', 'find', 'listForUser', 'delete'],
};

const DEFAULT_RULES = {
  register: { max: 10, windowMs: 3600000 },
  login: { max: 30, windowMs: 900000 },
  refresh: { max: 120, windowMs: 900000 },
  forgotPassword: { max: 5, windowMs: 3600000 },
  resetPassword: { max: 10, windowMs: 3600000 },
  verifyEmail: { max: 20, windowMs: 3600000 },
  resendVerification: { max: 5, windowMs: 3600000 },
  changePassword: { max: 10, windowMs: 3600000 },
  updateProfile: { max: 20, windowMs: 900000 },
  deleteAccount: { max: 3, windowMs: 3600000 },
  google: { max: 20, windowMs: 900000 },
  googleCallback: { max: 20, windowMs: 900000 },
  googleOneTap: { max: 30, windowMs: 900000 },
};

function assertStore(store, { hasIdentities = false } = {}) {
  const required = { ...STORE_METHODS };
  if (!hasIdentities) delete required.identities;
  for (const [group, methods] of Object.entries(required)) {
    for (const m of methods)
      if (!store || !store[group] || typeof store[group][m] !== 'function')
        throw new ConfigError(`Custom store is missing \`${group}.${m}()\`. See README, "Custom store".`);
  }
  if (typeof store.connect !== 'function') throw new ConfigError('Custom store is missing `connect()`.');
  return store;
}

// ---- field type shorthand ----
const FIELD_TYPE_MAP = {
  string:  () => ({ type: String, trim: true }),
  number:  () => ({ type: Number }),
  boolean: () => ({ type: Boolean }),
  date:    () => ({ type: Date }),
  url:     () => ({ type: String, trim: true }),
  phone:   () => ({ type: String, trim: true }),
};
const FIELD_MODIFIERS = ['required', 'unique', 'lowercase'];

/** Expand "string required unique" or { type: "string", required: true } into a Mongoose-ready schema definition. */
function resolveField(key, raw) {
  // Native Mongoose definition (type is a JS constructor) → passthrough
  if (isPlainObject(raw) && ([String, Number, Boolean, Date].includes(raw.type) || Array.isArray(raw.type))) return raw;

  let typeName, opts = {};
  if (typeof raw === 'string') {
    const parts = raw.trim().split(/\s+/);
    typeName = parts[0];
    for (let i = 1; i < parts.length; i++) {
      const m = parts[i].toLowerCase();
      if (m === 'required') opts.required = true;
      else if (m === 'unique') opts.unique = true;
      else if (m === 'lowercase') opts.lowercase = true;
      else throw new ConfigError(`Unknown modifier "${parts[i]}" in \`fields.${key}\`. Allowed: ${FIELD_MODIFIERS.join(', ')}.`);
    }
  } else if (isPlainObject(raw) && typeof raw.type === 'string') {
    const { type, register, ...rest } = raw;
    typeName = type;
    opts = rest;
  } else {
    throw new ConfigError(`\`fields.${key}\`: use a string like "string required" or an object like { type: "string", required: true }.`);
  }

  const factory = FIELD_TYPE_MAP[typeName.toLowerCase()];
  if (!factory) throw new ConfigError(`Unknown type "${typeName}" for \`fields.${key}\`. Use: ${Object.keys(FIELD_TYPE_MAP).join(', ')}.`);
  return { ...factory(), ...opts };
}

/** Resolve "bcrypt", "bcrypt:14", "argon2", or "scrypt" into a hasher object. Auto-requires the npm package. */
function resolveHasherShorthand(name) {
  const parts = name.split(':');
  const id = parts[0].toLowerCase();
  if (id === 'bcrypt') {
    let lib; try { lib = require('bcrypt'); } catch {
      throw new ConfigError(`password: "${name}" requires the bcrypt package. Run \`npm i bcrypt\`.`);
    }
    return assertHasher(createBcryptHasher(lib, parts[1] ? { rounds: Number(parts[1]) } : {}));
  }
  if (id === 'argon2') {
    let lib; try { lib = require('argon2'); } catch {
      throw new ConfigError(`password: "${name}" requires the argon2 package. Run \`npm i argon2\`.`);
    }
    return assertHasher(createArgon2Hasher(lib));
  }
  if (id === 'scrypt') return assertHasher(scrypt());
  throw new ConfigError(`Unknown hasher "${name}". Use "bcrypt", "argon2", or "scrypt".`);
}

function resolveDatabase(db, isProd) {
  if (!db) throw new ConfigError('`database` is required: a MongoDB URL, { connection: mongoose.connection }, { store }, or "memory" (development only).');
  if (db === 'memory') {
    if (isProd) throw new ConfigError('`database: "memory"` loses all data on restart and is blocked when NODE_ENV=production.');
    return { kind: 'memory' };
  }
  if (typeof db === 'string') {
    if (!/^mongodb(\+srv)?:\/\//.test(db)) throw new ConfigError('`database` string must be a MongoDB URL starting with mongodb:// or mongodb+srv://');
    return { kind: 'mongo', url: db };
  }
  if (isPlainObject(db)) {
    checkKeys(db, ['url', 'connection', 'store', 'connectOptions', 'mongoose'], 'database');
    if (db.store) return { kind: 'custom', store: db.store };
    if (db.connection || db.url) return { kind: 'mongo', url: db.url, connection: db.connection, connectOptions: db.connectOptions, mongoose: db.mongoose };
  }
  throw new ConfigError('`database` is not understood. Use a MongoDB URL, { url }, { connection }, { store } or "memory".');
}

function resolveConfig(input) {
  if (!isPlainObject(input)) throw new ConfigError('defineAuth() needs a config object.');
  checkKeys(input, TOP, 'config');
  const isProd = process.env.NODE_ENV === 'production';
  const logger = input.logger || console;
  for (const m of ['info', 'warn', 'error']) if (typeof logger[m] !== 'function') throw new ConfigError('`logger` needs info(), warn() and error().');

  // ---- roles
  let roles = input.roles === undefined ? ['user', 'admin'] : input.roles;
  if (Array.isArray(roles)) roles = { list: roles, default: roles[0] };
  checkKeys(roles, ['list', 'default'], 'roles');
  if (!Array.isArray(roles.list) || !roles.list.length || roles.list.some((r) => typeof r !== 'string' || !r))
    throw new ConfigError('`roles` must be a non-empty list of strings, e.g. ["user", "admin"].');
  if (!roles.list.includes(roles.default)) throw new ConfigError(`\`roles.default\` ("${roles.default}") must be one of roles.list.`);

  // ---- user / fields
  if (input.fields && input.user) throw new ConfigError('Use top-level `fields` or `user: { fields }`, not both.');
  let fields, registerFields;
  if (input.fields) {
    // New shorthand: top-level `fields` with auto-derived registerFields
    if (!isPlainObject(input.fields)) throw new ConfigError('`fields` must be an object, e.g. { username: "string required unique" }.');
    fields = {}; registerFields = [];
    for (const [k, raw] of Object.entries(input.fields)) {
      fields[k] = resolveField(k, raw);
      if (!(isPlainObject(raw) && raw.register === false)) registerFields.push(k);
    }
  } else {
    // Classic syntax: user.fields + explicit registerFields
    const user = input.user || {};
    checkKeys(user, ['fields', 'registerFields'], 'user');
    const rawFields = user.fields || {};
    fields = {};
    for (const [k, raw] of Object.entries(rawFields)) fields[k] = resolveField(k, raw);
    registerFields = user.registerFields || [];
    for (const f of registerFields)
      if (!(f in fields)) throw new ConfigError(`\`user.registerFields\` lists "${f}" but it is not defined in \`user.fields\`.`);
  }

  // ---- password (supports "bcrypt", "argon2", "scrypt" shorthand or the full object form)
  let hasher, password;
  if (typeof input.password === 'string') {
    hasher = resolveHasherShorthand(input.password);
    password = { hasher, minLength: 10, maxLength: 128, validate: undefined };
  } else {
    const pw = input.password || {};
    checkKeys(pw, ['hasher', 'minLength', 'maxLength', 'validate'], 'password');
    hasher = typeof pw.hasher === 'string' ? resolveHasherShorthand(pw.hasher) : assertHasher(pw.hasher || scrypt());
    password = {
      hasher,
      minLength: pw.minLength === undefined ? 10 : pw.minLength,
      maxLength: Math.min(pw.maxLength === undefined ? 128 : pw.maxLength, 1024),
      validate: pw.validate,
    };
  }
  if (!Number.isInteger(password.minLength) || password.minLength < 8)
    throw new ConfigError('`password.minLength` must be an integer of at least 8.');
  if (password.validate && typeof password.validate !== 'function') throw new ConfigError('`password.validate` must be a function.');

  // ---- tokens (supports "jsonwebtoken" shorthand or the full object form)
  const tk = typeof input.tokens === 'string' ? { adapter: input.tokens } : (input.tokens || {});
  checkKeys(tk, ['accessTtl', 'refreshTtl', 'absoluteTtl', 'issuer', 'audience', 'adapter'], 'tokens');
  const secrets = [].concat(input.secret || []);
  let tokenAdapter = tk.adapter || null;
  if (typeof tokenAdapter === 'string') {
    if (tokenAdapter !== 'jsonwebtoken')
      throw new ConfigError(`Unknown token adapter "${tokenAdapter}". Use "jsonwebtoken" or omit for the built-in jose.`);
    if (!secrets.length)
      throw new ConfigError('`secret` is required when using jsonwebtoken. Generate one with:\n  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'base64url\'))"');
    for (const s of secrets) if (typeof s !== 'string' || s.length < 32)
      throw new ConfigError('`secret` must be a string of at least 32 characters (use a random value, never a word).');
    let jwtLib; try { jwtLib = require('jsonwebtoken'); } catch {
      throw new ConfigError('`tokens: "jsonwebtoken"` requires the jsonwebtoken package. Run `npm i jsonwebtoken`.');
    }
    tokenAdapter = assertSigner(createJwtSigner(jwtLib, { secret: secrets[0], issuer: tk.issuer || 'oneauth', audience: tk.audience }));
  } else if (tokenAdapter) {
    tokenAdapter = assertSigner(tokenAdapter);
  }
  if (!tokenAdapter) {
    if (!secrets.length)
      throw new ConfigError('`secret` is required. Generate one with:\n  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'base64url\'))"\nand store it in an environment variable (e.g. AUTH_SECRET).');
    for (const s of secrets)
      if (typeof s !== 'string' || s.length < 32)
        throw new ConfigError('`secret` must be a string of at least 32 characters (use a random value, never a word).');
  }
  const tokens = {
    accessTtl: duration(tk.accessTtl === undefined ? '10m' : tk.accessTtl, 'tokens.accessTtl'),
    refreshTtl: duration(tk.refreshTtl === undefined ? '7d' : tk.refreshTtl, 'tokens.refreshTtl'),
    absoluteTtl: duration(tk.absoluteTtl === undefined ? '30d' : tk.absoluteTtl, 'tokens.absoluteTtl'),
    issuer: tk.issuer || 'oneauth',
    audience: tk.audience,
    adapter: tokenAdapter,
  };
  if (tokens.accessTtl < 1000) throw new ConfigError('`tokens.accessTtl` must be at least 1 second.');

  // ---- session / cookies
  const se = input.session || {};
  checkKeys(se, ['transport', 'checkOnRequest', 'loadUser', 'refreshReuseGrace', 'cookies'], 'session');
  const transport = se.transport || 'cookie';
  if (!['cookie', 'bearer', 'both'].includes(transport)) throw new ConfigError('`session.transport` must be "cookie", "bearer" or "both".');
  const ck = se.cookies || {};
  checkKeys(ck, ['prefix', 'sameSite', 'secure', 'domain'], 'session.cookies');
  const cookies = {
    prefix: ck.prefix || 'oa',
    sameSite: String(ck.sameSite || 'lax').toLowerCase(),
    secure: ck.secure === undefined ? isProd : !!ck.secure,
    domain: ck.domain,
  };
  if (!['lax', 'strict', 'none'].includes(cookies.sameSite)) throw new ConfigError('`session.cookies.sameSite` must be "lax", "strict" or "none".');
  if (cookies.sameSite === 'none' && !cookies.secure) throw new ConfigError('`sameSite: "none"` requires `secure: true` (browsers reject it otherwise).');
  if (isProd && !cookies.secure && transport !== 'bearer') throw new ConfigError('Cookies must be `secure` in production. Serve over HTTPS and remove `session.cookies.secure: false`.');
  const session = {
    transport,
    checkOnRequest: se.checkOnRequest !== false,
    loadUser: se.loadUser !== false,
    refreshReuseGrace: duration(se.refreshReuseGrace === undefined ? '10s' : se.refreshReuseGrace, 'session.refreshReuseGrace'),
    cookies,
  };

  // ---- urls
  const appName = input.appName || 'Your App';
  const appUrl = String(input.appUrl || 'http://localhost:3000').replace(/\/+$/, '');
  const frontendUrl = String(input.frontendUrl || appUrl).replace(/\/+$/, '');
  const basePath = '/' + String(input.basePath === undefined ? '/auth' : input.basePath).replace(/^\/+|\/+$/g, '');

  // ---- email flows
  const ev = input.emailVerification || {};
  checkKeys(ev, ['enabled', 'required', 'ttl', 'url'], 'emailVerification');
  const pr = input.passwordReset || {};
  checkKeys(pr, ['enabled', 'ttl', 'url'], 'passwordReset');
  const emailVerification = {
    enabled: ev.enabled !== false,
    required: !!ev.required,
    ttl: duration(ev.ttl || '24h', 'emailVerification.ttl'),
    url: ev.url || ((t) => `${frontendUrl}/verify-email?token=${encodeURIComponent(t)}`),
  };
  const passwordReset = {
    enabled: pr.enabled !== false,
    ttl: duration(pr.ttl || '30m', 'passwordReset.ttl'),
    url: pr.url || ((t) => `${frontendUrl}/reset-password?token=${encodeURIComponent(t)}`),
  };
  if (emailVerification.required && !emailVerification.enabled)
    throw new ConfigError('`emailVerification.required` needs `emailVerification.enabled` to be true.');

  let mailer = null;
  let templates = {};
  const em = input.email;
  if (typeof em === 'function') mailer = { send: em };
  else if (em && typeof em.send === 'function') { mailer = em; templates = em.templates || {}; }
  else if (isPlainObject(em) && em.send === undefined && em.templates) templates = em.templates;
  else if (em !== undefined && em !== null) throw new ConfigError('`email` must be a function ({ to, subject, text, html, url, token, type }) => Promise, or an object with send().');
  if (!mailer && (emailVerification.enabled || passwordReset.enabled)) {
    if (isProd)
      throw new ConfigError('Email verification / password reset need a mailer in production. Set `email` (e.g. mailers.nodemailer(transporter, { from })), or disable both with `emailVerification: { enabled: false }, passwordReset: { enabled: false }`.');
    mailer = consoleMailer(logger);
  }

  // ---- registration / lockout
  const rg = input.registration || {};
  checkKeys(rg, ['enabled', 'autoLogin'], 'registration');
  const registration = { enabled: rg.enabled !== false, autoLogin: !!rg.autoLogin };
  if (registration.autoLogin && emailVerification.required)
    throw new ConfigError('`registration.autoLogin` cannot be combined with `emailVerification.required` (the user must verify before signing in).');
  const lo = input.lockout || {};
  checkKeys(lo, ['maxAttempts', 'duration'], 'lockout');
  const lockout = { maxAttempts: lo.maxAttempts === undefined ? 5 : lo.maxAttempts, duration: duration(lo.duration || '15m', 'lockout.duration') };

  // ---- rate limit
  let rateLimit = null;
  if (input.rateLimit !== false) {
    const rl = input.rateLimit || {};
    checkKeys(rl, ['limiter', 'rules'], 'rateLimit');
    const limiter = rl.limiter || memoryLimiter();
    if (typeof limiter.hit !== 'function') throw new ConfigError('`rateLimit.limiter` needs hit(key, { max, windowMs }) -> { allowed, retryAfterSec }.');
    rateLimit = { limiter, rules: { ...DEFAULT_RULES, ...(rl.rules || {}) } };
  }

  // ---- security
  const sec = input.security || {};
  checkKeys(sec, ['trustedOrigins'], 'security');
  const trustedOrigins = new Set((sec.trustedOrigins || []).map((o) => String(o).replace(/\/+$/, '')));
  for (const u of [frontendUrl, appUrl]) { try { trustedOrigins.add(new URL(u).origin); } catch { /* ignore */ } }

  // ---- extension points
  const use = input.use || [];
  if (!Array.isArray(use) || use.some((f) => typeof f !== 'function')) throw new ConfigError('`use` must be an array of Express middleware functions, e.g. use: [helmet(), cors()].');
  const routeMiddleware = input.routeMiddleware || {};
  checkKeys(routeMiddleware, ROUTES, 'routeMiddleware');
  for (const [k, v] of Object.entries(routeMiddleware))
    if (!Array.isArray(v) || v.some((f) => typeof f !== 'function')) throw new ConfigError(`\`routeMiddleware.${k}\` must be an array of middleware functions.`);
  const routes = { ...Object.fromEntries(ROUTES.map((r) => [r, true])) };
  const rt = input.routes || {};
  checkKeys(rt, ROUTES, 'routes');
  Object.assign(routes, rt);
  const hooks = input.hooks || {};
  checkKeys(hooks, HOOKS, 'hooks');
  for (const [k, v] of Object.entries(hooks)) if (typeof v !== 'function') throw new ConfigError(`\`hooks.${k}\` must be a function.`);

  const seedUsers = input.seedUsers || [];
  if (!Array.isArray(seedUsers)) throw new ConfigError('`seedUsers` must be an array of { email, password, roles }.');

  // ---- providers (Google OAuth, etc.)
  const rawProviders = input.providers || {};
  if (rawProviders && !isPlainObject(rawProviders)) throw new ConfigError('`providers` must be an object, e.g. `providers: { google: { clientId, clientSecret } }`.');
  checkKeys(rawProviders, ['google'], 'providers');
  const google = resolveGoogleProvider(rawProviders.google || null, { basePath, appUrl, frontendUrl, session, routes, isProd, logger });
  const providers = { google };

  return {
    secrets, database: resolveDatabase(input.database, isProd), appName, appUrl, frontendUrl, basePath,
    roles, user: { fields, registerFields }, password, tokens, session, emailVerification, passwordReset,
    mailer, templates, registration, lockout, rateLimit, security: { trustedOrigins },
    use, routeMiddleware, routes, hooks, seedUsers, logger, isProd, providers,
  };
}

module.exports = { resolveConfig, ROUTES };
