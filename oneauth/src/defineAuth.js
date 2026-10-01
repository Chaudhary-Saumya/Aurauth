'use strict';
const { resolveConfig } = require('./config');
const { jose } = require('./tokens');
const { createService } = require('./service');
const { createMiddleware } = require('./middleware');
const { createRouter } = require('./router');
const { createMemoryStore } = require('./stores/memory');
const { createMongoStore } = require('./stores/mongo');
const { ConfigError } = require('./errors');

function createStore(cfg) {
  const db = cfg.database;
  if (db.kind === 'memory') return createMemoryStore();
  if (db.kind === 'custom') return db.store;
  return createMongoStore({ ...db, userFields: cfg.user.fields });
}

/**
 * defineAuth(config) -> an Express router (app.use(auth)) that also carries
 * auth.protect, auth.optional, auth.requireRole(...), auth.requireVerified, auth.api, auth.ready, auth.close().
 */
function defineAuth(input) {
  const cfg = resolveConfig(input);
  const log = cfg.logger;
  const store = createStore(cfg);
  const signer = cfg.tokens.adapter || jose({ secret: cfg.secrets, issuer: cfg.tokens.issuer, audience: cfg.tokens.audience });
  const service = createService(cfg, { store, signer, log });

  const ready = (async () => {
    await store.connect();
    for (const seed of cfg.seedUsers) {
      if (!seed || !seed.email || !seed.password) throw new ConfigError('Each `seedUsers` entry needs { email, password }. Read the password from an environment variable.');
      if (!(await service.api.findUserByEmail(seed.email)))
        await service.api.createUser({ emailVerified: true, ...seed });
    }
  })();
  ready.catch((e) => log.error('[oneauth] startup failed:', e));

  const mw = createMiddleware(cfg, service, ready);
  const router = createRouter(cfg, service, mw, log);

  return Object.assign(router, {
    protect: mw.protect,
    optional: mw.optional,
    requireRole: mw.requireRole,
    requireVerified: mw.requireVerified,
    api: service.api,
    ready,
    async close() {
      await ready.catch(() => {});
      if (cfg.rateLimit && typeof cfg.rateLimit.limiter.close === 'function') cfg.rateLimit.limiter.close();
      await store.close();
    },
  });
}

module.exports = { defineAuth };
