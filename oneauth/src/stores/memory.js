'use strict';
const crypto = require('node:crypto');

const dup = () => Object.assign(new Error('Duplicate email'), { code: 'DUPLICATE_EMAIL' });
const clone = (o) => (o ? { ...o, roles: o.roles ? [...o.roles] : o.roles } : null);
const ms = (d) => (d ? new Date(d).getTime() : 0);

/**
 * In-memory store: for development and tests only (data is lost on restart).
 * It also documents the store contract that any custom store must satisfy.
 */
function createMemoryStore() {
  const users = new Map();
  const byEmail = new Map();
  const sessions = new Map();
  const byHash = new Map();
  const tokens = new Map();

  function sweep() {
    const t = Date.now();
    for (const [id, s] of sessions) if (ms(s.expiresAt) <= t) { sessions.delete(id); byHash.delete(s.tokenHash); }
    for (const [h, k] of tokens) if (ms(k.expiresAt) <= t) tokens.delete(h);
  }

  return {
    kind: 'memory',
    async connect() {},
    async close() {},

    users: {
      async create(data) {
        if (byEmail.has(data.email)) throw dup();
        const id = crypto.randomUUID();
        const u = { failedLogins: 0, lockUntil: null, disabled: false, emailVerified: false, createdAt: new Date(), ...data, id };
        users.set(id, u);
        byEmail.set(u.email, id);
        return clone(u);
      },
      async findById(id) { return clone(users.get(String(id))); },
      async findByEmail(email) { const id = byEmail.get(email); return id ? clone(users.get(id)) : null; },
      async update(id, patch) {
        const u = users.get(String(id));
        if (!u) return null;
        Object.assign(u, patch);
        return clone(u);
      },
      async incrementFailedLogins(id) {
        const u = users.get(String(id));
        if (!u) return 0;
        u.failedLogins = (u.failedLogins || 0) + 1;
        return u.failedLogins;
      },
      async delete(id) {
        const u = users.get(String(id));
        if (u) { byEmail.delete(u.email); users.delete(String(id)); }
      },
    },

    sessions: {
      async create(s) {
        if (sessions.size % 500 === 499) sweep();
        const id = crypto.randomUUID();
        sessions.set(id, { usedAt: null, revokedAt: null, createdAt: new Date(), ...s, id });
        byHash.set(s.tokenHash, id);
      },
      async findByTokenHash(hash) { const id = byHash.get(hash); return id ? { ...sessions.get(id) } : null; },
      /** Atomically mark a refresh token as used. Returns true only for the first caller. */
      async consume(id) {
        const s = sessions.get(id);
        if (!s || s.usedAt || s.revokedAt) return false;
        s.usedAt = new Date();
        return true;
      },
      async revokeFamily(familyId) {
        for (const s of sessions.values()) if (s.familyId === familyId && !s.revokedAt) s.revokedAt = new Date();
      },
      async revokeAllForUser(userId, { exceptFamilyId } = {}) {
        for (const s of sessions.values())
          if (s.userId === userId && !s.revokedAt && s.familyId !== exceptFamilyId) s.revokedAt = new Date();
      },
      async isFamilyActive(familyId) {
        const t = Date.now();
        for (const s of sessions.values())
          if (s.familyId === familyId && !s.usedAt && !s.revokedAt && ms(s.expiresAt) > t) return true;
        return false;
      },
      async listActiveForUser(userId) {
        const t = Date.now();
        return [...sessions.values()].filter((s) => s.userId === userId && !s.usedAt && !s.revokedAt && ms(s.expiresAt) > t).map((s) => ({ ...s }));
      },
    },

    tokens: {
      async create({ userId, type, hash, expiresAt }) {
        tokens.set(hash, { userId, type, hash, expiresAt, usedAt: null });
      },
      /** Atomically consume a one-time token. Returns the token row, or null when invalid/used/expired. */
      async consume(type, hash) {
        const k = tokens.get(hash);
        if (!k || k.type !== type || k.usedAt || ms(k.expiresAt) <= Date.now()) return null;
        k.usedAt = new Date();
        return { ...k };
      },
      async deleteForUser(userId, type) {
        for (const [h, k] of tokens) if (k.userId === userId && k.type === type) tokens.delete(h);
      },
    },

    identities: {
      _data: new Map(), // keyed by `${provider}:${providerId}`
      async create({ userId, provider, providerId, email }) {
        const key = `${provider}:${providerId}`;
        if (this._data.has(key)) throw Object.assign(new Error('Duplicate identity'), { code: 'DUPLICATE_IDENTITY' });
        const id = crypto.randomUUID();
        const row = { id, userId, provider, providerId, email, createdAt: new Date() };
        this._data.set(key, row);
        return { ...row };
      },
      async find(provider, providerId) {
        const row = this._data.get(`${provider}:${providerId}`);
        return row ? { ...row } : null;
      },
      async listForUser(userId) {
        return [...this._data.values()].filter((r) => r.userId === userId).map((r) => ({ ...r }));
      },
      async delete(provider, providerId) {
        this._data.delete(`${provider}:${providerId}`);
      },
    },
  };
}

module.exports = { createMemoryStore };
