'use strict';
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { ConfigError } = require('./errors');
const scryptAsync = promisify(crypto.scrypt);

/** Default hasher: scrypt from Node's built-in crypto. Zero dependencies, no native build step. */
function scrypt({ N = 2 ** 15, r = 8, p = 1, keyLength = 64 } = {}) {
  const derive = (pw, salt, n, rr, pp, len) =>
    scryptAsync(pw.normalize('NFKC'), salt, len, { N: n, r: rr, p: pp, maxmem: 256 * n * rr * pp });
  return {
    name: 'scrypt',
    async hash(plain) {
      const salt = crypto.randomBytes(16);
      const dk = await derive(plain, salt, N, r, p, keyLength);
      return ['scrypt', N, r, p, salt.toString('base64url'), dk.toString('base64url')].join('$');
    },
    async verify(plain, stored) {
      try {
        const [id, n, rr, pp, s, h] = String(stored).split('$');
        if (id !== 'scrypt') return false;
        const expected = Buffer.from(h, 'base64url');
        const dk = await derive(plain, Buffer.from(s, 'base64url'), +n, +rr, +pp, expected.length);
        return dk.length === expected.length && crypto.timingSafeEqual(dk, expected);
      } catch { return false; }
    },
    needsRehash(stored) {
      const [id, n, rr, pp] = String(stored).split('$');
      return id !== 'scrypt' || +n !== N || +rr !== r || +pp !== p;
    },
  };
}

/** hashers.bcrypt(require('bcrypt'))  (also works with bcryptjs) */
function bcrypt(lib, { rounds = 12 } = {}) {
  if (!lib || typeof lib.hash !== 'function' || typeof lib.compare !== 'function')
    throw new ConfigError('hashers.bcrypt(lib): pass the module itself, e.g. hashers.bcrypt(require("bcrypt")).');
  return {
    name: 'bcrypt',
    maxBytes: 72, // bcrypt silently ignores anything after 72 bytes, so we reject longer passwords instead
    hash: (plain) => lib.hash(plain, rounds),
    verify: async (plain, stored) => { try { return await lib.compare(plain, stored); } catch { return false; } },
    needsRehash: (stored) => { const m = /^\$2[abxy]\$(\d+)\$/.exec(stored); return !m || Number(m[1]) < rounds; },
  };
}

/** hashers.argon2(require('argon2')) */
function argon2(lib, opts = {}) {
  if (!lib || typeof lib.hash !== 'function' || typeof lib.verify !== 'function')
    throw new ConfigError('hashers.argon2(lib): pass the module itself, e.g. hashers.argon2(require("argon2")).');
  const o = { type: lib.argon2id, ...opts };
  return {
    name: 'argon2id',
    hash: (plain) => lib.hash(plain, o),
    verify: async (plain, stored) => { try { return await lib.verify(stored, plain); } catch { return false; } },
    needsRehash: async (stored) => (typeof lib.needsRehash === 'function' ? lib.needsRehash(stored, o) : false),
  };
}

function assertHasher(h) {
  if (!h || typeof h.hash !== 'function' || typeof h.verify !== 'function')
    throw new ConfigError('`password.hasher` must be an object with async hash(plain) and verify(plain, hash). Use hashers.scrypt(), hashers.bcrypt(lib) or hashers.argon2(lib).');
  return h;
}

module.exports = { scrypt, bcrypt, argon2, assertHasher };
