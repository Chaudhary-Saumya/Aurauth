'use strict';
const { SignJWT, jwtVerify, decodeProtectedHeader } = require('jose');
const { ConfigError } = require('./errors');
const { sha256, randomToken } = require('./utils');

/**
 * Default access-token signer: HS256 JWT via `jose`. Pass several secrets to rotate:
 * the first one signs, all of them verify (matched by `kid`).
 */
function jose({ secret, issuer, audience }) {
  const keys = [].concat(secret).map((s) => ({ kid: sha256(s).slice(0, 8), key: new TextEncoder().encode(s) }));
  return {
    name: 'jose-hs256',
    async sign(claims, { expiresInSeconds }) {
      const { kid, key } = keys[0];
      const jwt = new SignJWT({ ...claims })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT', kid })
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + expiresInSeconds)
        .setJti(randomToken(12));
      if (issuer) jwt.setIssuer(issuer);
      if (audience) jwt.setAudience(audience);
      return jwt.sign(key);
    },
    async verify(token) {
      const { kid } = decodeProtectedHeader(token);
      const k = keys.find((x) => x.kid === kid);
      if (!k) throw new Error('unknown key id');
      const { payload } = await jwtVerify(token, k.key, { algorithms: ['HS256'], issuer, audience });
      return payload;
    },
  };
}

/** tokens.jsonwebtoken(require('jsonwebtoken'), { secret }) */
function jsonwebtoken(lib, { secret, algorithm = 'HS256', issuer, audience } = {}) {
  if (!lib || typeof lib.sign !== 'function' || typeof lib.verify !== 'function')
    throw new ConfigError('tokens.jsonwebtoken(lib, opts): pass the jsonwebtoken module itself.');
  if (!secret) throw new ConfigError('tokens.jsonwebtoken(lib, { secret }): `secret` (or a private/public key) is required.');
  const common = {};
  if (issuer) common.issuer = issuer;
  if (audience) common.audience = audience;
  return {
    name: 'jsonwebtoken',
    sign: async (claims, { expiresInSeconds }) => lib.sign({ ...claims }, secret, { algorithm, expiresIn: expiresInSeconds, ...common }),
    verify: async (token) => lib.verify(token, secret, { algorithms: [algorithm], ...common }),
  };
}

function assertSigner(s) {
  if (!s || typeof s.sign !== 'function' || typeof s.verify !== 'function')
    throw new ConfigError('`tokens.adapter` must be an object with async sign(claims, { expiresInSeconds }) and verify(token).');
  return s;
}

module.exports = { jose, jsonwebtoken, assertSigner };
