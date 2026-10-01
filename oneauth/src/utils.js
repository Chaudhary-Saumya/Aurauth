'use strict';
const crypto = require('node:crypto');
const { ConfigError } = require('./errors');

const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha256 = (v) => crypto.createHash('sha256').update(String(v)).digest('base64url');

const UNITS = { ms: 1, s: 1e3, m: 6e4, h: 36e5, d: 864e5 };
/** "15m" | "7d" | 30000 (ms) -> milliseconds */
function duration(v, name) {
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return v;
  const m = /^(\d+)\s*(ms|s|m|h|d)$/.exec(String(v).trim());
  if (!m) throw new ConfigError(`${name} must look like "15m", "12h", "7d" or be a number of milliseconds (got ${JSON.stringify(v)}).`);
  return Number(m[1]) * UNITS[m[2]];
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;

function parseCookies(header) {
  const out = Object.create(null);
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (!k || k in out) continue;
    let v = part.slice(i + 1).trim();
    if (v[0] === '"') v = v.slice(1, -1);
    try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
  }
  return out;
}

function serializeCookie(name, value, o = {}) {
  let s = `${name}=${encodeURIComponent(value)}`;
  if (o.maxAgeMs != null) {
    s += `; Max-Age=${Math.floor(o.maxAgeMs / 1000)}; Expires=${new Date(Date.now() + o.maxAgeMs).toUTCString()}`;
  }
  s += `; Path=${o.path || '/'}`;
  if (o.domain) s += `; Domain=${o.domain}`;
  s += '; HttpOnly';
  if (o.secure) s += '; Secure';
  const ss = String(o.sameSite || 'lax').toLowerCase();
  s += `; SameSite=${ss[0].toUpperCase()}${ss.slice(1)}`;
  return s;
}

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)+$/;
function normalizeEmail(v) {
  if (typeof v !== 'string') return null;
  const e = v.normalize('NFKC').trim().toLowerCase();
  return e.length <= 254 && EMAIL_RE.test(e) ? e : null;
}

/** Levenshtein distance, used only to suggest fixes for typos in config keys. */
function distance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

function checkKeys(obj, allowed, where) {
  if (obj === undefined || obj === null) return;
  if (!isPlainObject(obj)) throw new ConfigError(`\`${where}\` must be an object.`);
  for (const key of Object.keys(obj)) {
    if (allowed.includes(key)) continue;
    const near = allowed.find((k) => distance(k.toLowerCase(), key.toLowerCase()) <= 2);
    throw new ConfigError(`Unknown option \`${where}.${key}\`.${near ? ` Did you mean \`${near}\`?` : ''} Allowed: ${allowed.join(', ')}.`);
  }
}

module.exports = { randomToken, sha256, duration, isPlainObject, parseCookies, serializeCookie, normalizeEmail, checkKeys };
