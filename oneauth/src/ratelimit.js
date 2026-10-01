'use strict';

/**
 * In-memory fixed-window limiter. Fine for a single instance.
 * Running several instances? Pass your own limiter: { hit(key, { max, windowMs }) -> { allowed, retryAfterSec } }
 */
function memoryLimiter({ maxKeys = 50000 } = {}) {
  const hits = new Map();
  const sweep = () => { const t = Date.now(); for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k); };
  const timer = setInterval(sweep, 60000);
  if (timer.unref) timer.unref();
  return {
    async hit(key, { max, windowMs }) {
      const t = Date.now();
      let e = hits.get(key);
      if (!e || e.resetAt <= t) {
        if (hits.size >= maxKeys) { sweep(); if (hits.size >= maxKeys) hits.delete(hits.keys().next().value); }
        e = { count: 0, resetAt: t + windowMs };
        hits.set(key, e);
      }
      e.count += 1;
      return { allowed: e.count <= max, retryAfterSec: Math.ceil((e.resetAt - t) / 1000) };
    },
    close() { clearInterval(timer); hits.clear(); },
  };
}

module.exports = { memoryLimiter };
