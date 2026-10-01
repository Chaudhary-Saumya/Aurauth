'use strict';

class AuthError extends Error {
  constructor(status, code, message, headers) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

class ConfigError extends Error {
  constructor(message) {
    super(`[oneauth] ${message}`);
    this.name = 'ConfigError';
  }
}

const E = {
  invalidInput: (m = 'Invalid input.') => new AuthError(400, 'invalid_input', m),
  invalidToken: (m = 'This link is invalid or has expired.') => new AuthError(400, 'invalid_token', m),
  invalidCredentials: () => new AuthError(401, 'invalid_credentials', 'Invalid email or password.'),
  unauthorized: (m = 'Authentication required.', code = 'unauthorized') => new AuthError(401, code, m),
  forbidden: (m = 'You do not have access to this resource.', code = 'forbidden') => new AuthError(403, code, m),
  notFound: (m = 'Not found.') => new AuthError(404, 'not_found', m),
  emailTaken: () => new AuthError(409, 'email_taken', 'This email is already registered.'),
  tooMany: (retryAfterSec, code = 'too_many_requests') =>
    new AuthError(429, code, 'Too many attempts. Please try again later.', { 'Retry-After': String(Math.max(1, retryAfterSec || 1)) }),
};

/** Convert any thrown value into an AuthError, or null when it is an unexpected server error. */
function toAuthError(err) {
  if (err instanceof AuthError) return err;
  if (err && err.type === 'entity.parse.failed') return new AuthError(400, 'invalid_json', 'Request body is not valid JSON.');
  if (err && err.type === 'entity.too.large') return new AuthError(413, 'payload_too_large', 'Request body is too large.');
  if (err && err.name === 'ValidationError' && err.errors) {
    const first = Object.values(err.errors)[0];
    return E.invalidInput(first && first.message ? first.message : 'Invalid input.');
  }
  return null;
}

function sendError(res, err) {
  if (err.headers) for (const [k, v] of Object.entries(err.headers)) res.setHeader(k, v);
  if (err.status === 401) res.setHeader('WWW-Authenticate', 'Bearer');
  res.status(err.status).json({ error: { code: err.code, message: err.message } });
}

module.exports = { AuthError, ConfigError, E, toAuthError, sendError };
