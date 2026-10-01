# aurauth

> **Zero-boilerplate, self-hosted authentication for Express + MongoDB.**  
> Configure it in **one file**, mount it in **one line**.

[![npm version](https://img.shields.io/badge/npm-0.1.0-blue.svg)](https://www.npmjs.com/package/aurauth)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3178C6.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: 34/34 Passing](https://img.shields.io/badge/Tests-34%2F34%20Passing-brightgreen.svg)]()

No boilerplate user models, JWT helper files, password hashing glue, refresh token rotation race-conditions, email verification flows, or rate-limiting middleware to hand-wire.

---

## ⚡ Quickstart (60 Seconds)

### 1. Install

```bash
npm install aurauth express mongoose
```

### 2. Configure (`auth.js`)

```javascript
const { createAuth } = require('aurauth');

module.exports = createAuth({
  secret: process.env.AUTH_SECRET,       // 32+ random characters
  database: process.env.MONGO_URL,       // mongodb://... or 'memory' for testing
  
  // Custom user fields — simple shorthand
  fields: {
    username: 'string required unique',
    dob:      'date',
  },

  // Roles (first is default for new signups)
  roles: ['user', 'admin'],
});
```

> **Tip:** Generate a secure secret:  
> `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`

### 3. Mount (`index.js`)

```javascript
const express = require('express');
const auth = require('./auth');

const app = express();
app.use(express.json());

// 🚀 Mount all authentication endpoints in 1 line
app.use(auth);

// 🔒 Protected route (requires valid login)
app.get('/api/dashboard', auth.protect, (req, res) => {
  res.json({ message: 'Welcome!', user: req.user });
});

// 🛡️ Admin-only route
app.delete('/api/users/:id', auth.requireRole('admin'), async (req, res) => {
  await auth.api.deleteUser(req.params.id);
  res.json({ message: 'User deleted' });
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

---

## 📦 What Routes You Get (Built-in)

All routes are automatically mounted under `/auth` (customizable via `basePath`):

| Method | Endpoint | Description | Auth Required |
|---|---|---|:---:|
| `POST` | `/auth/register` | Register new user `{ email, password, username, dob }` | No |
| `POST` | `/auth/login` | Login with email + password (returns user + tokens/cookies) | No |
| `GET` | `/auth/google` | Start Google OAuth 2.0 PKCE redirect flow | No |
| `GET` | `/auth/google/callback` | Google OAuth callback handler | No |
| `POST` | `/auth/google/one-tap` | Google Identity Services One-Tap / Button login `{ credential }` | No |
| `POST` | `/auth/refresh` | Rotates refresh token with reuse-detection | Cookie/Token |
| `POST` | `/auth/logout` | Revokes current session immediately | Yes |
| `POST` | `/auth/logout-all` | Revokes all active sessions across all devices | Yes |
| `GET` | `/auth/me` | Returns current user profile | Yes |
| `PATCH` | `/auth/me` | Updates allowed profile fields (`username`, `dob`, etc.) | Yes |
| `DELETE` | `/auth/me` | Deletes account (requires `{ password }` verification) | Yes |
| `GET` | `/auth/sessions` | Lists all active devices / login sessions | Yes |
| `DELETE` | `/auth/sessions/:id` | Revoke a specific session / device remotely | Yes |
| `POST` | `/auth/change-password`| Changes password and revokes all other sessions | Yes |
| `POST` | `/auth/forgot-password`| Sends single-use secure reset token | No |
| `POST` | `/auth/reset-password` | Resets password with token & invalidates all sessions | No |
| `POST` | `/auth/verify-email` | Verifies user's email address | No |
| `POST` | `/auth/resend-verification` | Resends email verification link | No |

---

## 🛠️ Field Definition Shorthand

Define custom user fields effortlessly using intuitive string syntax or objects:

```javascript
fields: {
  // String shorthand syntax
  username:    'string required unique',
  age:         'number',
  phone:       'phone',
  website:     'url',
  birthDate:   'date',

  // Object syntax (supports full Mongoose options)
  bio: {
    type: 'string',
    maxLength: 500,
    default: '',
  },
  
  // Field not settable during public signup (admin/internal only)
  badge: {
    type: 'string',
    register: false,
  }
}
```

---

## 🧩 Middleware Reference

`aurauth` provides robust Express middleware attached directly to the auth instance:

- **`auth.protect`**: Rejects unauthenticated requests with `401 Unauthorized`. Populates `req.user` and `req.auth`.
- **`auth.optional`**: Populates `req.user` if valid authentication is present; allows request to continue if not.
- **`auth.requireRole('admin', 'editor')`**: Enforces RBAC. Returns `403 Forbidden` if user lacks required role.
- **`auth.requireVerified`**: Blocks access if the user's email is not yet verified.

### Request Context:
Inside any protected route:
- `req.user`: Complete sanitized user object (`id`, `email`, `roles`, `emailVerified`, plus your custom fields).
- `req.auth`: Session metadata (`userId`, `sessionId`, `roles`, `claims`).

---

## 🔐 Built-in Security Architecture

Everything is configured with high-security defaults out of the box:

- 🛡️ **Zero Password Leaks**: Uses constant-time equality checks and timing-equalized error responses to prevent user enumeration.
- 🔄 **Refresh Token Rotation + Family Revocation**: Stored hashed (SHA-256). If an old token is reused (e.g. stolen), the entire session family is instantly revoked with a 10s grace window for concurrent tab races.
- 🍪 **Safe Cookie Transport**: `HttpOnly`, `SameSite=Lax`, `Secure` in production. Refresh cookie is path-scoped to `/auth`. CSRF protection through origin verification.
- 🛑 **Rate Limiting & Lockout**: Automatic per-IP rate limiting and brute-force account lockout after consecutive failed login attempts.
- 🚫 **Mass-Assignment Protection**: Internal fields (`roles`, `emailVerified`, password hashes) can never be injected via registration or profile updates.
- ⚠️ **Loud Startup Validation**: Warns or halts immediately if secrets are weak, production database is set to memory, or mailers are missing in production.

---

## ⚡ Pluggable Hasher, JWT & Email Providers

Want to use `bcrypt`, `argon2`, `jsonwebtoken`, or `nodemailer`? You can plug them directly with one line:

```javascript
const { createAuth, hashers, jwt, mailers } = require('aurauth');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

module.exports = createAuth({
  secret: process.env.AUTH_SECRET,
  database: process.env.MONGO_URL,

  // Pluggable hasher shorthand or adapter
  password: 'bcrypt', // or hashers.bcrypt(bcrypt, { rounds: 12 })
  
  // Pluggable mailer (e.g. Nodemailer)
  email: mailers.nodemailer(nodemailer.createTransporter({ ... }), {
    from: 'My App <no-reply@myapp.com>'
  }),
});
```

## 🌐 Login with Google (OAuth 2.0 + One-Tap)

Add Google Authentication configured **only** in your single `auth.js` file. `aurauth` automatically mounts:
- `GET /auth/google` (PKCE + State + Nonce authorization code redirect flow)
- `GET /auth/google/callback` (Secure token exchange & identity resolution)
- `POST /auth/google/one-tap` (Google Identity Services one-tap / prompt login)

### 1. Google Cloud Console Setup
1. Go to the [Google Cloud Console Credentials Page](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth 2.0 Client ID** with Application Type: **Web application**.
3. Add your frontend/backend URLs to **Authorized JavaScript origins**:
   - `http://localhost:3000` (development)
   - `https://yourdomain.com` (production)
4. Add the callback URL to **Authorized redirect URIs**:
   - `http://localhost:3000/auth/google/callback` (development)
   - `https://yourdomain.com/auth/google/callback` (production)
5. Copy your **Client ID** and **Client Secret**.

### 2. Configure `auth.js`

```javascript
const { createAuth } = require('aurauth');

module.exports = createAuth({
  secret: process.env.AUTH_SECRET,
  database: process.env.MONGO_URL,

  providers: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // required for redirect flow
      redirectUri: 'http://localhost:3000/auth/google/callback', // default: `${appUrl}${basePath}/google/callback`
      successRedirect: '/dashboard',                  // default: frontendUrl
      errorRedirect: '/login?error=google',           // default: frontendUrl + '/login'
      linkExistingAccounts: true,                     // default true (safe account linking)
      allowedDomains: [],                             // optional Google Workspace `hd` allowlist
    },
  },
});
```

### 3. Frontend Integration

#### Option A: Plain Redirect Button (Zero JS)
```html
<!-- Simple OAuth 2.0 PKCE Redirect -->
<a href="/auth/google" class="btn btn-google">
  Continue with Google
</a>

<!-- Or with safe post-login redirection -->
<a href="/auth/google?redirectTo=/billing">
  Continue with Google
</a>
```

#### Option B: Google Identity Services (One-Tap & FedCM Button)
```html
<script src="https://accounts.google.com/gsi/client" async defer></script>
<script>
  async function handleCredentialResponse(response) {
    const res = await fetch('/auth/google/one-tap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: response.credential })
    });
    const data = await res.json();
    if (res.ok) {
      window.location.href = '/dashboard';
    } else {
      console.error('Google Sign-In failed', data);
    }
  }

  window.onload = function () {
    google.accounts.id.initialize({
      client_id: "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
      callback: handleCredentialResponse
    });
    // Display the One-Tap prompt
    google.accounts.id.prompt();
    // Or render the official button
    google.accounts.id.renderButton(
      document.getElementById("googleBtn"),
      { theme: "outline", size: "large", type: "standard" }
    );
  };
</script>

<div id="googleBtn"></div>
```

---

## 🧑‍💻 Programmatic Admin API (`auth.api`)

Manage users and linked social identities server-side from background workers, CLI scripts, or admin panels:

```javascript
// Create user
const user = await auth.api.createUser({
  email: 'admin@myapp.com',
  password: 'SuperSecurePassword123!',
  roles: ['admin'],
  emailVerified: true,
  username: 'superadmin'
});

// Manage users
await auth.api.setRoles(userId, ['admin', 'billing']);
await auth.api.setDisabled(userId, true);
await auth.api.revokeSessions(userId); // force logout everywhere
await auth.api.deleteUser(userId);     // GDPR delete

// Manage linked social identities
const identities = await auth.api.listIdentities(userId);
// [ { id: '...', userId: '...', provider: 'google', providerId: '...', email: '...' } ]

// Unlink a social provider (refuses if user has no password and no other logins)
await auth.api.unlinkIdentity(userId, 'google');
```

---

## 🧪 Testing

Run the comprehensive test suite (34 tests covering all attack vectors, flows, Google OAuth PKCE/One-Tap, and edge cases):

```bash
npm test
```

---

## 📄 License

MIT © [Sumit Chaudhary](https://github.com/sumitchaudhary)
