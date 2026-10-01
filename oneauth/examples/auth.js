// ============================================================================
//  auth.js — Authentication config (aurauth)
//  This is the ONLY file you write for authentication.
//  Every route, model, token, session, and security default is handled.
// ============================================================================
'use strict';
const { createAuth, defineAuth } = require('../index'); // In your app: require('aurauth')

// ─── Environment ─────────────────────────────────────────────────────────────
// Required env vars (fail loudly if missing — never silently run with defaults):
//   AUTH_SECRET   - 32+ char random string  (node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))")
//   MONGO_URL     - mongodb://... or mongodb+srv://...
//   GOOGLE_CLIENT_ID     - Google Cloud OAuth Client ID (optional, enables Google Login)
//   GOOGLE_CLIENT_SECRET - Google Cloud OAuth Client Secret (required for redirect flow)
//   FRONTEND_URL  - where your SPA / mobile app lives (used for email links + CORS)
//   APP_URL       - public URL of this API server
//   SMTP_URL      - smtp://user:pass@host:port  (production only)
//   ADMIN_EMAIL   - seed admin email (optional)
//   ADMIN_PASSWORD- seed admin password (optional)
// ─────────────────────────────────────────────────────────────────────────────

module.exports = defineAuth({

  // ── Secret & Database ────────────────────────────────────────────────────
  // The JWT signing secret. All access/refresh tokens are signed with this.
  // MUST be 32+ chars, random, stored in env — NEVER hardcode.
  secret:      process.env.AUTH_SECRET,

  // MongoDB connection string. Use 'memory' ONLY for local development.
  database:    process.env.MONGO_URL || 'memory',

  // ── Social Login / OAuth Providers ───────────────────────────────────────
  // Configure Google Login in 1 place. Automatically mounts:
  //   GET  /auth/google           (PKCE authorization redirect flow)
  //   GET  /auth/google/callback  (OAuth callback & token exchange)
  //   POST /auth/google/one-tap   (Google Identity Services One-Tap prompt / button)
  providers: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // required for redirect flow
      // redirectUri: `${process.env.APP_URL || 'http://localhost:3000'}/auth/google/callback`,
      // successRedirect: process.env.FRONTEND_URL || 'http://localhost:5173',
      // errorRedirect: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?error=google`,
      // linkExistingAccounts: true, // auto-links Google to existing verified email accounts
      // allowedDomains: [],        // optional: e.g. ['mycompany.com'] to restrict Workspace users
    },
  },

  // ── App Identity ─────────────────────────────────────────────────────────
  appName:     process.env.APP_NAME || 'MyApp',
  appUrl:      process.env.APP_URL  || 'http://localhost:3000',
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173',

  // ── User Fields ──────────────────────────────────────────────────────────
  // Define what data lives on each user. Every field listed here is
  // automatically accepted from the signup form (POST /auth/register).
  // To make a field admin-only, add: register: false
  //
  // Supported types: "string", "number", "boolean", "date", "url", "phone"
  // Modifiers:       required, unique, lowercase
  //
  // Note: email + password are built-in — you never define them here.
  fields: {
    username: "string required unique lowercase",
    dob:      "date required",
    // avatar:   "url",                          // optional fields omit "required"
    // bio:      "string",
    // phone:    "phone",
    // isPublic: "boolean",
    // plan:     { type: "string", register: false },  // admin-only, not from signup
  },

  // ── Roles ────────────────────────────────────────────────────────────────
  // First role = default for new signups. Use auth.requireRole('admin') to protect routes.
  roles: ['user', 'admin'],

  // ── Password Hashing ────────────────────────────────────────────────────
  // "bcrypt"      — industry standard, auto-requires `npm i bcrypt`
  // "argon2"      — memory-hard, auto-requires `npm i argon2`
  // "scrypt"      — Node built-in, zero dependencies (default)
  // "bcrypt:14"   — bcrypt with custom rounds
  //
  // Or full control: { hasher: hashers.bcrypt(bcrypt, { rounds: 14 }), minLength: 10 }
  password: "bcrypt",

  // ── JWT / Token Config ───────────────────────────────────────────────────
  // "jsonwebtoken" — auto-requires `npm i jsonwebtoken`
  // Omit to use the built-in jose (HS256, zero deps).
  //
  // Or full control: { adapter: jwt.jsonwebtoken(lib, { secret }), accessTtl: '15m' }
  tokens: "jsonwebtoken",

  // ── Session & Cookie Config ──────────────────────────────────────────────
  // oneauth manages its own cookies — you do NOT need cookie-parser.
  //
  // transport: "cookie"  — HttpOnly cookies (web apps, default)
  //            "bearer"  — Authorization header only (mobile / API clients)
  //            "both"    — cookies + tokens in response body
  session: {
    transport: 'cookie',
    cookies: {
      prefix:   'app',                            // cookie names: app_access, app_refresh
      sameSite: 'lax',                            // 'strict' for same-origin only
      secure:   process.env.NODE_ENV === 'production',
      // domain: '.myapp.com',                    // share across subdomains
    },
  },

  // ── Email Verification ───────────────────────────────────────────────────
  emailVerification: {
    enabled:  true,                               // sends a verify link on signup
    required: false,                              // true = block login until verified
    ttl:      '24h',
    // url: (token) => `${frontendUrl}/verify?token=${token}`,  // custom link format
  },

  // ── Password Reset ──────────────────────────────────────────────────────
  passwordReset: {
    enabled: true,
    ttl:     '30m',
    // url: (token) => `${frontendUrl}/reset?token=${token}`,
  },

  // ── Email Transport ──────────────────────────────────────────────────────
  // In development: emails print to the terminal (console mailer, automatic).
  // In production: pass a real mailer or oneauth blocks startup with an error.
  //
  // Uncomment for production:
  // email: mailers.nodemailer(
  //   require('nodemailer').createTransport(process.env.SMTP_URL),
  //   { from: `${process.env.APP_NAME} <no-reply@myapp.com>` }
  // ),

  // ── Registration ─────────────────────────────────────────────────────────
  registration: {
    enabled:   true,
    autoLogin: false,                             // true = login immediately after signup
  },

  // ── Security ─────────────────────────────────────────────────────────────
  // Origins that may call state-changing auth endpoints (POST, DELETE).
  // Your own appUrl and frontendUrl are trusted automatically.
  security: {
    trustedOrigins: [
      // 'https://admin.myapp.com',
      // 'capacitor://localhost',               // Ionic / Capacitor mobile
    ],
  },

  // ── Account Lockout ──────────────────────────────────────────────────────
  lockout: {
    maxAttempts: 5,                               // lock after 5 wrong passwords
    duration:    '15m',
  },

  // ── Hooks (optional) ─────────────────────────────────────────────────────
  // hooks: {
  //   beforeRegister: ({ email, fields }) => { /* validate, block domains, etc. */ },
  //   afterRegister:  ({ user })          => { /* analytics, welcome email, etc. */ },
  //   afterLogin:     ({ user })          => { /* log, update last-seen, etc. */ },
  //   onLoginFailed:  ({ email })         => { /* alert, rate-limit per user, etc. */ },
  //   afterPasswordReset: ({ user })      => { /* notify, log, etc. */ },
  //   afterEmailVerified: ({ user })      => { /* unlock features, etc. */ },
  // },

  // ── Seed Users (first startup) ───────────────────────────────────────────
  seedUsers: (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD)
    ? [{
        email:         process.env.ADMIN_EMAIL,
        password:      process.env.ADMIN_PASSWORD,
        roles:         ['admin'],
        emailVerified: true,
        username:      'admin',
        dob:           new Date('2000-01-01'),
      }]
    : [],
});
