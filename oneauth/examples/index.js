// ============================================================================
//  index.js — Application entry point
//  Mount aurauth + your own routes. That's it.
// ============================================================================
'use strict';
require('dotenv').config?.();                       // load .env (install: npm i dotenv)
const express = require('express');
const auth    = require('./auth');                   // <- the one file you wrote

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Global Middleware ──────────────────────────────────────────────────────
app.set('trust proxy', 1);                          // required behind nginx / load balancer / cloud
app.disable('x-powered-by');                        // don't advertise Express

// NOTE: You do NOT need cookie-parser for auth — oneauth handles its own cookies.
// Only add it if YOUR routes need req.cookies:
// const cookieParser = require('cookie-parser');
// app.use(cookieParser());

// ─── Mount Auth ─────────────────────────────────────────────────────────────
// This single line gives you ALL auth routes under /auth/*
app.use(auth);

// ┌────────────────────────────────────────────────────────────────────────────
// │  ROUTES YOU GET (all under /auth):
// │
// │  Registration & Login
// │    POST   /auth/register            { email, password, username, dob }
// │    POST   /auth/login               { email, password }
// │    GET    /auth/google              (starts Google OAuth 2.0 PKCE redirect flow)
// │    GET    /auth/google/callback     (Google OAuth callback handler)
// │    POST   /auth/google/one-tap      { credential } (Google Identity Services)
// │    POST   /auth/logout              (ends current session)
// │    POST   /auth/logout-all          (ends ALL sessions — all devices)
// │
// │  Tokens
// │    POST   /auth/refresh             rotates refresh token, returns new access token
// │
// │  Profile
// │    GET    /auth/me                  current user (requires auth)
// │    PATCH  /auth/me                  update profile fields (requires auth)
// │    DELETE /auth/me                  delete account { password } (requires auth)
// │
// │  Sessions / Devices
// │    GET    /auth/sessions            list all active sessions
// │    DELETE /auth/sessions/:id        revoke a specific session (device)
// │
// │  Password
// │    POST   /auth/change-password     { currentPassword, newPassword } (requires auth)
// │    POST   /auth/forgot-password     { email } — sends reset email
// │    POST   /auth/reset-password      { token, password } — from email link
// │
// │  Email Verification
// │    POST   /auth/verify-email        { token } — from email link
// │    POST   /auth/resend-verification { email }
// │
// │  MIDDLEWARE (use on your own routes):
// │    auth.protect              — requires valid access token
// │    auth.optional             — attaches user if token present, no error if absent
// │    auth.requireRole('admin') — requires auth + specific role(s)
// │    auth.requireVerified      — requires auth + verified email
// │
// │  PROGRAMMATIC API (server-side only):
// │    auth.api.createUser({ email, password, roles, ... })
// │    auth.api.findUserByEmail(email)
// │    auth.api.findUserById(id)
// │    auth.api.setRoles(userId, ['admin'])
// │    auth.api.setDisabled(userId, true)
// │    auth.api.revokeSessions(userId)
// └────────────────────────────────────────────────────────────────────────────

// ─── Your Application Routes ────────────────────────────────────────────────

// Health check (no auth)
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// Public route — optional auth (attaches user if logged in, no error if not)
app.get('/api/posts', auth.optional, (req, res) => {
  res.json({
    posts: [],
    viewingAs: req.user ? req.user.username : 'anonymous',
  });
});

// Protected route — any authenticated user
app.get('/api/profile', auth.protect, (req, res) => {
  res.json({ user: req.user });
});

// Protected route — only verified email
app.get('/api/billing', auth.requireVerified, (req, res) => {
  res.json({ plan: 'free', user: req.user.id });
});

// Protected route — admin only
app.delete('/api/users/:id', auth.requireRole('admin'), (req, res) => {
  res.json({ deleted: req.params.id });
});

// Protected route — multiple roles allowed
app.put('/api/posts/:id', auth.requireRole('admin', 'editor'), (req, res) => {
  res.json({ updated: req.params.id, by: req.user.id });
});

// ─── Global Error Handler ───────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[app]', err);
  if (!res.headersSent) {
    res.status(err.status || 500).json({
      error: { code: err.code || 'server_error', message: err.message || 'Something went wrong.' },
    });
  }
});

// ─── Start Server ───────────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`\n  🚀  Server running on http://localhost:${PORT}`);
  console.log(`  🔐  Auth routes:     http://localhost:${PORT}/auth/*`);
  console.log(`  ❤️   Health check:    http://localhost:${PORT}/health\n`);
});

// ─── Graceful Shutdown ──────────────────────────────────────────────────────
async function shutdown(signal) {
  console.log(`\n  ⏳  ${signal} received — shutting down gracefully...`);
  server.close();
  await auth.close();                               // closes DB connection + rate limiter
  console.log('  ✅  Shutdown complete.\n');
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
