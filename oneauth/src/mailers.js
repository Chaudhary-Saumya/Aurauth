'use strict';
const { ConfigError } = require('./errors');

/** Development mailer: prints the message (including the raw token) to the terminal. */
function consoleMailer(log = console) {
  return {
    name: 'console',
    async send(m) {
      log.info(`\n[oneauth:email] to=${m.to} type=${m.type}\n  subject: ${m.subject}\n  link:    ${m.url}\n  token:   ${m.token}\n`);
    },
  };
}

/** mailers.nodemailer(transporter, { from }) */
function nodemailer(transporter, { from } = {}) {
  if (!transporter || typeof transporter.sendMail !== 'function') throw new ConfigError('mailers.nodemailer(transporter, { from }): pass a nodemailer transporter.');
  if (!from) throw new ConfigError('mailers.nodemailer(transporter, { from }): `from` is required, e.g. "MyApp <no-reply@myapp.com>".');
  return { name: 'nodemailer', send: (m) => transporter.sendMail({ from, to: m.to, subject: m.subject, text: m.text, html: m.html }) };
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const defaultTemplates = {
  verify: ({ url, appName }) => ({
    subject: `Verify your email for ${appName}`,
    text: `Confirm your email address by opening this link:\n\n${url}\n\nIf you did not create an account, you can ignore this email.`,
    html: `<p>Confirm your email address for <b>${esc(appName)}</b>:</p><p><a href="${esc(url)}">Verify email</a></p><p>If you did not create an account, ignore this email.</p>`,
  }),
  reset: ({ url, appName }) => ({
    subject: `Reset your ${appName} password`,
    text: `Reset your password by opening this link:\n\n${url}\n\nIf you did not ask for this, you can ignore this email. The link expires soon.`,
    html: `<p>Reset your <b>${esc(appName)}</b> password:</p><p><a href="${esc(url)}">Choose a new password</a></p><p>If you did not ask for this, ignore this email.</p>`,
  }),
};

module.exports = { consoleMailer, nodemailer, defaultTemplates };
