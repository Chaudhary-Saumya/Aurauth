'use client'

import { useMemo, useState } from 'react'
import { Check, Copy, Download, GitBranch, LockKeyhole, Minus, Plus, ShieldCheck, Terminal, Trash2, ArrowRight, Layers, Key, RefreshCw, Zap } from 'lucide-react'

type Field = { name: string; type: string; required: boolean; unique: boolean }

interface RouteData {
  method: string
  path: string
  name: string
  auth: 'Public' | 'Requires Auth' | 'Requires Admin' | 'Token / Cookie'
  description: string
  requestBody?: string
  responseBody: string
}

const routesData: RouteData[] = [
  {
    method: 'POST',
    path: '/auth/register',
    name: 'Register',
    auth: 'Public',
    description: 'Create a new user account with validated custom fields, securely hashed password, and an initial session.',
    requestBody: `{\n  "email": "developer@company.com",\n  "password": "CorrectHorseBattery99!",\n  "username": "developer",\n  "dob": "1998-04-12"\n}`,
    responseBody: `{\n  "user": {\n    "id": "674a91f3b18e4c001a4e21a0",\n    "email": "developer@company.com",\n    "username": "developer",\n    "roles": ["user"],\n    "emailVerified": false\n  }\n}`,
  },
  {
    method: 'POST',
    path: '/auth/login',
    name: 'Login',
    auth: 'Public',
    description: 'Authenticate with email + password. Returns user object and sets HttpOnly cookies (or returns bearer tokens).',
    requestBody: `{\n  "email": "developer@company.com",\n  "password": "CorrectHorseBattery99!"\n}`,
    responseBody: `{\n  "user": {\n    "id": "674a91f3b18e4c001a4e21a0",\n    "email": "developer@company.com",\n    "roles": ["user"]\n  }\n}`,
  },
  {
    method: 'GET',
    path: '/auth/google',
    name: 'Google Redirect',
    auth: 'Public',
    description: 'Initiates Google OAuth 2.0 PKCE flow with signed state + nonce cookie and redirects to Google.',
    requestBody: `// Query param (optional)\nGET /auth/google?redirectTo=/dashboard`,
    responseBody: `// 302 Found\nLocation: https://accounts.google.com/o/oauth2/v2/auth?client_id=...\nSet-Cookie: app_google_state=...; HttpOnly; SameSite=Lax`,
  },
  {
    method: 'GET',
    path: '/auth/google/callback',
    name: 'Google Callback',
    auth: 'Public',
    description: 'Validates HMAC state cookie, exchanges authorization code for Google ID token, verifies JWKS signature, links accounts safely, issues session, and redirects.',
    responseBody: `// 302 Found\nLocation: /dashboard\nSet-Cookie: app_access=...; HttpOnly; SameSite=Lax\nSet-Cookie: app_refresh=...; HttpOnly; SameSite=Lax`,
  },
  {
    method: 'POST',
    path: '/auth/google/one-tap',
    name: 'Google One-Tap',
    auth: 'Public',
    description: 'Authenticates Google Identity Services credential (ID token). Verifies JWKS signature, resolves identity, and issues session tokens/cookies with origin verification.',
    requestBody: `{\n  "credential": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."\n}`,
    responseBody: `{\n  "user": {\n    "id": "674a91f3b18e4c001a4e21a0",\n    "email": "developer@gmail.com",\n    "roles": ["user"],\n    "providers": ["google"],\n    "emailVerified": true\n  },\n  "accessToken": "eyJhbGciOi...",\n  "refreshToken": "e3b0c44..."\n}`,
  },
  {
    method: 'POST',
    path: '/auth/refresh',
    name: 'Refresh token',
    auth: 'Token / Cookie',
    description: 'Rotates the refresh token and issues a new access token. Protected by reuse detection and race-condition grace period.',
    responseBody: `{\n  "status": "refreshed",\n  "expiresIn": "10m"\n}`,
  },
  {
    method: 'POST',
    path: '/auth/logout',
    name: 'Logout',
    auth: 'Requires Auth',
    description: 'Revokes the current session immediately and clears client auth cookies.',
    responseBody: `{\n  "status": "logged_out"\n}`,
  },
  {
    method: 'POST',
    path: '/auth/logout-all',
    name: 'Logout all',
    auth: 'Requires Auth',
    description: 'Revokes all active sessions across all devices (phones, laptops, browsers).',
    responseBody: `{\n  "status": "all_sessions_revoked"\n}`,
  },
  {
    method: 'GET',
    path: '/auth/me',
    name: 'Get profile',
    auth: 'Requires Auth',
    description: 'Fetches the currently authenticated user profile including custom fields and roles.',
    responseBody: `{\n  "user": {\n    "id": "674a91f3b18e4c001a4e21a0",\n    "email": "developer@company.com",\n    "username": "developer",\n    "dob": "1998-04-12",\n    "roles": ["user"],\n    "emailVerified": true\n  }\n}`,
  },
  {
    method: 'PATCH',
    path: '/auth/me',
    name: 'Update profile',
    auth: 'Requires Auth',
    description: 'Updates allowed custom profile fields. Internal fields (roles, password, email) cannot be modified here.',
    requestBody: `{\n  "username": "new_handle",\n  "dob": "1998-04-12"\n}`,
    responseBody: `{\n  "user": {\n    "id": "674a91f3b18e4c001a4e21a0",\n    "username": "new_handle"\n  }\n}`,
  },
  {
    method: 'DELETE',
    path: '/auth/me',
    name: 'Delete account',
    auth: 'Requires Auth',
    description: 'GDPR-compliant permanent account deletion. Requires password confirmation for safety.',
    requestBody: `{\n  "password": "CorrectHorseBattery99!"\n}`,
    responseBody: `{\n  "status": "account_deleted"\n}`,
  },
  {
    method: 'GET',
    path: '/auth/sessions',
    name: 'List sessions',
    auth: 'Requires Auth',
    description: 'Lists all active login sessions / devices for the current user.',
    responseBody: `{\n  "sessions": [\n    {\n      "id": "sess_89f02a",\n      "current": true,\n      "createdAt": "2026-09-30T10:00:00Z",\n      "ip": "127.0.0.1"\n    }\n  ]\n}`,
  },
  {
    method: 'DELETE',
    path: '/auth/sessions/:id',
    name: 'Revoke session',
    auth: 'Requires Auth',
    description: 'Remotely terminates a specific device/session by ID.',
    responseBody: `{\n  "status": "session_revoked"\n}`,
  },
  {
    method: 'POST',
    path: '/auth/change-password',
    name: 'Change password',
    auth: 'Requires Auth',
    description: 'Updates password and signs out all other active devices for security.',
    requestBody: `{\n  "currentPassword": "OldPassword123!",\n  "newPassword": "BrandNewPassword99!"\n}`,
    responseBody: `{\n  "status": "password_changed"\n}`,
  },
  {
    method: 'POST',
    path: '/auth/forgot-password',
    name: 'Forgot password',
    auth: 'Public',
    description: 'Sends a one-time cryptographic password reset link to the given email (timing-safe).',
    requestBody: `{\n  "email": "developer@company.com"\n}`,
    responseBody: `{\n  "status": "reset_email_sent_if_exists"\n}`,
  },
  {
    method: 'POST',
    path: '/auth/reset-password',
    name: 'Reset password',
    auth: 'Public',
    description: 'Resets the password using a valid token and revokes all active sessions.',
    requestBody: `{\n  "token": "7a8b9c...token",\n  "password": "BrandNewPassword99!"\n}`,
    responseBody: `{\n  "status": "password_reset_success"\n}`,
  },
  {
    method: 'POST',
    path: '/auth/verify-email',
    name: 'Verify email',
    auth: 'Public',
    description: 'Validates an email verification token and marks account as verified.',
    requestBody: `{\n  "token": "3f4e5d...token"\n}`,
    responseBody: `{\n  "status": "email_verified"\n}`,
  },
  {
    method: 'POST',
    path: '/auth/resend-verification',
    name: 'Resend verification',
    auth: 'Public',
    description: 'Resends the email verification link to unverified users.',
    requestBody: `{\n  "email": "developer@company.com"\n}`,
    responseBody: `{\n  "status": "verification_sent_if_unverified"\n}`,
  },
]

function AurauthLogo() {
  return (
    <svg className="brand-svg" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect width="32" height="32" rx="8" fill="#09090B" />
      <path d="M16 6L24 10.5V17.5C24 22.5 19.5 25.5 16 26.5C12.5 25.5 8 22.5 8 17.5V10.5L16 6Z" stroke="#10B981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="16" cy="15" r="2.5" fill="#10B981" />
      <path d="M16 17.5V21" stroke="#10B981" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}

export default function Page() {
  const [hasher, setHasher] = useState('scrypt')
  const [transport, setTransport] = useState('Cookies')
  const [tab, setTab] = useState('auth.js')
  const [route, setRoute] = useState(0)
  const [toast, setToast] = useState(false)

  const [fields, setFields] = useState<Field[]>([
    { name: 'username', type: 'string', required: true, unique: true },
    { name: 'dob', type: 'date', required: true, unique: false },
  ])

  const [roles, setRoles] = useState(['user', 'admin', 'moderator'])
  const [defaultRole, setDefaultRole] = useState('user')
  const [isAddingRole, setIsAddingRole] = useState(false)
  const [newRoleInput, setNewRoleInput] = useState('')

  const [googleAuth, setGoogleAuth] = useState(true)
  const [security, setSecurity] = useState({ email: true, reset: true, lockout: true, rate: true })
  const [newFieldName, setNewFieldName] = useState('')
  const [newFieldType, setNewFieldType] = useState('string')
  const [newFieldRequired, setNewFieldRequired] = useState(false)

  const codeAuth = useMemo(() => {
    const orderedRoles = [defaultRole, ...roles.filter((r) => r !== defaultRole)]
    const fieldLines = fields
      .map((f) => `    ${f.name}: '${f.type}${f.required ? ' required' : ''}${f.unique ? ' unique' : ''}',`)
      .join('\n')

    const providerLines = googleAuth
      ? `  providers: {\n    google: {\n      clientId: process.env.GOOGLE_CLIENT_ID,\n      clientSecret: process.env.GOOGLE_CLIENT_SECRET,\n    },\n  },`
      : ''

    const featureLines = [
      security.email ? '  emailVerification: { enabled: true, required: false },' : '',
      security.reset ? '  passwordReset: { enabled: true },' : '',
      security.lockout ? "  lockout: { maxAttempts: 5, duration: '15m' }," : '',
    ]
      .filter(Boolean)
      .join('\n')

    return `const { createAuth } = require('aurauth')

module.exports = createAuth({
  database: process.env.MONGO_URL || 'mongodb://localhost:27017/myapp',
  secret: process.env.AUTH_SECRET,
${providerLines ? providerLines + '\n' : ''}  fields: {
${fieldLines}
  },
  roles: ${JSON.stringify(orderedRoles)},
  password: '${hasher}',
  session: {
    transport: '${transport === 'Cookies' ? 'cookie' : transport.toLowerCase()}',
  },
${featureLines}
})`
  }, [fields, roles, defaultRole, hasher, transport, security, googleAuth])

  const codeIndex = useMemo(() => {
    return `const express = require('express')
const auth = require('./auth')

const app = express()
app.use(express.json())

// Mount all aurauth endpoints in 1 line
// (Handles /register, /login, /google, /google/callback, /google/one-tap, /me, /refresh...)
app.use(auth)

// Protected route (requires valid login)
app.get('/api/dashboard', auth.protect, (req, res) => {
  res.json({ message: 'Welcome!', user: req.user })
})

// Role-protected route (admin only)
app.delete('/api/users/:id', auth.requireRole('admin'), async (req, res) => {
  await auth.api.deleteUser(req.params.id)
  res.json({ message: 'User deleted' })
})

app.listen(3000, () => console.log('Server running on port 3000'))`
  }, [])

  const codeClient = useMemo(() => {
    return `<!-- Option A: Standard OAuth 2.0 PKCE Link (Zero JS) -->
<a href="/auth/google" class="btn-google">
  Continue with Google
</a>

<!-- Option B: Google Identity Services (One-Tap & FedCM Prompt) -->
<script src="https://accounts.google.com/gsi/client" async defer></script>
<div id="googleBtn"></div>

<script>
  async function handleGoogleCallback(response) {
    const res = await fetch('/auth/google/one-tap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: response.credential })
    });
    if (res.ok) window.location.href = '/dashboard';
  }

  window.onload = function () {
    google.accounts.id.initialize({
      client_id: "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
      callback: handleGoogleCallback
    });
    google.accounts.id.renderButton(document.getElementById("googleBtn"), { theme: "outline", size: "large" });
    google.accounts.id.prompt(); // Floating One-Tap popup
  };
</script>`
  }, [])

  const codeEnv = useMemo(() => {
    return `AUTH_SECRET=your_32_character_random_secret_here
MONGO_URL=mongodb://localhost:27017/myapp
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret
PORT=3000
NODE_ENV=development`
  }, [])

  const displayCode = tab === 'auth.js' ? codeAuth : tab === 'index.js' ? codeIndex : tab === 'client.html' ? codeClient : codeEnv

  const addField = () => {
    if (newFieldName.trim()) {
      setFields([
        ...fields,
        {
          name: newFieldName.trim().replace(/\s+/g, '_').toLowerCase(),
          type: newFieldType,
          required: newFieldRequired,
          unique: false,
        },
      ])
      setNewFieldName('')
      setNewFieldRequired(false)
    }
  }

  const addRole = () => {
    const trimmed = newRoleInput.trim().toLowerCase()
    if (trimmed && !roles.includes(trimmed)) {
      setRoles([...roles, trimmed])
    }
    setNewRoleInput('')
    setIsAddingRole(false)
  }

  const copyText = async (text: string) => {
    await navigator.clipboard.writeText(text)
    setToast(true)
    setTimeout(() => setToast(false), 1600)
  }

  const downloadActiveFile = () => {
    const filename = tab
    const blob = new Blob([displayCode], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.click()
    URL.revokeObjectURL(url)
  }

  const activeRoute = routesData[route] || routesData[0]

  return (
    <main>
      {/* Full-width Seamless Navbar */}
      <header className="site-header">
        <div className="header-inner">
          <div className="brand">
            <AurauthLogo />
            <span>aurauth</span>
            <small>v0.1.0</small>
          </div>

          <nav>
            <a href="#configurator">Configurator</a>
            <a href="#routes">Routes</a>
            <a href="#architecture">Architecture</a>
            <a href="#docs">Docs</a>
          </nav>

          <div className="header-actions">
            <button className="npm-pill" onClick={() => copyText('npm i aurauth')}>
              <span className="npm-badge">npm</span>
              <code>npm i aurauth</code>
              <Copy size={12} />
            </button>
            <a className="icon-btn" href="https://github.com/sumitchaudhary" target="_blank" rel="noreferrer" aria-label="GitHub">
              <GitBranch size={16} />
            </a>
          </div>
        </div>
      </header>

      {/* Centered Hero Section */}
      <section className="hero-center">
        <div className="eyebrow-pill">
          <span className="status-dot" />
          EXPRESS + MONGODB AUTHENTICATION
        </div>

        <h1 className="hero-title">
          <span className="title-line-1">Authentication for Express.</span>
        </h1>

        <p className="hero-sub">
          Configure in one file, mount in one line. Complete with refresh token rotation, RBAC, lockout protection, and automatic account management.
        </p>

        <div className="install-command-bar">
          <Terminal size={16} color="#059669" />
          <code>npm install aurauth express mongoose</code>
          <button className="copy-pill-btn" onClick={() => copyText('npm install aurauth express mongoose')}>
            <Copy size={12} /> Copy
          </button>
        </div>

        <div className="hero-buttons-row">
          <a className="btn-launch" href="#configurator">
            <Zap size={16} /> Launch Configurator
          </a>
          <a className="btn-docs" href="#docs">
            Read Docs <ArrowRight size={15} />
          </a>
        </div>
      </section>

      {/* 4 Feature Highlights Grid */}
      <div className="features-container">
        <div className="features-highlight-grid">
          <div className="feature-box">
            <div className="feature-icon-wrapper"><Layers size={20} /></div>
            <div>
              <strong>1-Line Mount</strong>
              <span>app.use(auth) mounts 15 endpoints</span>
            </div>
          </div>
          <div className="feature-box">
            <div className="feature-icon-wrapper"><RefreshCw size={20} /></div>
            <div>
              <strong>Token Rotation</strong>
              <span>With family reuse revocation</span>
            </div>
          </div>
          <div className="feature-box">
            <div className="feature-icon-wrapper"><Key size={20} /></div>
            <div>
              <strong>Role-Based Access</strong>
              <span>auth.requireRole('admin') middleware</span>
            </div>
          </div>
          <div className="feature-box">
            <div className="feature-icon-wrapper"><ShieldCheck size={20} /></div>
            <div>
              <strong>Hardened Security</strong>
              <span>Constant-time login equality</span>
            </div>
          </div>
        </div>
      </div>

      {/* 01 Configurator Section */}
      <section className="section-configurator" id="configurator">
        <div className="section-centered-header">
          <div className="eyebrow-pill" style={{ margin: '0 auto 8px' }}>
            01 / INTERACTIVE BUILDER
          </div>
          <h2>Shape your auth layer.</h2>
          <p>
            Customize your schema, roles, and hashing. Copy the generated config directly into your project.
          </p>
        </div>

        <div className="configurator-card">
          <aside className="config-sidebar">
            {/* Database */}
            <div className="config-group">
              <div className="config-group-header">
                <span className="config-title">Database</span>
                <span className="config-title" style={{ color: 'var(--text-muted)' }}>MongoDB</span>
              </div>
              <div className="db-display-pill">
                <Terminal size={14} />
                <span>process.env.MONGO_URL</span>
              </div>
            </div>

            {/* Custom User Fields */}
            <div className="config-group">
              <div className="config-group-header">
                <span className="config-title">User Fields</span>
                <span className="config-title" style={{ color: 'var(--text-muted)' }}>{fields.length} custom fields</span>
              </div>

              <div className="field-chips-list">
                {fields.map((f, i) => (
                  <div className="field-chip-item" key={f.name}>
                    <strong>{f.name}</strong>
                    <span className="type-badge">{f.type}</span>
                    {f.required && <span className="req-badge">required</span>}
                    <button className="field-delete-btn" onClick={() => setFields(fields.filter((_, x) => x !== i))} aria-label={`Remove ${f.name}`}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                ))}
              </div>

              {/* Clean Field Input Box */}
              <div className="add-field-form">
                <input
                  placeholder="Enter field name (e.g. bio, plan, age)"
                  value={newFieldName}
                  onChange={(e) => setNewFieldName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addField()}
                />
                <div className="add-field-row-controls">
                  <select
                    value={newFieldType}
                    onChange={(e) => setNewFieldType(e.target.value)}
                    aria-label="Field type"
                  >
                    <option value="string">Type: string</option>
                    <option value="number">Type: number</option>
                    <option value="date">Type: date</option>
                    <option value="boolean">Type: boolean</option>
                    <option value="phone">Type: phone</option>
                    <option value="url">Type: url</option>
                  </select>
                  <label className="req-checkbox-label">
                    <input
                      type="checkbox"
                      checked={newFieldRequired}
                      onChange={(e) => setNewFieldRequired(e.target.checked)}
                    />
                    Required
                  </label>
                  <button className="btn-add-field-action" onClick={addField}>
                    <Plus size={13} /> Add
                  </button>
                </div>
              </div>
            </div>

            {/* Roles */}
            <div className="config-group">
              <div className="config-group-header">
                <span className="config-title">Roles</span>
                <span className="config-title" style={{ color: 'var(--text-muted)' }}>default: {defaultRole}</span>
              </div>
              <div className="roles-chips-wrapper">
                {roles.map((r) => (
                  <button className="role-tag-pill" key={r} onClick={() => roles.length > 1 && setRoles(roles.filter((x) => x !== r))}>
                    {r} <Minus size={11} />
                  </button>
                ))}
                {isAddingRole ? (
                  <div className="role-input-box">
                    <input
                      autoFocus
                      placeholder="role"
                      value={newRoleInput}
                      onChange={(e) => setNewRoleInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') addRole()
                        if (e.key === 'Escape') setIsAddingRole(false)
                      }}
                      onBlur={addRole}
                    />
                    <button onClick={addRole}><Check size={12} /></button>
                  </div>
                ) : (
                  <button className="btn-add-role-trigger" onClick={() => setIsAddingRole(true)}>
                    <Plus size={12} /> role
                  </button>
                )}
              </div>
              <select className="dropdown-role-select" value={defaultRole} onChange={(e) => setDefaultRole(e.target.value)} aria-label="Default role">
                {roles.map((r) => (
                  <option key={r} value={r}>Default role: {r}</option>
                ))}
              </select>
            </div>

            {/* Password Hasher */}
            <div className="config-group">
              <div className="config-group-header">
                <span className="config-title">Password Hasher</span>
              </div>
              <div className="seg-control-bar">
                {['scrypt', 'bcrypt', 'argon2'].map((h) => (
                  <button key={h} className={hasher === h ? 'active' : ''} onClick={() => setHasher(h)}>
                    {h}
                  </button>
                ))}
              </div>
            </div>

            {/* Session Transport */}
            <div className="config-group">
              <div className="config-group-header">
                <span className="config-title">Session Transport</span>
              </div>
              <div className="seg-control-bar">
                {['Cookies', 'Bearer', 'Both'].map((t) => (
                  <button key={t} className={transport === t ? 'active' : ''} onClick={() => setTransport(t)}>
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {/* Social Providers (OAuth) */}
            <div className="config-group">
              <div className="config-group-header">
                <span className="config-title">Social Providers</span>
                <span className="config-title" style={{ color: '#10b981' }}>OAuth 2.0</span>
              </div>
              <div className="toggle-setting-row">
                <span>Google (PKCE + One-Tap)</span>
                <button
                  aria-pressed={googleAuth}
                  className={`toggle-btn ${googleAuth ? 'on' : ''}`}
                  onClick={() => setGoogleAuth(!googleAuth)}
                >
                  <span />
                </button>
              </div>
            </div>

            {/* Security Toggles */}
            <div className="config-group">
              <div className="config-group-header">
                <span className="config-title">Security Defaults</span>
                <ShieldCheck size={15} color="#10b981" />
              </div>
              {[
                ['email', 'Email verification flow'],
                ['reset', 'Password reset links'],
                ['lockout', 'Account lockout after 5 fails'],
                ['rate', 'Per-IP rate limiting'],
              ].map(([key, label]) => (
                <div className="toggle-setting-row" key={key}>
                  <span>{label}</span>
                  <button
                    aria-pressed={security[key as keyof typeof security]}
                    className={`toggle-btn ${security[key as keyof typeof security] ? 'on' : ''}`}
                    onClick={() => setSecurity({ ...security, [key]: !security[key as keyof typeof security] })}
                  >
                    <span />
                  </button>
                </div>
              ))}
            </div>
          </aside>

          {/* Live Code View */}
          <div className="config-code-view">
            <div className="config-code-header">
              <div className="code-tabs-bar">
                {['auth.js', 'index.js', 'client.html', '.env'].map((t) => (
                  <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
                    {t}
                  </button>
                ))}
              </div>
              <div className="code-tools-group">
                <button className="btn-code-tool" onClick={() => copyText(displayCode)}>
                  <Copy size={13} /> Copy code
                </button>
                <button className="btn-code-tool" onClick={downloadActiveFile}>
                  <Download size={13} /> Download
                </button>
              </div>
            </div>

            <div className="config-code-editor">
              <div className="code-gutter-numbers">
                {displayCode.split('\n').map((_, i) => (
                  <span key={i}>{String(i + 1).padStart(2, '0')}</span>
                ))}
              </div>
              <pre><code>{displayCode}</code></pre>
            </div>

            <div className="config-code-footer">
              <span><span className="status-dot" style={{ display: 'inline-block', marginRight: 6 }} />Generated Live Preview</span>
              <span>{displayCode.split('\n').length} lines</span>
            </div>
          </div>
        </div>
      </section>

      {/* 02 Routes Section */}
      <section className="section-routes" id="routes">
        <div className="section-centered-header">
          <div className="eyebrow-pill" style={{ margin: '0 auto 8px' }}>
            02 / ENDPOINTS
          </div>
          <h2>{routesData.length} Built-in Routes</h2>
          <p>
            All endpoints are automatically handled with standardized responses.
          </p>
        </div>

        <div className="routes-deck">
          <div className="routes-menu">
            {routesData.map((r, i) => {
              const badgeClass =
                r.method === 'POST'
                  ? 'tag-post'
                  : r.method === 'GET'
                  ? 'tag-get'
                  : r.method === 'PATCH'
                  ? 'tag-patch'
                  : 'tag-delete'

              return (
                <button
                  className={`route-menu-btn ${route === i ? 'active' : ''}`}
                  onClick={() => setRoute(i)}
                  key={`${r.method}-${r.path}`}
                >
                  <span className={`method-tag ${badgeClass}`}>{r.method}</span>
                  <code>{r.path}</code>
                  <span className="route-nickname">{r.name}</span>
                </button>
              )
            })}
          </div>

          <div className="route-pane-content">
            <div className="route-pane-header">
              <span
                className={`method-tag ${
                  activeRoute.method === 'POST'
                    ? 'tag-post'
                    : activeRoute.method === 'GET'
                    ? 'tag-get'
                    : activeRoute.method === 'PATCH'
                    ? 'tag-patch'
                    : 'tag-delete'
                }`}
              >
                {activeRoute.method}
              </span>
              <code>{activeRoute.path}</code>
              <span className="auth-pill">
                <LockKeyhole size={12} /> {activeRoute.auth}
              </span>
            </div>

            <p className="route-info-desc">{activeRoute.description}</p>

            {activeRoute.requestBody && (
              <>
                <div className="data-box-label">REQUEST PAYLOAD</div>
                <pre className="data-box"><code>{activeRoute.requestBody}</code></pre>
              </>
            )}

            <div className="data-box-label">RESPONSE SCHEMA</div>
            <pre className="data-box"><code>{activeRoute.responseBody}</code></pre>
          </div>
        </div>
      </section>

      {/* 03 Security Architecture */}
      <section className="section-security" id="architecture">
        <div className="section-centered-header">
          <div className="eyebrow-pill" style={{ margin: '0 auto 8px' }}>
            03 / ARCHITECTURE
          </div>
          <h2>Built-in Hardening</h2>
          <p>
            Enterprise security best practices configured by default with zero manual glue.
          </p>
        </div>

        <div className="security-cards-grid">
          <div className="security-tile">
            <div>
              <span className="tile-number">01</span>
              <h3>Token Rotation</h3>
              <p>Refresh tokens rotate on every use. Stolen token reuse immediately terminates the whole session family with a 10s multi-tab grace window.</p>
            </div>
          </div>
          <div className="security-tile">
            <div>
              <span className="tile-number">02</span>
              <h3>Timing Equalization</h3>
              <p>Login endpoints use constant-time checks and timing-equalized error paths to prevent account and username enumeration attacks.</p>
            </div>
          </div>
          <div className="security-tile">
            <div>
              <span className="tile-number">03</span>
              <h3>Mass Assignment Guard</h3>
              <p>Internal fields like roles, password hashes, and verification flags are strictly whitelisted and blocked from public request bodies.</p>
            </div>
          </div>
          <div className="security-tile">
            <div>
              <span className="tile-number">04</span>
              <h3>Cryptographic Hashing</h3>
              <p>Passwords use scrypt or bcrypt with salt. All refresh and reset tokens are stored as SHA-256 hashes at rest.</p>
            </div>
          </div>
          <div className="security-tile">
            <div>
              <span className="tile-number">05</span>
              <h3>OAuth PKCE & Safe Account Linking</h3>
              <p>RFC 7636 PKCE with HMAC-signed state cookies. Unverified pre-registered accounts have passwords wiped on link to stop account takeover.</p>
            </div>
          </div>
        </div>
      </section>

      {/* 04 Programmatic API */}
      <section className="section-api" id="docs">
        <div className="api-spotlight-box">
          <div>
            <div className="eyebrow-pill" style={{ marginBottom: 12 }}>04 / PROGRAMMATIC API</div>
            <h2>Server-Side Control</h2>
            <p>
              When you need to manage users from background workers, cron jobs, or admin scripts, use the built-in <code>auth.api</code> methods.
            </p>
          </div>

          <div className="api-code-card">
            <div className="api-code-card-header">
              <span>server.js</span>
              <button className="copy-pill-btn" onClick={() => copyText(`const user = await auth.api.createUser({ email: 'admin@app.com', password: 'Password123!' });`)}>
                <Copy size={12} />
              </button>
            </div>
            <pre>
              <code>{`// Create user programmatically
const user = await auth.api.createUser({
  email: 'admin@app.com',
  password: 'SuperSecurePassword99!',
  roles: ['admin']
})

// Manage permissions & lifecycle
await auth.api.setRoles(user.id, ['admin'])
await auth.api.setDisabled(user.id, false)
await auth.api.revokeSessions(user.id) // force logout
await auth.api.deleteUser(user.id)     // GDPR delete

// Manage linked social accounts
const identities = await auth.api.listIdentities(user.id)
await auth.api.unlinkIdentity(user.id, 'google')`}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer>
        <div className="brand">
          <AurauthLogo />
          <span>aurauth</span>
        </div>
        <div style={{ display: 'flex', gap: '24px' }}>
          <a href="https://npmjs.com/package/aurauth" target="_blank" rel="noreferrer">NPM Package ↗</a>
          <a href="https://github.com/sumitchaudhary" target="_blank" rel="noreferrer">GitHub ↗</a>
          <a href="#configurator">Configurator</a>
        </div>
        <span>MIT License © 2026 Sumit Chaudhary</span>
      </footer>

      {toast && (
        <div className="toast-message">
          <Check size={16} /> Copied to clipboard!
        </div>
      )}
    </main>
  )
}
