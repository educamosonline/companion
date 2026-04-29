import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { Context, Next } from "hono";
import { getToken } from "./auth-manager.js";

// ─── Configuration ──────────────────────────────────────────────────────────

const AUTH_EMAIL = process.env.AUTH_EMAIL || "andre@neuronspark.ai";
const AUTH_PASSWORD_HASH = process.env.AUTH_PASSWORD_HASH || hashPassword("Iamthetao@78");
const AUTH_SESSION_SECRET = process.env.AUTH_SESSION_SECRET || AUTH_PASSWORD_HASH;
const SESSION_COOKIE = "ns_session";
const SESSION_MAX_AGE = 7 * 24 * 60 * 60; // 7 days in seconds
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

interface Session {
  email: string;
  createdAt: number;
  expiresAt: number;
}

interface SessionPayload {
  email: string;
  iat: number;
  exp: number;
}

// ─── Rate Limiting ──────────────────────────────────────────────────────────

interface LoginAttempt {
  count: number;
  lastAttempt: number;
  lockedUntil: number;
}

const loginAttempts = new Map<string, LoginAttempt>();

function isRateLimited(ip: string): boolean {
  const attempt = loginAttempts.get(ip);
  if (!attempt) return false;
  if (attempt.lockedUntil > Date.now()) return true;
  if (Date.now() - attempt.lastAttempt > LOCKOUT_DURATION) {
    loginAttempts.delete(ip);
    return false;
  }
  return false;
}

function recordFailedAttempt(ip: string): void {
  const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: 0, lockedUntil: 0 };
  attempt.count++;
  attempt.lastAttempt = Date.now();
  if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
    attempt.lockedUntil = Date.now() + LOCKOUT_DURATION;
    attempt.count = 0;
  }
  loginAttempts.set(ip, attempt);
}

function clearAttempts(ip: string): void {
  loginAttempts.delete(ip);
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function hashPassword(password: string): string {
  return createHash("sha256").update(password).digest("hex");
}

function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function signSessionPayload(payloadBase64: string): string {
  return createHmac("sha256", AUTH_SESSION_SECRET).update(payloadBase64).digest("base64url");
}

function createSessionToken(email: string): string {
  const now = Date.now();
  const payload: SessionPayload = {
    email,
    iat: now,
    exp: now + SESSION_MAX_AGE * 1000,
  };
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = signSessionPayload(payloadBase64);
  return `${payloadBase64}.${signature}`;
}

function verifySessionToken(token: string): Session | null {
  const [payloadBase64, providedSignature] = token.split(".");
  if (!payloadBase64 || !providedSignature) return null;

  const expectedSignature = signSessionPayload(payloadBase64);
  if (!secureCompare(providedSignature, expectedSignature)) return null;

  let payload: SessionPayload;
  try {
    payload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString("utf8")) as SessionPayload;
  } catch {
    return null;
  }

  if (!payload.email || !payload.iat || !payload.exp || payload.exp < Date.now()) {
    return null;
  }

  return {
    email: payload.email,
    createdAt: payload.iat,
    expiresAt: payload.exp,
  };
}

function parseCookies(cookieHeader: string | null | undefined): Record<string, string> {
  if (!cookieHeader) return {};
  const cookies: Record<string, string> = {};
  for (const pair of cookieHeader.split(";")) {
    const [key, ...rest] = pair.trim().split("=");
    if (key) cookies[key.trim()] = rest.join("=").trim();
  }
  return cookies;
}

function getClientIp(c: Context): string {
  return c.req.header("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
}

// ─── Public API ─────────────────────────────────────────────────────────────

export function getSessionFromCookie(cookieHeader: string | null | undefined): Session | null {
  const cookies = parseCookies(cookieHeader);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  return verifySessionToken(token);
}

export function isAuthenticated(cookieHeader: string | null | undefined): boolean {
  return getSessionFromCookie(cookieHeader) !== null;
}

export function createAuthRoutes(app: any): void {
  // Login page
  app.get("/login", (c: Context) => {
    // If already authenticated, redirect to app
    if (isAuthenticated(c.req.header("cookie"))) {
      return c.redirect("/");
    }
    c.header("Cache-Control", "no-store");
    c.header("Clear-Site-Data", "\"cache\", \"storage\"");
    return c.html(getLoginPageHtml());
  });

  // Login API
  app.post("/auth/login", async (c: Context) => {
    const ip = getClientIp(c);

    if (isRateLimited(ip)) {
      return c.json({ error: "Too many login attempts. Please wait 15 minutes." }, 429);
    }

    let body: { email?: string; password?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid request" }, 400);
    }

    const { email, password } = body;
    if (!email || !password) {
      return c.json({ error: "Email and password are required" }, 400);
    }

    const emailMatch = email.toLowerCase() === AUTH_EMAIL.toLowerCase();
    const passwordMatch = secureCompare(hashPassword(password), AUTH_PASSWORD_HASH);

    if (!emailMatch || !passwordMatch) {
      recordFailedAttempt(ip);
      return c.json({ error: "Invalid email or password" }, 401);
    }

    clearAttempts(ip);

    const sessionToken = createSessionToken(email.toLowerCase());
    const companionToken = getToken();
    c.header("Set-Cookie", `companion_auth=${companionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${365 * 24 * 60 * 60}`);
    c.header("Set-Cookie", `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`);
    return c.json({ ok: true, token: companionToken });
  });

  // Logout API
  app.post("/auth/logout", (c: Context) => {
    c.header("Cache-Control", "no-store");
    c.header("Clear-Site-Data", "\"cache\", \"storage\"");
    c.header("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    c.header("Set-Cookie", "companion_auth=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    return c.json({ ok: true });
  });

  // Auth status
  app.get("/auth/status", (c: Context) => {
    const session = getSessionFromCookie(c.req.header("cookie"));
    if (session) {
      return c.json({ authenticated: true, email: session.email });
    }
    return c.json({ authenticated: false }, 401);
  });
}

export function authMiddleware() {
  return async (c: Context, next: Next) => {
    const path = new URL(c.req.url).pathname;

    // Skip auth for login page and auth endpoints
    if (path === "/login" || path === "/sw.js" || path === "/manifest.json" || path.startsWith("/auth/")) {
      return next();
    }

    // Skip auth for CLI WebSocket connections (they're local only)
    if (path.startsWith("/ws/cli/")) {
      return next();
    }

    if (!isAuthenticated(c.req.header("cookie"))) {
      // For API/WS requests, return 401
      if (path.startsWith("/api/") || path.startsWith("/ws/")) {
        return c.json({ error: "Unauthorized" }, 401);
      }
      // For page requests, redirect to login
      return c.redirect("/login");
    }

    return next();
  };
}

// ─── Session cleanup interval ───────────────────────────────────────────────

setInterval(() => {
  const now = Date.now();
  for (const [ip, attempt] of loginAttempts) {
    if (now - attempt.lastAttempt > LOCKOUT_DURATION) loginAttempts.delete(ip);
  }
}, 60_000);

// ─── Login Page HTML ────────────────────────────────────────────────────────

function getLoginPageHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in - Neuron Spark Code</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: #F5F5F0;
      --fg: #1a1a18;
      --card: #FFFFFF;
      --primary: #ae5630;
      --primary-hover: #c4643a;
      --border: rgba(0,0,0,0.08);
      --muted: #B1ADA1;
      --error: #c53030;
      --error-bg: rgba(197,48,48,0.06);
      --input-bg: #FFFFFF;
      --input-border: rgba(0,0,0,0.12);
      --input-focus: #ae5630;
      --shadow: 0 1px 3px rgba(0,0,0,0.04), 0 8px 24px rgba(0,0,0,0.06);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #2b2a27;
        --fg: #eeeeee;
        --card: #1f1e1b;
        --border: rgba(255,255,255,0.08);
        --muted: #8a8780;
        --error: #fc8181;
        --error-bg: rgba(252,129,129,0.1);
        --input-bg: #252422;
        --input-border: rgba(255,255,255,0.12);
        --shadow: 0 1px 3px rgba(0,0,0,0.2), 0 8px 24px rgba(0,0,0,0.3);
      }
    }

    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--fg);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
      -webkit-font-smoothing: antialiased;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      animation: fadeIn 0.4s ease-out;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .login-header {
      text-align: center;
      margin-bottom: 2rem;
    }

    .login-logo {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 56px;
      height: 56px;
      border-radius: 16px;
      background: var(--primary);
      margin-bottom: 1.25rem;
      box-shadow: 0 2px 8px rgba(174,86,48,0.25);
    }

    .login-logo svg {
      width: 28px;
      height: 28px;
      color: white;
    }

    .login-title {
      font-size: 1.375rem;
      font-weight: 600;
      letter-spacing: -0.01em;
      margin-bottom: 0.375rem;
    }

    .login-subtitle {
      font-size: 0.875rem;
      color: var(--muted);
    }

    .login-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2rem;
      box-shadow: var(--shadow);
    }

    .form-group {
      margin-bottom: 1.25rem;
    }

    .form-label {
      display: block;
      font-size: 0.8125rem;
      font-weight: 500;
      margin-bottom: 0.5rem;
      color: var(--fg);
    }

    .form-input {
      width: 100%;
      padding: 0.625rem 0.875rem;
      font-size: 0.875rem;
      font-family: inherit;
      background: var(--input-bg);
      border: 1px solid var(--input-border);
      border-radius: 10px;
      color: var(--fg);
      outline: none;
      transition: border-color 0.15s, box-shadow 0.15s;
    }

    .form-input::placeholder {
      color: var(--muted);
    }

    .form-input:focus {
      border-color: var(--input-focus);
      box-shadow: 0 0 0 3px rgba(174,86,48,0.12);
    }

    .form-input.error {
      border-color: var(--error);
      box-shadow: 0 0 0 3px rgba(197,48,48,0.1);
    }

    .password-wrapper {
      position: relative;
    }

    .password-toggle {
      position: absolute;
      right: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      color: var(--muted);
      cursor: pointer;
      padding: 0.25rem;
      display: flex;
      align-items: center;
      transition: color 0.15s;
    }

    .password-toggle:hover {
      color: var(--fg);
    }

    .password-toggle svg {
      width: 18px;
      height: 18px;
    }

    .login-btn {
      width: 100%;
      padding: 0.75rem 1rem;
      font-size: 0.875rem;
      font-weight: 600;
      font-family: inherit;
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      transition: background 0.15s, transform 0.1s;
      margin-top: 0.5rem;
    }

    .login-btn:hover:not(:disabled) {
      background: var(--primary-hover);
    }

    .login-btn:active:not(:disabled) {
      transform: scale(0.985);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .login-btn.loading {
      position: relative;
      color: transparent;
    }

    .login-btn.loading::after {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      width: 18px;
      height: 18px;
      margin: -9px 0 0 -9px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .error-message {
      display: none;
      align-items: center;
      gap: 0.5rem;
      padding: 0.625rem 0.875rem;
      margin-bottom: 1.25rem;
      background: var(--error-bg);
      border: 1px solid rgba(197,48,48,0.15);
      border-radius: 10px;
      font-size: 0.8125rem;
      color: var(--error);
      animation: shake 0.3s ease-out;
    }

    .error-message.visible {
      display: flex;
    }

    .error-message svg {
      width: 16px;
      height: 16px;
      flex-shrink: 0;
    }

    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20% { transform: translateX(-4px); }
      40% { transform: translateX(4px); }
      60% { transform: translateX(-2px); }
      80% { transform: translateX(2px); }
    }

    .login-footer {
      text-align: center;
      margin-top: 1.5rem;
      font-size: 0.75rem;
      color: var(--muted);
    }

    .login-footer a {
      color: var(--primary);
      text-decoration: none;
    }

    .login-footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-header">
      <div class="login-logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="16 18 22 12 16 6"></polyline>
          <polyline points="8 6 2 12 8 18"></polyline>
        </svg>
      </div>
      <h1 class="login-title">Neuron Spark Code</h1>
      <p class="login-subtitle">Sign in to your workspace</p>
    </div>

    <div class="login-card">
      <div class="error-message" id="errorMsg">
        <svg viewBox="0 0 16 16" fill="currentColor">
          <path fill-rule="evenodd" d="M8 15A7 7 0 108 1a7 7 0 000 14zm1-3a1 1 0 11-2 0 1 1 0 012 0zM7.5 5.5a.5.5 0 011 0v3a.5.5 0 01-1 0v-3z" clip-rule="evenodd"/>
        </svg>
        <span id="errorText"></span>
      </div>

      <form id="loginForm" autocomplete="on">
        <div class="form-group">
          <label class="form-label" for="email">Email</label>
          <input
            class="form-input"
            type="email"
            id="email"
            name="email"
            placeholder="you@example.com"
            autocomplete="username"
            required
            autofocus
          >
        </div>

        <div class="form-group">
          <label class="form-label" for="password">Password</label>
          <div class="password-wrapper">
            <input
              class="form-input"
              type="password"
              id="password"
              name="password"
              placeholder="Enter your password"
              autocomplete="current-password"
              required
            >
            <button type="button" class="password-toggle" id="togglePassword" tabindex="-1" aria-label="Toggle password visibility">
              <svg id="eyeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                <circle cx="12" cy="12" r="3"></circle>
              </svg>
            </button>
          </div>
        </div>

        <button type="submit" class="login-btn" id="loginBtn">Sign in</button>
      </form>
    </div>

    <div class="login-footer">
      Powered by <a href="https://neuronspark.ai" target="_blank" rel="noopener">NeuronSpark</a>
    </div>
  </div>

  <script>
    (async () => {
      try {
        if ('serviceWorker' in navigator) {
          const registrations = await navigator.serviceWorker.getRegistrations();
          await Promise.all(registrations.map((registration) => registration.unregister()));
        }
        if (window.caches) {
          const cacheNames = await caches.keys();
          await Promise.all(cacheNames.map((cacheName) => caches.delete(cacheName)));
        }
      } catch {}

      try { localStorage.removeItem('companion_auth_token'); } catch {}
      try { sessionStorage.removeItem('companion_auth_token'); } catch {}
    })();

    const form = document.getElementById('loginForm');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const loginBtn = document.getElementById('loginBtn');
    const errorMsg = document.getElementById('errorMsg');
    const errorText = document.getElementById('errorText');
    const togglePassword = document.getElementById('togglePassword');

    let passwordVisible = false;

    togglePassword.addEventListener('click', () => {
      passwordVisible = !passwordVisible;
      passwordInput.type = passwordVisible ? 'text' : 'password';
      togglePassword.querySelector('svg').innerHTML = passwordVisible
        ? '<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>'
        : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
    });

    function showError(msg) {
      errorText.textContent = msg;
      errorMsg.classList.add('visible');
      emailInput.classList.add('error');
      passwordInput.classList.add('error');
    }

    function clearError() {
      errorMsg.classList.remove('visible');
      emailInput.classList.remove('error');
      passwordInput.classList.remove('error');
    }

    emailInput.addEventListener('input', clearError);
    passwordInput.addEventListener('input', clearError);

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearError();

      const email = emailInput.value.trim();
      const password = passwordInput.value;

      if (!email || !password) {
        showError('Please fill in all fields.');
        return;
      }

      loginBtn.disabled = true;
      loginBtn.classList.add('loading');

      try {
        const res = await fetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });

        const data = await res.json();

        if (res.ok) {
          if (data.token) {
            try { localStorage.setItem('companion_auth_token', data.token); } catch {}
          }
          window.location.href = '/';
        } else {
          showError(data.error || 'Login failed');
          passwordInput.value = '';
          passwordInput.focus();
        }
      } catch {
        showError('Connection error. Please try again.');
      } finally {
        loginBtn.disabled = false;
        loginBtn.classList.remove('loading');
      }
    });
  </script>
</body>
</html>`;
}
