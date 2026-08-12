// USCCS Admin Console — misconduct review / sanction workflow.
//
// Unlike the other two apps in this project (stat-tracking, matchday),
// THIS app has real individual login - it's the only one exposing
// league-wide disciplinary data, so "no login, public link" (the model
// used everywhere else) is not an acceptable trust model here.
//
// Auth model: SportsEngine OAuth "User Authentication" - each admin logs
// in with their own real SportsEngine account. After login, we check their
// role_assignments for the org's "orgAdmin" composite role. No separate
// custom allowlist for now (deliberately deferred - see conversation).
//
// REQUIRED ENVIRONMENT VARIABLES:
//   SE_CLIENT_ID, SE_CLIENT_SECRET  - same SportsEngine app registration used elsewhere
//   SE_ORG_ID                      - org ID admins must have the orgAdmin role for (e.g. 356507)
//   ADMIN_BASE_URL                 - this app's own public URL, e.g. https://admin.onrender.com
//                                     (used to build the OAuth redirect_uri - must exactly match
//                                     what's sent on both the authorize and token-exchange steps)
//   DATABASE_URL                   - same Supabase/Postgres instance matchday uses
//   PORT                           - (optional) most hosts set this automatically
//
// DEPLOYMENT NOTE: SportsEngine's OAuth setup has only been confirmed working
// with Postman's testing redirect URI (oauth.pstmn.io) throughout this
// project so far. Whether an arbitrary custom redirect_uri (this app's real
// callback URL) is accepted without any additional registration on
// SportsEngine's side is UNCONFIRMED - test this early once deployed, before
// assuming the login flow will work in production.

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 8787;
const SE_CLIENT_ID = process.env.SE_CLIENT_ID;
const SE_CLIENT_SECRET = process.env.SE_CLIENT_SECRET;
const SE_ORG_ID = process.env.SE_ORG_ID;
const ADMIN_BASE_URL = process.env.ADMIN_BASE_URL;
const REDIRECT_URI = ADMIN_BASE_URL ? ADMIN_BASE_URL.replace(/\/$/, '') + '/oauth/callback' : null;

const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000; // 8 hours

// ---------- Postgres ----------

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('[postgres] Unexpected error on idle client:', err.message);
});

// ---------- Cookie helpers (manual - no new dependency) ----------

function parseCookies(req) {
  const header = req.headers.cookie;
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    cookies[key] = decodeURIComponent(val);
  });
  return cookies;
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push('Path=/');
  parts.push('HttpOnly');
  parts.push('SameSite=Lax');
  if (ADMIN_BASE_URL && ADMIN_BASE_URL.startsWith('https://')) parts.push('Secure');
  if (options.maxAgeSeconds != null) parts.push('Max-Age=' + options.maxAgeSeconds);
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name) {
  setCookie(res, name, '', { maxAgeSeconds: 0 });
}

// ---------- SportsEngine OAuth ----------

function exchangeCodeForToken(code) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      client_id: SE_CLIENT_ID,
      client_secret: SE_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: REDIRECT_URI,
    });
    const req = https.request(
      {
        hostname: 'user.sportsengine.com',
        path: '/oauth/token',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            if (!json.access_token) return reject(new Error('Token exchange failed: ' + data));
            resolve(json);
          } catch (e) {
            reject(new Error('Could not parse token response: ' + data));
          }
        });
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function fetchIdentity(accessToken) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: 'user.sportsengine.com',
        path: '/oauth/me',
        method: 'GET',
        headers: { Authorization: 'Bearer ' + accessToken },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error('Could not parse /oauth/me response: ' + data));
          }
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

/**
 * Checks whether the identity response's role_assignments includes the
 * org's "orgAdmin" composite role for our specific SE_ORG_ID. Per the
 * confirmed real response shape, multiple entries share role_key:'orgAdmin'
 * (bundled together) - finding any one of them is sufficient.
 */
function hasOrgAdminRole(identityResponse) {
  const assignments = identityResponse?.result?.user?.role_assignments || [];
  return assignments.some(
    (a) => String(a.org_id) === String(SE_ORG_ID) && a.role_key === 'orgAdmin'
  );
}

// ---------- Session management (Postgres-backed) ----------

async function createSession(identityResponse, seTokenExpiresAt) {
  const user = identityResponse.result.user;
  const sessionId = crypto.randomBytes(32).toString('hex');
  const email = (user.email_addresses || []).find((e) => e.is_primary)?.address || null;
  const name = (user.first_name + ' ' + user.last_name).trim();
  const sessionExpiresAt = new Date(Date.now() + SESSION_LIFETIME_MS);

  await pool.query(
    `INSERT INTO admin_sessions (session_id, se_user_id, name, email, access_token, se_token_expires_at, session_expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [sessionId, String(user.id), name, email, user.authentication.access_token, seTokenExpiresAt, sessionExpiresAt]
  );

  return sessionId;
}

async function getSession(sessionId) {
  if (!sessionId) return null;
  const result = await pool.query(
    'SELECT * FROM admin_sessions WHERE session_id = $1 AND session_expires_at > now()',
    [sessionId]
  );
  return result.rows[0] || null;
}

async function destroySession(sessionId) {
  if (!sessionId) return;
  await pool.query('DELETE FROM admin_sessions WHERE session_id = $1', [sessionId]);
}

// ---------- Server ----------

const HTML_FILE = path.join(__dirname, 'index.html');

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const cookies = parseCookies(req);

  // GET /oauth/login — start the flow, with a CSRF-protecting state param
  if (req.method === 'GET' && url.pathname === '/oauth/login') {
    if (!REDIRECT_URI) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      return res.end('ADMIN_BASE_URL is not configured on the server.');
    }
    const state = crypto.randomBytes(16).toString('hex');
    setCookie(res, 'oauth_state', state, { maxAgeSeconds: 600 }); // 10 min to complete login

    const authorizeUrl = 'https://user.sportsengine.com/oauth/authorize?' + new URLSearchParams({
      client_id: SE_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      state,
    }).toString();

    res.writeHead(302, { Location: authorizeUrl });
    return res.end();
  }

  // GET /oauth/callback — SportsEngine redirects here after login
  if (req.method === 'GET' && url.pathname === '/oauth/callback') {
    const code = url.searchParams.get('code');
    const returnedState = url.searchParams.get('state');
    const expectedState = cookies.oauth_state;
    clearCookie(res, 'oauth_state');

    if (!code) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      return res.end('Missing authorization code.');
    }
    if (!returnedState || returnedState !== expectedState) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('State mismatch - possible CSRF attempt, or your login session expired. Try logging in again.');
    }

    try {
      const tokenData = await exchangeCodeForToken(code);
      const seTokenExpiresAt = new Date(Date.now() + (tokenData.expires_in || 1800) * 1000);
      const identity = await fetchIdentity(tokenData.access_token);
      // Merge the actual access token into the shape hasOrgAdminRole/createSession expect
      identity.result.user.authentication.access_token = tokenData.access_token;

      if (!hasOrgAdminRole(identity)) {
        res.writeHead(403, { 'Content-Type': 'text/html' });
        return res.end('<h2>Not authorized</h2><p>Your SportsEngine account does not have admin access to this organization.</p>');
      }

      const sessionId = await createSession(identity, seTokenExpiresAt);
      setCookie(res, 'admin_session', sessionId, { maxAgeSeconds: SESSION_LIFETIME_MS / 1000 });
      res.writeHead(302, { Location: '/' });
      return res.end();
    } catch (err) {
      console.error('[oauth/callback] Error:', err.message);
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      return res.end('Login failed: ' + err.message);
    }
  }

  // GET /oauth/logout
  if (req.method === 'GET' && url.pathname === '/oauth/logout') {
    await destroySession(cookies.admin_session);
    clearCookie(res, 'admin_session');
    res.writeHead(302, { Location: '/oauth/login' });
    return res.end();
  }

  // GET /api/whoami — proves the whole login chain works end to end
  if (req.method === 'GET' && url.pathname === '/api/whoami') {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ name: session.name, email: session.email, seUserId: session.se_user_id }));
  }

  // GET / — the main page. Requires a valid session; redirects to login if not.
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(302, { Location: '/oauth/login' });
      return res.end();
    }
    fs.readFile(HTML_FILE, 'utf8', (err, data) => {
      if (err) {
        res.writeHead(404);
        return res.end('index.html not found — make sure it is in the same folder as server.js');
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, async () => {
  console.log(`Admin console server running on port ${PORT}`);
  if (!ADMIN_BASE_URL) {
    console.warn('WARNING: ADMIN_BASE_URL not set. OAuth login will not work until this is configured.');
  }
  if (!process.env.DATABASE_URL) {
    console.warn('WARNING: no DATABASE_URL set. Database calls will fail until this is configured.');
  } else {
    try {
      await pool.query('SELECT 1');
      console.log('[postgres] Connected successfully.');
    } catch (err) {
      console.error('[postgres] Connection test FAILED:', err.message);
    }
  }
});
