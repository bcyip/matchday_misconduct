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
// CONFIRMED DEPLOYMENT CONSTRAINT: the SportsEngine app (client_id) used by
// this whole project allows only ONE registered redirect URI at a time - not
// one per app. Since matchday and the stat-tracking app only need a redirect
// URI occasionally (manually, in Postman, to refresh their shared token) but
// THIS app needs one live and reachable during real user logins, the ONE
// registered URI is set to THIS app's own /oauth/callback - and that same
// route doubles as a manual code-display page (like Postman's own testing
// callback) whenever it receives a request that isn't a real login attempt
// (detected via a state-mismatch - see below). This is why ADMIN_BASE_URL
// must be set to this app's actual public URL, and why that same URL is
// what should be entered as the redirect_uri when manually visiting the
// authorize URL for the other two apps' token refresh in Postman too.

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

    // If the state doesn't match, this wasn't initiated through our own
    // /oauth/login (e.g. someone visited the authorize URL directly, in
    // Postman, to manually get a code/token for the stat-tracking or
    // matchday apps - both of which use a manually-refreshed shared token
    // rather than live per-user login). Rather than reject this outright,
    // just display the code - the same role Postman's oauth.pstmn.io
    // testing page normally plays. This lets ONE registered redirect URI
    // (SportsEngine only allows one) serve both purposes: real admin
    // console logins, and manual token generation for the other two apps.
    if (!returnedState || returnedState !== expectedState) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`
        <!DOCTYPE html><html><body style="font-family: -apple-system, sans-serif; padding: 40px; max-width: 600px; margin: 0 auto;">
          <h2>Authorization Code</h2>
          <p>This wasn't a real admin console login attempt (no matching login session), so here's the raw code instead — for manually generating a token in Postman for the stat-tracking or matchday apps.</p>
          <p style="background:#f4f6fa; padding:14px; border-radius:8px; word-break:break-all; font-family:monospace;">${code}</p>
          <p style="color:#888; font-size:13px;">This code expires quickly — copy it and complete the token exchange in Postman right away.</p>
        </body></html>
      `);
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

  // GET /api/misconduct/teams — distinct team list, for populating the filter dropdown
  if (req.method === 'GET' && url.pathname === '/api/misconduct/teams') {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    try {
      const result = await pool.query(`
        SELECT DISTINCT team_id, team_name FROM match_report_entries
        WHERE event_type IN ('Yellow Card', 'Red Card')
        ORDER BY team_name
      `);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ teams: result.rows }));
    } catch (err) {
      console.error('[api/misconduct/teams] Error:', err.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // GET /api/misconduct — filtered, sorted misconduct list, joined with review status
  if (req.method === 'GET' && url.pathname === '/api/misconduct') {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    try {
      const includeYellow = url.searchParams.get('includeYellow') === 'true';
      const teamId = url.searchParams.get('teamId') || null;
      const playerName = url.searchParams.get('playerName') || null;
      const dateFrom = url.searchParams.get('dateFrom') || null;
      const dateTo = url.searchParams.get('dateTo') || null;

      const eventTypes = includeYellow ? ['Yellow Card', 'Red Card'] : ['Red Card'];

      const conditions = ['e.event_type = ANY($1)'];
      const params = [eventTypes];
      let paramIdx = 2;

      if (teamId) { conditions.push(`e.team_id = $${paramIdx++}`); params.push(teamId); }
      if (playerName) { conditions.push(`e.name ILIKE $${paramIdx++}`); params.push('%' + playerName + '%'); }
      if (dateFrom) { conditions.push(`s.game_date >= $${paramIdx++}`); params.push(dateFrom); }
      if (dateTo) { conditions.push(`s.game_date <= $${paramIdx++}`); params.push(dateTo); }

      const query = `
        SELECT
          e.id AS entry_id, e.game_id, e.team_id, e.team_name, e.person_type,
          e.profile_id, e.name, e.event_type, e.minute, e.reason, e.supplemental_report,
          s.game_date,
          r.status, r.committee_notes, r.reviewed_by, r.reviewed_at,
          sus.games_suspended, sus.standard_games
        FROM match_report_entries e
        LEFT JOIN match_report_scores s ON s.game_id = e.game_id
        LEFT JOIN misconduct_reviews r ON r.entry_id = e.id
        LEFT JOIN suspensions sus ON sus.entry_id = e.id
        WHERE ${conditions.join(' AND ')}
        ORDER BY s.game_date DESC NULLS LAST, e.minute DESC NULLS LAST
      `;

      const result = await pool.query(query, params);
      // No review row yet = implicitly 'pending' - reflect that in the response
      // rather than leaving status as null for the frontend to special-case.
      const rows = result.rows.map(row => ({ ...row, status: row.status || 'pending' }));

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ misconduct: rows }));
    } catch (err) {
      console.error('[api/misconduct] Error:', err.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // POST /api/misconduct/:entryId/review — update review status, notes, and
  // (if a suspension already exists for this entry) the current games
  // suspended. NEVER creates or deletes a suspension - matchday already
  // auto-created it at submission time, and it is never removed.
  const reviewMatch = url.pathname.match(/^\/api\/misconduct\/(\d+)\/review$/);
  if (req.method === 'POST' && reviewMatch) {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    const entryId = parseInt(reviewMatch[1], 10);

    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', async () => {
      let payload;
      try {
        payload = JSON.parse(body);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      }

      const { status, committeeNotes, gamesSuspended } = payload;
      const VALID_STATUSES = ['pending', 'reviewed'];
      if (!VALID_STATUSES.includes(status)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'status must be one of: ' + VALID_STATUSES.join(', ') }));
      }

      // gamesSuspended is only meaningful/settable if a suspension already
      // exists for this entry (i.e. it was a Red Card - Yellow Cards never
      // get one). If provided, it must be a non-negative integer (0 is
      // valid - e.g. a 1-game standard reduced to 0 on appeal).
      let parsedGames = null;
      if (gamesSuspended !== undefined && gamesSuspended !== null && gamesSuspended !== '') {
        parsedGames = parseInt(gamesSuspended, 10);
        if (!Number.isInteger(parsedGames) || parsedGames < 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Games Suspended must be a non-negative number.' }));
        }
      }

      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        const reviewResult = await client.query(
          `INSERT INTO misconduct_reviews (entry_id, status, committee_notes, reviewed_by, reviewed_at, updated_at)
           VALUES ($1, $2, $3, $4, now(), now())
           ON CONFLICT (entry_id) DO UPDATE SET
             status = EXCLUDED.status, committee_notes = EXCLUDED.committee_notes,
             reviewed_by = EXCLUDED.reviewed_by, reviewed_at = now(), updated_at = now()
           RETURNING id`,
          [entryId, status, committeeNotes || null, session.name]
        );
        const reviewId = reviewResult.rows[0].id;

        let suspensionUpdated = false;
        if (parsedGames !== null) {
          // UPDATE only - if no suspension row exists for this entry (e.g.
          // it's a Yellow Card, or something went wrong at submission),
          // this correctly affects 0 rows rather than creating one here.
          const updateResult = await client.query(
            `UPDATE suspensions SET games_suspended = $1, review_id = $2 WHERE entry_id = $3`,
            [parsedGames, reviewId, entryId]
          );
          suspensionUpdated = updateResult.rowCount > 0;
        }

        await client.query('COMMIT');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, suspensionUpdated, gamesSuspended: parsedGames }));
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('[api/misconduct/review POST] Error:', err.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      } finally {
        client.release();
      }
    });
    return;
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
