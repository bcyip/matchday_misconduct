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
// Separate, dedicated refresh token for this app's OWN direct SportsEngine
// data queries (fetching past games for the schedule cache below) - NOT
// the same token used by matchday or the schedule monitor. Per this
// project's established rule, an SE_REFRESH_TOKEN is never reused across
// apps. SE_CLIENT_ID/SE_CLIENT_SECRET above are still shared (same app
// registration), only the refresh token itself is unique to this app.
const SE_DATA_REFRESH_TOKEN = process.env.SE_DATA_REFRESH_TOKEN;
const SE_ORG_ID = process.env.SE_ORG_ID;
// The matchday app's own base URL - needed to call ITS retry-score-push
// endpoint from here, rather than duplicating SportsEngine credentials or
// GraphQL logic in this app too. Keeps the actual score-push logic living
// in exactly one place (matchday), which this just calls over HTTP.
const MATCHDAY_APP_URL = process.env.MATCHDAY_APP_URL;
const ADMIN_BASE_URL = process.env.ADMIN_BASE_URL;
const REDIRECT_URI = ADMIN_BASE_URL ? ADMIN_BASE_URL.replace(/\/$/, '') + '/oauth/callback' : null;

const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000; // 8 hours

// ---------- Postgres ----------

// Division ID -> friendly name lookup, same data maintained independently
// by the schedule monitor and stat-tracking app. Used here only to resolve
// a readable name for display/filtering on the match reports page -
// division_id itself (the raw SportsEngine ID) is what's actually stored.
const DIVISION_LOOKUP = {
  '6a4439745407815052443199': { name: 'AL/MS', gender: 'Men', conference: 'East' },
  '6a4439745407813fac44341f': { name: 'Baltimore', gender: 'Men', conference: 'East' },
  '6a0c980026aee381f43b3ef0': { name: 'Big Sky', gender: 'Men', conference: 'West' },
  '6a4e96e416115e0153c5de9d': { name: 'Crossroads', gender: 'Men' }, // conference unknown - not in the provided mapping, ask if this needs a conference
  '6a44397409f291d00804fde8': { name: 'Florida North', gender: 'Men', conference: 'East' },
  '6a4439744e42a26275c7ff31': { name: 'Florida South', gender: 'Men', conference: 'East' },
  '6a443974b5457c8f19bccbfc': { name: 'Georgia', gender: 'Men', conference: 'East' },
  '6a4e96e4c7769d01229fb5c6': { name: 'Great Lakes', gender: 'Men' }, // conference unknown
  '6a4e96e47d61ac00f01ad8b8': { name: 'Great Lakes II', gender: 'Men' }, // conference unknown
  '6a4e96e4801326012116f744': { name: 'Great Plains', gender: 'Men', conference: 'Central' }, // Midwest -> Central per instruction
  '6a4e96e46b8d1e00ef1ee690': { name: 'Heartland', gender: 'Men' }, // conference unknown
  '6a4e96e416115e0122c5e2c1': { name: 'Heartland II', gender: 'Men' }, // conference unknown
  '6a44397409f291e60904fdda': { name: 'Hudson Valley', gender: 'Men', conference: 'East' },
  '6a443974b5457c54e4bcd12d': { name: 'KY/TN', gender: 'Men', conference: 'East' },
  '6a0cb110cdb76433cc151485': { name: 'Midwest North', gender: 'Men', conference: 'Central' }, // Midwest -> Central per instruction
  '6a0e070026aee3f6e43b446f': { name: 'Midwest North II', gender: 'Men' }, // conference unknown - not in the provided mapping
  '6a0e0700cdb76416601513ae': { name: 'Midwest South', gender: 'Men', conference: 'Central' }, // Midwest -> Central per instruction
  '6a4e96e46b8d1e01201ee2ce': { name: 'Ozark', gender: 'Men' }, // conference unknown
  '6a44397409f29192050500f1': { name: 'NC East', gender: 'Men', conference: 'East' },
  '6a4439744e42a29553c7fe6c': { name: 'NC West', gender: 'Men', conference: 'East' },
  '6a4439743c1d137b18c8db12': { name: 'New England Central', gender: 'Men', conference: 'East' },
  '6a443974593ddf505e16a197': { name: 'New England North', gender: 'Men', conference: 'East' },
  '6a44397454078160b344310a': { name: 'New England South', gender: 'Men', conference: 'East' },
  '6a0c980026aee362b23b3f0e': { name: 'NorCal', gender: 'Men', conference: 'West' },
  '6a0c980004d6b0c7a8af73bd': { name: 'NorCal II', gender: 'Men', conference: 'West' },
  '6a0c980098c2fde79e7c20e8': { name: 'Northwest', gender: 'Men' }, // conference unknown (only listed for Women)
  '6a0e08bbf841cfba91996998': { name: 'Northwoods', gender: 'Men' }, // conference unknown
  '6a0e09e298c2fd5b067c22c4': { name: 'Northwoods II', gender: 'Men' }, // conference unknown
  '6a4439744e42a24ee3c80243': { name: 'NYC', gender: 'Men', conference: 'East' },
  '6a443974b5457c6597bccdad': { name: 'Philly', gender: 'Men', conference: 'East' },
  '6a0e08bb61444a4db0f2ef89': { name: 'Prairie', gender: 'Men' }, // conference unknown
  '6a4e96e48dabb800efcfbce9': { name: 'Red River', gender: 'Men' }, // conference unknown
  '6a4e96e48dabb80151cfb8bd': { name: 'Red River II', gender: 'Men' }, // conference unknown
  '6a4e96e4c7769d00f19fb81b': { name: 'Rocky Mountain', gender: 'Men', conference: 'Central' },
  '6a4e96e435cc6d00ef70bd6d': { name: 'Rocky Mountain II', gender: 'Men', conference: 'Central' },
  '6a4e96e4c7769d00bc9fbb3f': { name: 'Sabine River', gender: 'Men' }, // conference unknown
  '6a4e96e48dabb80120cfb96d': { name: 'Sabine River II', gender: 'Men' }, // conference unknown
  '6a0c980026aee3a5643b3edf': { name: 'SoCal', gender: 'Men', conference: 'West' },
  '6a0c980098c2fd32fc7c1d07': { name: 'SoCal II', gender: 'Men', conference: 'West' },
  '6a3ed52cf2a55d01e50c59e5': { name: 'SoCal III', gender: 'Men', conference: 'West' },
  '6a4e96e480132600f016f99d': { name: 'Southwest', gender: 'Men', conference: 'Central' },
  '6a4e96e4c7769d01539fb593': { name: 'Southwest II', gender: 'Men', conference: 'Central' },
  '6a0c9800bc500ed1f8da9d08': { name: 'Utah', gender: 'Men', conference: 'West' },
  '6a443974593ddf60ee169e3f': { name: 'Virginia', gender: 'Men', conference: 'East' },
  '6a44397409f291bc4904fe1b': { name: 'Washington DC', gender: 'Men', conference: 'East' }, // matches "DC" in the provided mapping
  '6a4446b9c3ff52e2d366a921': { name: 'DMV', gender: 'Women', conference: 'East' },
  '6a444639c3ff52b71466af8b': { name: 'FL', gender: 'Women', conference: 'East' }, // matches "Florida" in the provided mapping
  '6a0e0a64a70302e718b84569': { name: 'Midwest', gender: 'Women', conference: 'Central' }, // Midwest -> Central per instruction
  '6a0e0a6498c2fd83787c1db1': { name: 'Midwest II', gender: 'Women', conference: 'Central' }, // Midwest -> Central per instruction
  '6a46cdfc06f455aa0cc3badb': { name: 'New England', gender: 'Women', conference: 'East' },
  '6a0c982c61444a4e0cf2efa3': { name: 'NorCal', gender: 'Women', conference: 'West' },
  '6a0c982c61444a7966f2eb9a': { name: 'NorCal II', gender: 'Women', conference: 'West' },
  '6a0c982cf841cf9b0499667d': { name: 'Northwest', gender: 'Women', conference: 'West' },
  '6a0c982c98c2fd32fc7c1d0d': { name: 'Oregon II', gender: 'Women', conference: 'West' },
  '6a4e9b904b609600f0e70d42': { name: 'Ozark', gender: 'Women' }, // conference unknown
  '6a44470e99ca5a7f419d52d3': { name: 'Philly', gender: 'Women', conference: 'East' },
  '6a4e9b6a801326012116f792': { name: 'Rocky Mountain', gender: 'Women', conference: 'Central' },
  '6a4e9b6a4b60960121e70967': { name: 'Rocky Mountain II', gender: 'Women', conference: 'Central' },
  '6a0c982c98c2fd79027c1c4f': { name: 'SoCal', gender: 'Women', conference: 'West' },
  '6a0c982c8a5826dcee7f909e': { name: 'SoCal II', gender: 'Women', conference: 'West' },
  '6a4e9b6a80132600f016fa7f': { name: 'Southwest', gender: 'Women', conference: 'Central' },
  // Not yet in this table at all - no SportsEngine division_id known for
  // these three, mentioned in the provided conference mapping but never
  // seen in any team/division export so far:
  //   Oregon (Men, West Conference)
  //   Washington (Men, West Conference) - distinct from "Washington DC" above
  //   West Divide (Women, Central Conference)
};

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
 * Checks whether the identity response's role_assignments includes org
 * admin access for our specific SE_ORG_ID. SportsEngine's API uses
 * DIFFERENT fields depending on role_type: a role_type of "SimpleRole"
 * populates `role` (e.g. "org_admin", snake_case) with `role_key` left
 * null, while the originally-confirmed shape had `role_key` populated
 * directly (e.g. "orgAdmin", camelCase) - both are checked here so
 * either shape is recognized correctly.
 */
function hasOrgAdminRole(identityResponse) {
  const assignments = identityResponse?.result?.user?.role_assignments || [];
  return assignments.some(
    (a) => String(a.org_id) === String(SE_ORG_ID) && (a.role_key === 'orgAdmin' || a.role === 'org_admin')
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

// ---------- SportsEngine data fetching (this app's OWN direct queries -
// separate from the SSO login flow above, and from the schedule monitor)
// ----------

let seDataTokenCache = { accessToken: null, expiresAt: 0 };

function refreshSeDataAccessToken() {
  return new Promise((resolve, reject) => {
    if (!SE_CLIENT_ID || !SE_CLIENT_SECRET || !SE_DATA_REFRESH_TOKEN) {
      return reject(new Error('Missing SE_CLIENT_ID / SE_CLIENT_SECRET / SE_DATA_REFRESH_TOKEN environment variables.'));
    }
    const body = JSON.stringify({
      client_id: SE_CLIENT_ID,
      client_secret: SE_CLIENT_SECRET,
      refresh_token: SE_DATA_REFRESH_TOKEN,
      grant_type: 'refresh_token',
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
            if (!json.access_token) return reject(new Error('Token refresh failed: ' + data));
            seDataTokenCache.accessToken = json.access_token;
            seDataTokenCache.expiresAt = Date.now() + (json.expires_in || 1800) * 1000 - 60000;
            resolve(seDataTokenCache.accessToken);
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

async function getValidSeDataAccessToken() {
  if (seDataTokenCache.accessToken && Date.now() < seDataTokenCache.expiresAt) return seDataTokenCache.accessToken;
  return refreshSeDataAccessToken();
}

async function callSeGraphQL(query, variables) {
  const token = await getValidSeDataAccessToken();
  const body = JSON.stringify({ query, variables });
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: 'api.sportsengine.com',
        path: '/graphql',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), Authorization: 'Bearer ' + token },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            if (json.errors) return reject(new Error('GraphQL error: ' + JSON.stringify(json.errors)));
            resolve(json.data);
          } catch (e) {
            reject(new Error('Non-JSON response from SportsEngine: ' + data.slice(0, 300)));
          }
        });
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function seSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Same retry/backoff shape as the schedule monitor's proven implementation
// - a 4-day past-games window is small, but transient 502s/rate limits can
// still hit any individual page fetch.
async function callSeGraphQLWithRetry(query, variables, maxAttempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await callSeGraphQL(query, variables);
    } catch (err) {
      lastError = err;
      console.warn(`[sync-schedule] Page fetch attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
      if (attempt < maxAttempts) {
        const isRateLimit = /rate limit|too many requests/i.test(err.message);
        const backoffMs = isRateLimit ? attempt * 20000 : attempt * 3000;
        await seSleep(backoffMs);
      }
    }
  }
  throw lastError;
}

const SE_EVENTS_QUERY = `
  query Events($orgId: Int!, $from: UTCDateTime!, $to: UTCDateTime!, $page: Int!, $perPage: Int!) {
    events(organizationId: $orgId, from: $from, to: $to, calendarEventType: GAME, page: $page, perPage: $perPage) {
      results {
        id
        eventTeams { name score team { id program { primaryName } divisionId } homeTeam }
        start
        subvenue { name venueId venueName }
        subvenueId
        updated
        created
        gameStatus
      }
      pageInformation { count page pages }
    }
  }`;

function deriveGenderFromProgramName(primaryName) {
  if (!primaryName) return null;
  const lower = primaryName.toLowerCase();
  if (lower.includes('women')) return 'Women';
  if (lower.includes('men')) return 'Men';
  return null;
}

function extractGameInfo(event) {
  const teams = event.eventTeams || [];
  const home = teams.find((t) => t.homeTeam === true);
  const away = teams.find((t) => t.homeTeam === false);
  const subvenue = event.subvenue || {};
  const locationName = [subvenue.venueName, subvenue.name].filter(Boolean).join(' - ') || null;

  const divisionId = (home && home.team && home.team.divisionId) || (away && away.team && away.team.divisionId) || null;
  const divisionInfo = divisionId ? DIVISION_LOOKUP[divisionId] : null;

  const programName = (home && home.team && home.team.program && home.team.program.primaryName)
    || (away && away.team && away.team.program && away.team.program.primaryName) || null;
  const gender = deriveGenderFromProgramName(programName) || (divisionInfo && divisionInfo.gender) || null;

  return {
    eventId: event.id,
    startTime: event.start || null,
    locationName,
    homeTeam: (home && home.name) || null,
    awayTeam: (away && away.name) || null,
    homeTeamId: (home && home.team && home.team.id) || null,
    awayTeamId: (away && away.team && away.team.id) || null,
    divisionId,
    divisionName: (divisionInfo && divisionInfo.name) || null,
    gender,
    gameStatus: event.gameStatus || null,
    seHomeScore: (home && home.score) || null,
    seAwayScore: (away && away.score) || null,
  };
}

/**
 * Fetches games directly from SportsEngine for the given range, paginated.
 * Deliberately simpler than the schedule monitor's fetchFullSchedule - this
 * app only ever fetches a short PAST window (default 4 days), so there's
 * no season-long pagination concern, but the same retry/dedup safeguards
 * are kept since any individual page can still hit a transient failure.
 */
/**
 * Returns the UTC instant corresponding to 23:59:59 Eastern time on
 * "today" (Eastern's calendar day, not the server's or UTC's) - so a game
 * scheduled for later today still counts as "not yet past" only relative
 * to the exact moment, while still being includable as "today's game" for
 * sync/display purposes. Handles EDT/EST automatically via Intl.
 */
/**
 * Converts a 'YYYY-MM-DD' string (as entered in a date input, meant as an
 * EASTERN calendar date) into the correct UTC instants for the start and
 * end of that day in Eastern time. Naively parsing 'YYYY-MM-DDT23:59:59'
 * treats it as UTC, not Eastern - which silently excludes any evening
 * game (Eastern's day boundary is hours off from UTC's). Handles
 * EDT/EST automatically.
 */
function getEasternDayBounds(dateStr) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const probe = new Date(Date.UTC(y, m - 1, d, 12, 0, 0)); // noon UTC - safely mid-day regardless of offset, just for reading the offset
  const offsetParts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York', timeZoneName: 'shortOffset'
  }).formatToParts(probe);
  const offsetHours = parseInt(offsetParts.find(p => p.type === 'timeZoneName').value.replace('GMT', ''), 10);
  const start = new Date(Date.UTC(y, m - 1, d, 0, 0, 0) - offsetHours * 60 * 60 * 1000);
  const end = new Date(Date.UTC(y, m - 1, d + 1, 0, 0, 0) - offsetHours * 60 * 60 * 1000 - 1000);
  return { start, end };
}

function getEndOfTodayEastern(now) {
  const easternDateStr = now.toLocaleDateString('en-CA', { timeZone: 'America/New_York' });
  return getEasternDayBounds(easternDateStr).end;
}

async function fetchGamesInRange(from, to) {
  let allEvents = [];
  let page = 1;
  let totalPages = 1;
  const PER_PAGE = 40; // same conservative value as the schedule monitor - 100/page hits SportsEngine's complexity limit
  const PAGE_DELAY_MS = 1500;

  console.log(`[sync-schedule] Fetching games from ${from} to ${to}...`);

  do {
    const data = await callSeGraphQLWithRetry(SE_EVENTS_QUERY, { orgId: parseInt(SE_ORG_ID, 10), from, to, page, perPage: PER_PAGE });
    const pageResults = (data.events && data.events.results) || [];
    const reportedCount = (data.events && data.events.pageInformation && data.events.pageInformation.count) || null;
    totalPages = (data.events && data.events.pageInformation && data.events.pageInformation.pages) || 1;
    console.log(`[sync-schedule] Page ${page}/${totalPages}: got ${pageResults.length} events (SportsEngine reports total count: ${reportedCount})`);
    allEvents = allEvents.concat(pageResults);
    page++;
    if (page <= totalPages) await seSleep(PAGE_DELAY_MS);
  } while (page <= totalPages);

  console.log(`[sync-schedule] Fetched ${allEvents.length} total events across all pages before dedup.`);

  // Dedup by event ID - same pagination-drift safeguard used elsewhere in
  // this project.
  const seenIds = new Set();
  const deduped = [];
  for (const event of allEvents) {
    if (seenIds.has(event.id)) continue;
    seenIds.add(event.id);
    deduped.push(event);
  }

  console.log(`[sync-schedule] ${deduped.length} unique events after dedup (from ${allEvents.length} raw).`);
  return deduped.map(extractGameInfo);
}



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

  // GET /api/match-reports/filter-options — distinct divisions and teams
  // currently present in match_report_scores, for populating filter
  // dropdowns. Divisions only reflect reports submitted after the
  // division-capture feature was added - older reports have division_id
  // NULL and won't appear here (not backfilled).
  if (req.method === 'GET' && url.pathname === '/api/match-reports/filter-options') {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    try {
      const [divisionsResult, teamsResult] = await Promise.all([
        pool.query(`SELECT DISTINCT division_id FROM match_report_scores WHERE division_id IS NOT NULL ORDER BY division_id`),
        pool.query(`
          SELECT DISTINCT team_id, team_name FROM (
            SELECT team1_id AS team_id, team1_name AS team_name FROM match_report_scores
            UNION
            SELECT team2_id AS team_id, team2_name AS team_name FROM match_report_scores
          ) t ORDER BY team_name
        `),
      ]);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const divisions = divisionsResult.rows.map(d => ({
        division_id: d.division_id,
        division_name: (DIVISION_LOOKUP[d.division_id] && DIVISION_LOOKUP[d.division_id].name) || d.division_id,
        gender: (DIVISION_LOOKUP[d.division_id] && DIVISION_LOOKUP[d.division_id].gender) || null,
      })).sort((a, b) => a.division_name.localeCompare(b.division_name) || (a.gender || '').localeCompare(b.gender || ''));
      res.end(JSON.stringify({ divisions, teams: teamsResult.rows }));
    } catch (err) {
      console.error('[api/match-reports/filter-options] Error:', err.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // GET /api/match-reports?division=&dateFrom=&dateTo=&team=&gender= —
  // unified list of PAST games: reads from our own local
  // schedule_games_cache (populated only by the explicit "Sync Historical
  // Games" button below, never automatically) and merges in our own
  // submitted report data where it exists. A game with no report yet
  // still appears, with score/YC/RC/incident_report left blank - this is
  // deliberately the ONE view for this page now, not a separate toggle
  // (see conversation).
  // POST /api/match-reports/sync-schedule — fetches PAST games directly
  // from SportsEngine (this app's own credentials, decoupled from the
  // schedule monitor entirely) and upserts them into our local cache, so
  // the main list below can read from our own database instead of a live
  // fetch on every load. Only runs when this button is explicitly
  // clicked - never automatically, and never as a side effect of the
  // schedule monitor's own separate polling.
  if (req.method === 'POST' && url.pathname === '/api/match-reports/sync-schedule') {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', async () => {
      let payload = {};
      try {
        if (body) payload = JSON.parse(body);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      }
      try {
        const now = new Date();
        // End of TODAY in Eastern time (not just "right now") - so a game
        // scheduled for later today still gets synced, while games on
        // future days remain excluded.
        const endOfTodayEastern = getEndOfTodayEastern(now);

        // Default: last 4 days, as specifically requested - a deliberate,
        // manually-triggered sync, not a wide historical backfill.
        const defaultFrom = new Date(now.getTime() - 4 * 24 * 60 * 60 * 1000);
        const rangeFrom = payload.dateFrom ? getEasternDayBounds(payload.dateFrom).start : defaultFrom;
        const rangeToRaw = payload.dateTo ? getEasternDayBounds(payload.dateTo).end : now;
        const rangeTo = rangeToRaw < endOfTodayEastern ? rangeToRaw : endOfTodayEastern; // never sync PAST today (Eastern), but allow all of today

        const games = await fetchGamesInRange(rangeFrom.toISOString(), rangeTo.toISOString());

        // Only games through the end of TODAY (Eastern) get cached, even if
        // the requested range somehow included later dates - this cache is
        // specifically for history, but "today" counts as history even if
        // a specific game later today hasn't kicked off yet.
        const pastGames = games.filter(g => g.startTime && new Date(g.startTime) <= endOfTodayEastern);

        let syncedCount = 0;
        const gamesWithSeScore = [];
        for (const g of pastGames) {
          await pool.query(
            `INSERT INTO schedule_games_cache (game_id, start_time, division_id, gender, location_name, home_team, home_team_id, away_team, away_team_id, game_status, se_home_score, se_away_score, synced_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
             ON CONFLICT (game_id) DO UPDATE SET
               start_time = EXCLUDED.start_time, division_id = EXCLUDED.division_id, gender = EXCLUDED.gender,
               location_name = EXCLUDED.location_name, home_team = EXCLUDED.home_team, home_team_id = EXCLUDED.home_team_id,
               away_team = EXCLUDED.away_team, away_team_id = EXCLUDED.away_team_id, game_status = EXCLUDED.game_status,
               se_home_score = EXCLUDED.se_home_score, se_away_score = EXCLUDED.se_away_score,
               synced_at = now()`,
            [g.eventId, g.startTime, g.divisionId, g.gender, g.locationName, g.homeTeam, g.homeTeamId, g.awayTeam, g.awayTeamId, g.gameStatus, g.seHomeScore, g.seAwayScore]
          );
          syncedCount++;
          // SportsEngine itself has a score filled in - a strong signal a
          // report was received through some other channel (someone
          // entered it directly into SportsEngine, bypassing matchday).
          if (g.seHomeScore != null && g.seHomeScore !== '' && g.seAwayScore != null && g.seAwayScore !== '') {
            gamesWithSeScore.push(g.eventId);
          }
        }

        // Auto-flag "MO report received" for games with an SE score, but
        // only if our OWN system doesn't already have a real report for
        // it - a real report always takes priority and displays as it
        // does now, per the explicit requirement.
        let autoFlaggedCount = 0;
        if (gamesWithSeScore.length > 0) {
          const existingReportsResult = await pool.query(
            'SELECT game_id FROM match_report_scores WHERE game_id = ANY($1)',
            [gamesWithSeScore]
          );
          const alreadyHasRealReport = new Set(existingReportsResult.rows.map(r => r.game_id));
          const toAutoFlag = gamesWithSeScore.filter(id => !alreadyHasRealReport.has(id));
          for (const gameId of toAutoFlag) {
            const result = await pool.query(
              `INSERT INTO external_report_flags (game_id, flagged_by)
               VALUES ($1, $2)
               ON CONFLICT (game_id) DO NOTHING`,
              [gameId, 'auto-detected (SE score present)']
            );
            if (result.rowCount > 0) autoFlaggedCount++;
          }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, syncedCount, autoFlaggedCount, rangeFrom: rangeFrom.toISOString(), rangeTo: rangeTo.toISOString() }));
      } catch (err) {
        console.error('[api/match-reports sync-schedule] Error:', err.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/match-reports') {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    try {
      const divisionParam = url.searchParams.get('division');
      const divisions = divisionParam ? divisionParam.split(',').filter(Boolean) : [];
      const conferenceParam = url.searchParams.get('conference');
      const conferences = conferenceParam ? conferenceParam.split(',').filter(Boolean) : [];
      const team = url.searchParams.get('team');
      const gender = url.searchParams.get('gender');
      const dateFromParam = url.searchParams.get('dateFrom');
      const dateToParam = url.searchParams.get('dateTo');

      // Default to the last 30 days through today (Eastern) if no range
      // given - a full-season fetch on every page load would be
      // needlessly heavy.
      const now = new Date();
      const endOfTodayEastern = getEndOfTodayEastern(now);
      const defaultFrom = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      const rangeFrom = dateFromParam ? getEasternDayBounds(dateFromParam).start : defaultFrom;
      // Never look past the end of today (Eastern) - this view is
      // specifically PAST games, but "today" counts even before its last
      // game has kicked off. This only affects what's shown from the
      // already-synced cache - it never triggers a new SportsEngine fetch,
      // which only ever happens via the manual sync button below.
      const rangeToRaw = dateToParam ? getEasternDayBounds(dateToParam).end : now;
      const rangeTo = rangeToRaw < endOfTodayEastern ? rangeToRaw : endOfTodayEastern;

      // Existing submitted-report data for this range, keyed by game_id
      // for easy merging below. Same query/shape as before.
      const reportConditions = ['mrs.game_date >= $1', 'mrs.game_date <= $2'];
      const reportParams = [rangeFrom.toISOString(), rangeTo.toISOString()];
      const reportResult = await pool.query(`
        SELECT
          mrs.game_id, mrs.game_date, mrs.division_id, mrs.gender, mrs.incident_report,
          mrs.team1_id, mrs.team1_name, mrs.team1_score,
          mrs.team2_id, mrs.team2_name, mrs.team2_score,
          mrs.submitted_at,
          COALESCE(t1.yellow_count, 0) AS team1_yellow_count,
          COALESCE(t1.red_count, 0) AS team1_red_count,
          COALESCE(t2.yellow_count, 0) AS team2_yellow_count,
          COALESCE(t2.red_count, 0) AS team2_red_count
        FROM match_report_scores mrs
        LEFT JOIN (
          SELECT game_id, team_id,
            COUNT(*) FILTER (WHERE event_type = 'Yellow Card') AS yellow_count,
            COUNT(*) FILTER (WHERE event_type = 'Red Card') AS red_count
          FROM match_report_entries GROUP BY game_id, team_id
        ) t1 ON t1.game_id = mrs.game_id AND t1.team_id = mrs.team1_id
        LEFT JOIN (
          SELECT game_id, team_id,
            COUNT(*) FILTER (WHERE event_type = 'Yellow Card') AS yellow_count,
            COUNT(*) FILTER (WHERE event_type = 'Red Card') AS red_count
          FROM match_report_entries GROUP BY game_id, team_id
        ) t2 ON t2.game_id = mrs.game_id AND t2.team_id = mrs.team2_id
        WHERE ${reportConditions.join(' AND ')}
      `, reportParams);
      const reportByGameId = new Map(reportResult.rows.map(r => [r.game_id, r]));

      const [flaggedResult, forfeitResult] = await Promise.all([
        pool.query('SELECT game_id FROM external_report_flags'),
        pool.query('SELECT game_id, reason, referee_paid FROM forfeit_flags'),
      ]);
      const forfeitInfoByGameId = new Map(forfeitResult.rows.map(r => [r.game_id, { reason: r.reason, referee_paid: r.referee_paid }]));
      const flaggedIds = new Set(flaggedResult.rows.map(r => r.game_id));

      let mergedRows;

      // Read from our own local cache instead of live-fetching the
      // schedule monitor on every load - the cache is only ever populated
      // by the explicit "Sync Historical Games" button (see sync-schedule
      // endpoint above), never automatically here.
      const cacheResult = await pool.query(
        'SELECT * FROM schedule_games_cache WHERE start_time >= $1 AND start_time <= $2',
        [rangeFrom.toISOString(), rangeTo.toISOString()]
      );
      // SportsEngine's own score, kept SEPARATE from our own report score
      // deliberately - never merged into team1_score/team2_score, so the
      // two sources are never confused with each other on display.
      const seScoreByGameId = new Map(cacheResult.rows.map(g => [g.game_id, { seHomeScore: g.se_home_score, seAwayScore: g.se_away_score }]));

      mergedRows = cacheResult.rows.map(g => {
        const existing = reportByGameId.get(g.game_id);
        if (existing) return existing; // real submitted report - use it as-is

        // No report yet - build a stub row from cached schedule data, with
        // score/YC/RC/incident_report all left blank (null).
        return {
          game_id: g.game_id,
          game_date: g.start_time,
          division_id: g.division_id,
          gender: g.gender,
          incident_report: null,
          team1_id: g.home_team_id,
          team1_name: g.home_team,
          team1_score: null,
          team2_id: g.away_team_id,
          team2_name: g.away_team,
          team2_score: null,
          submitted_at: null,
          team1_yellow_count: null,
          team1_red_count: null,
          team2_yellow_count: null,
          team2_red_count: null,
        };
      });

      // Any report whose game_id isn't in the cache yet (e.g. a game
      // outside the synced range) still gets included - never silently
      // drop a real report just because its schedule entry isn't cached.
      const mergedIds = new Set(mergedRows.map(r => r.game_id));
      for (const r of reportResult.rows) {
        if (!mergedIds.has(r.game_id)) mergedRows.push(r);
      }

      // Apply the same filters to the merged set, regardless of whether a
      // report exists for a given game.
      if (divisions.length > 0) mergedRows = mergedRows.filter(r => divisions.includes(r.division_id));
      if (conferences.length > 0) mergedRows = mergedRows.filter(r => {
        const info = r.division_id ? DIVISION_LOOKUP[r.division_id] : null;
        return info && conferences.includes(info.conference);
      });
      if (gender) mergedRows = mergedRows.filter(r => r.gender === gender);
      if (team) mergedRows = mergedRows.filter(r => r.team1_id === team || r.team2_id === team);

      mergedRows.sort((a, b) => {
        const dateA = a.game_date ? new Date(a.game_date).getTime() : -Infinity;
        const dateB = b.game_date ? new Date(b.game_date).getTime() : -Infinity;
        return dateB - dateA;
      });

      let reports = mergedRows.map(r => {
        const forfeitInfo = forfeitInfoByGameId.get(r.game_id) || null;
        const forfeitReason = forfeitInfo ? forfeitInfo.reason : null;
        const isForfeit = forfeitReason != null;
        return {
          ...r,
          division_name: r.division_id ? ((DIVISION_LOOKUP[r.division_id] && DIVISION_LOOKUP[r.division_id].name) || r.division_id) : null,
          flagged_external: flaggedIds.has(r.game_id),
          is_forfeit: isForfeit,
          forfeit_reason: forfeitReason, // 'forfeit' | 'postponed' | 'rainout' | null
          referee_paid: forfeitInfo ? forfeitInfo.referee_paid : null, // true | false | null (undecided)
          // SportsEngine's own score - kept SEPARATE from our own report
          // score (team1_score/team2_score above) deliberately. Only
          // available for games that have actually been synced.
          se_home_score: (seScoreByGameId.get(r.game_id) || {}).seHomeScore || null,
          se_away_score: (seScoreByGameId.get(r.game_id) || {}).seAwayScore || null,
          // A forfeit/postponed/rainout counts as "entered" even with no
          // real score data - there's nothing more to report for it.
          has_report: r.team1_score != null || r.team2_score != null || isForfeit,
        };
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ reports }));
    } catch (err) {
      console.error('[api/match-reports] Error:', err.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // POST /api/match-reports/:gameId/push-score — calls matchday's OWN
  // retry-score-push endpoint over HTTP, rather than duplicating
  // SportsEngine credentials or the GraphQL updateScore logic here too.
  // Requires MATCHDAY_APP_URL to be configured.
  // POST /api/match-reports/:gameId/flag-external — toggle whether a
  // report is known to have been received through some OTHER system, but
  // not yet entered here. Body: { flagged: true|false }.
  const flagExternalMatch = url.pathname.match(/^\/api\/match-reports\/([^/]+)\/flag-external$/);
  if (req.method === 'POST' && flagExternalMatch) {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    const gameId = decodeURIComponent(flagExternalMatch[1]);
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
      try {
        if (payload.flagged) {
          await pool.query(
            `INSERT INTO external_report_flags (game_id, flagged_by)
             VALUES ($1, $2)
             ON CONFLICT (game_id) DO NOTHING`,
            [gameId, session.name || null]
          );
        } else {
          await pool.query('DELETE FROM external_report_flags WHERE game_id = $1', [gameId]);
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        console.error('[api/match-reports flag-external] Error:', err.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // POST /api/match-reports/:gameId/flag-forfeit — mark a game as a
  // forfeit. No real match report will ever exist for it, but it should
  // be counted as "entered"/resolved rather than perpetually showing as
  // missing. Body: { forfeit: true|false }.
  const flagForfeitMatch = url.pathname.match(/^\/api\/match-reports\/([^/]+)\/flag-forfeit$/);
  if (req.method === 'POST' && flagForfeitMatch) {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    const gameId = decodeURIComponent(flagForfeitMatch[1]);
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
      try {
        const ALLOWED_REASONS = ['forfeit', 'postponed', 'rainout'];
        if (payload.reason) {
          if (!ALLOWED_REASONS.includes(payload.reason)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'reason must be one of: ' + ALLOWED_REASONS.join(', ') }));
          }
          await pool.query(
            `INSERT INTO forfeit_flags (game_id, reason, flagged_by, flagged_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (game_id) DO UPDATE SET reason = EXCLUDED.reason, flagged_by = EXCLUDED.flagged_by, flagged_at = now()`,
            [gameId, payload.reason, session.name || null]
          );
        } else {
          await pool.query('DELETE FROM forfeit_flags WHERE game_id = $1', [gameId]);
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        console.error('[api/match-reports flag-forfeit] Error:', err.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // POST /api/match-reports/:gameId/set-referee-paid — independent of the
  // forfeit/postponed/rainout reason itself, since a pay decision can
  // come at a different time. Body: { refereePaid: true|false|null }.
  // Only updates a row that already exists (a reason must already be set)
  // - referee pay status is meaningless without one.
  const setRefereePaidMatch = url.pathname.match(/^\/api\/match-reports\/([^/]+)\/set-referee-paid$/);
  if (req.method === 'POST' && setRefereePaidMatch) {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    const gameId = decodeURIComponent(setRefereePaidMatch[1]);
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
      try {
        const refereePaid = payload.refereePaid === true ? true : payload.refereePaid === false ? false : null;
        const result = await pool.query(
          'UPDATE forfeit_flags SET referee_paid = $1 WHERE game_id = $2',
          [refereePaid, gameId]
        );
        if (result.rowCount === 0) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'No forfeit/postponed/rainout reason set for this game yet.' }));
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        console.error('[api/match-reports set-referee-paid] Error:', err.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  const pushScoreMatch = url.pathname.match(/^\/api\/match-reports\/([^/]+)\/push-score$/);
  if (req.method === 'POST' && pushScoreMatch) {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    if (!MATCHDAY_APP_URL) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'MATCHDAY_APP_URL is not configured on this app.' }));
    }
    const gameId = decodeURIComponent(pushScoreMatch[1]);
    try {
      const matchdayUrl = new URL('/api/match-report/' + encodeURIComponent(gameId) + '/retry-score-push', MATCHDAY_APP_URL);
      const result = await new Promise((resolve, reject) => {
        const req2 = https.request(
          { hostname: matchdayUrl.hostname, path: matchdayUrl.pathname, method: 'POST' },
          (res2) => {
            let data = '';
            res2.on('data', (chunk) => (data += chunk));
            res2.on('end', () => {
              try { resolve(JSON.parse(data)); }
              catch (e) { reject(new Error('Non-JSON response from matchday: ' + data.slice(0, 200))); }
            });
          }
        );
        req2.on('error', reject);
        req2.setTimeout(15000, () => { req2.destroy(); reject(new Error('Timed out waiting for matchday to respond (15s).')); });
        req2.end();
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (err) {
      console.error('[api/match-reports push-score] Error:', err.message);
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
      const includeRed = url.searchParams.get('includeRed') !== 'false'; // default true
      const includeYellow = url.searchParams.get('includeYellow') === 'true'; // default false
      const includeIncidentReports = url.searchParams.get('includeIncidentReports') !== 'false'; // default true
      const teamId = url.searchParams.get('teamId') || null;
      const playerName = url.searchParams.get('playerName') || null;
      const dateFrom = url.searchParams.get('dateFrom') || null;
      const dateTo = url.searchParams.get('dateTo') || null;

      const eventTypes = [];
      if (includeRed) eventTypes.push('Red Card');
      if (includeYellow) eventTypes.push('Yellow Card');

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
          sus.games_suspended, sus.standard_games,
          LEAST(
            (SELECT COUNT(*) FROM match_report_scores mrs2
             WHERE (mrs2.team1_id = sus.team_id OR mrs2.team2_id = sus.team_id)
             AND mrs2.game_date > sus.issued_from_game_date
             AND mrs2.game_date < now()),
            COALESCE(sus.games_suspended, sus.standard_games)
          ) AS games_served,
          NULL AS incident_report
        FROM match_report_entries e
        LEFT JOIN match_report_scores s ON s.game_id = e.game_id
        LEFT JOIN misconduct_reviews r ON r.entry_id = e.id
        LEFT JOIN suspensions sus ON sus.entry_id = e.id
        WHERE ${conditions.join(' AND ')}
        ORDER BY s.game_date DESC NULLS LAST, e.minute DESC NULLS LAST
      `;

      // Incident reports are a separate, synthetic row type - not from
      // match_report_entries at all, since they're per-GAME, not tied to
      // one specific player/team. Shaped to fit the same column structure
      // as above so the frontend can render both without special-casing.
      // Only the date filters apply (a report isn't tied to one team or
      // player). Gated by its own includeIncidentReports toggle, independent
      // of includeRed/includeYellow.
      const incidentConditions = ['s.incident_report IS NOT NULL'];
      const incidentParams = [];
      let incidentParamIdx = 1;
      if (dateFrom) { incidentConditions.push(`s.game_date >= $${incidentParamIdx++}`); incidentParams.push(dateFrom); }
      if (dateTo) { incidentConditions.push(`s.game_date <= $${incidentParamIdx++}`); incidentParams.push(dateTo); }

      const incidentQuery = `
        SELECT
          ('incident-' || s.game_id) AS entry_id, s.game_id, NULL AS team_id,
          (s.team1_name || ' vs ' || s.team2_name) AS team_name, NULL AS person_type,
          NULL AS profile_id, s.gender AS name, 'Report' AS event_type, NULL AS minute,
          'Incident Report' AS reason, NULL AS supplemental_report,
          s.game_date,
          NULL AS status, NULL AS committee_notes, NULL AS reviewed_by, NULL AS reviewed_at,
          NULL AS games_suspended, NULL AS standard_games, NULL AS games_served,
          s.incident_report
        FROM match_report_scores s
        WHERE ${incidentConditions.join(' AND ')}
      `;

      const [result, incidentResult] = await Promise.all([
        eventTypes.length > 0 ? pool.query(query, params) : Promise.resolve({ rows: [] }),
        includeIncidentReports ? pool.query(incidentQuery, incidentParams) : Promise.resolve({ rows: [] }),
      ]);
      const combinedRows = [...result.rows, ...incidentResult.rows].sort((a, b) => {
        const dateA = a.game_date ? new Date(a.game_date).getTime() : -Infinity;
        const dateB = b.game_date ? new Date(b.game_date).getTime() : -Infinity;
        return dateB - dateA;
      });
      const rowsForStatus = combinedRows;
      // No review row yet = implicitly 'pending' - reflect that in the response
      // rather than leaving status as null for the frontend to special-case.
      // Incident report rows are excluded from this default - they have no
      // real review workflow, so leaving status null (rather than a
      // misleading 'pending') lets the frontend render them differently.
      const rows = rowsForStatus.map(row => ({
        ...row,
        status: row.event_type === 'Report' ? row.status : (row.status || 'pending'),
      }));

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

  // GET /match-reports — running list of submitted match reports. Same
  // auth gate as the main page.
  if (req.method === 'GET' && url.pathname === '/match-reports') {
    const session = await getSession(cookies.admin_session);
    if (!session) {
      res.writeHead(302, { Location: '/oauth/login' });
      return res.end();
    }
    fs.readFile(path.join(__dirname, 'match-reports.html'), 'utf8', (err, data) => {
      if (err) {
        res.writeHead(404);
        return res.end('match-reports.html not found — make sure it is in the same folder as server.js');
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
