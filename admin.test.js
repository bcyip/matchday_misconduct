// Admin Console API test suite.
//
// IMPORTANT DIFFERENCE FROM matchday's test suite: every route here requires
// a real login session, and real OAuth login can't be scripted without an
// actual browser (SportsEngine's login page, real credentials). So this
// suite creates a SYNTHETIC session directly in Postgres - bypassing the
// browser-only login step specifically, not the actual authorization logic
// each endpoint runs (every endpoint still does its own real session lookup
// against the database, exactly as it would for a real logged-in user).
// This tests "does the app correctly behave once someone is logged in,"
// not "does the OAuth login flow itself work" - that part stays manual
// (see the accompanying admin_console_test_plan.md).
//
// Usage:
//   TEST_BASE_URL=https://your-admin-console.onrender.com \
//   TEST_DATABASE_URL=postgresql://... \
//   node --test test/
//
// SAFETY: this connects directly to whatever Postgres instance
// TEST_DATABASE_URL points at. Do NOT point this at a database with real
// misconduct data you don't want touched - use a QA/test database, or at
// minimum be aware this creates and cleans up rows with clearly-synthetic
// IDs (see randomId() below).

const { test, describe, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { Pool } = require('pg');

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:8787';
const pool = new Pool({
  connectionString: process.env.TEST_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

function randomId(prefix) {
  return prefix + '-' + crypto.randomBytes(6).toString('hex');
}

// ---------- Synthetic session + test data setup ----------

async function createSyntheticSession(name = 'Test Admin') {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const seUserId = randomId('test-admin-user');
  const sessionExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  const seTokenExpiresAt = new Date(Date.now() + 30 * 60 * 1000);

  await pool.query(
    `INSERT INTO admin_sessions (session_id, se_user_id, name, email, access_token, se_token_expires_at, session_expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [sessionId, seUserId, name, 'test@example.com', 'fake-access-token', seTokenExpiresAt, sessionExpiresAt]
  );

  return sessionId;
}

async function destroySession(sessionId) {
  await pool.query('DELETE FROM admin_sessions WHERE session_id = $1', [sessionId]);
}

/**
 * Creates a full synthetic match report (scores + one entry) directly in
 * Postgres, so the misconduct list/filter endpoints have real rows to
 * query against without depending on the separate matchday app's HTTP API.
 */
async function createTestIncident({ gameId, teamId, teamName, gameDate, eventType, reason, minute, supplementalReport }) {
  await pool.query(
    `INSERT INTO match_report_scores (game_id, game_date, team1_id, team1_name, team1_score, team2_id, team2_name, team2_score, submitted_at)
     VALUES ($1, $2, $3, $4, 1, 'opp-team', 'Opponent', 0, now())
     ON CONFLICT (game_id) DO NOTHING`,
    [gameId, gameDate, teamId, teamName]
  );

  const result = await pool.query(
    `INSERT INTO match_report_entries (game_id, team_id, team_name, person_type, profile_id, name, event_type, minute, reason, supplemental_report, submitted_at)
     VALUES ($1, $2, $3, 'player', $4, $5, $6, $7, $8, $9, now())
     RETURNING id`,
    [gameId, teamId, teamName, randomId('test-player'), 'Test Player', eventType, minute, reason, supplementalReport]
  );

  return result.rows[0].id; // entry_id
}

async function cleanupIncident(gameId) {
  await pool.query('DELETE FROM match_report_entries WHERE game_id = $1', [gameId]);
  await pool.query('DELETE FROM match_report_scores WHERE game_id = $1', [gameId]);
  await pool.query(`DELETE FROM misconduct_reviews WHERE entry_id NOT IN (SELECT id FROM match_report_entries)`);
}

async function apiGet(path, sessionId) {
  const res = await fetch(BASE_URL + path, {
    headers: sessionId ? { Cookie: 'admin_session=' + sessionId } : {},
  });
  let body;
  try { body = await res.json(); } catch (e) { body = null; }
  return { status: res.status, body };
}

async function apiPost(path, payload, sessionId) {
  const res = await fetch(BASE_URL + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(sessionId ? { Cookie: 'admin_session=' + sessionId } : {}),
    },
    body: JSON.stringify(payload),
  });
  let body;
  try { body = await res.json(); } catch (e) { body = null; }
  return { status: res.status, body };
}

// ---------- Authorization gating ----------

describe('Authorization', () => {
  test('protected endpoints reject requests with no session cookie', async () => {
    const listRes = await apiGet('/api/misconduct', null);
    assert.strictEqual(listRes.status, 401);

    const teamsRes = await apiGet('/api/misconduct/teams', null);
    assert.strictEqual(teamsRes.status, 401);

    const reviewRes = await apiPost('/api/misconduct/1/review', { status: 'pending' }, null);
    assert.strictEqual(reviewRes.status, 401);
  });

  test('protected endpoints reject an invalid/nonexistent session id', async () => {
    const fakeSessionId = crypto.randomBytes(32).toString('hex'); // well-formed but never created
    const res = await apiGet('/api/misconduct', fakeSessionId);
    assert.strictEqual(res.status, 401);
  });

  test('a real synthetic session is accepted', async () => {
    const sessionId = await createSyntheticSession();
    const res = await apiGet('/api/misconduct', sessionId);
    assert.strictEqual(res.status, 200, 'a valid session should be accepted: ' + JSON.stringify(res.body));
    await destroySession(sessionId);
  });
});

// ---------- Misconduct list: filtering ----------

describe('Misconduct list filtering', () => {
  test('defaults to Red Cards only - Yellow Cards excluded unless requested', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');

    const rcEntryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'Violent Conduct', minute: 40, supplementalReport: 'Test incident description.',
    });
    const ycGameId = randomId('test-game');
    await createTestIncident({
      gameId: ycGameId, teamId, teamName: 'Test Team', gameDate: '2026-09-02',
      eventType: 'Yellow Card', reason: 'Dissent', minute: 10, supplementalReport: null,
    });

    const defaultRes = await apiGet('/api/misconduct?teamId=' + teamId, sessionId);
    const defaultIds = defaultRes.body.misconduct.map(m => m.entry_id);
    assert.ok(defaultIds.includes(rcEntryId), 'RC should be included by default');
    assert.strictEqual(defaultRes.body.misconduct.every(m => m.event_type === 'Red Card'), true, 'default results should be RC only');

    const withYellowRes = await apiGet('/api/misconduct?teamId=' + teamId + '&includeYellow=true', sessionId);
    assert.strictEqual(withYellowRes.body.misconduct.length, 2, 'includeYellow=true should return both');

    await cleanupIncident(gameId);
    await cleanupIncident(ycGameId);
    await destroySession(sessionId);
  });

  test('results are sorted by most recent game first', async () => {
    const sessionId = await createSyntheticSession();
    const teamId = randomId('test-team');
    const olderGameId = randomId('test-game');
    const newerGameId = randomId('test-game');

    await createTestIncident({
      gameId: olderGameId, teamId, teamName: 'Test Team', gameDate: '2026-08-01',
      eventType: 'Red Card', reason: 'Serious Foul Play', minute: 20, supplementalReport: 'Older incident.',
    });
    await createTestIncident({
      gameId: newerGameId, teamId, teamName: 'Test Team', gameDate: '2026-10-15',
      eventType: 'Red Card', reason: 'Serious Foul Play', minute: 20, supplementalReport: 'Newer incident.',
    });

    const res = await apiGet('/api/misconduct?teamId=' + teamId, sessionId);
    const gameIdsInOrder = res.body.misconduct.map(m => m.game_id);
    assert.strictEqual(gameIdsInOrder[0], newerGameId, 'newest game should appear first');
    assert.strictEqual(gameIdsInOrder[1], olderGameId, 'older game should appear second');

    await cleanupIncident(olderGameId);
    await cleanupIncident(newerGameId);
    await destroySession(sessionId);
  });

  test('team filter narrows results correctly', async () => {
    const sessionId = await createSyntheticSession();
    const teamA = randomId('test-team-a');
    const teamB = randomId('test-team-b');
    const gameA = randomId('test-game');
    const gameB = randomId('test-game');

    await createTestIncident({ gameId: gameA, teamId: teamA, teamName: 'Team A', gameDate: '2026-09-01', eventType: 'Red Card', reason: 'DOGSO-F', minute: 15, supplementalReport: 'A' });
    await createTestIncident({ gameId: gameB, teamId: teamB, teamName: 'Team B', gameDate: '2026-09-01', eventType: 'Red Card', reason: 'DOGSO-F', minute: 15, supplementalReport: 'B' });

    const res = await apiGet('/api/misconduct?teamId=' + teamA, sessionId);
    assert.strictEqual(res.body.misconduct.length, 1);
    assert.strictEqual(res.body.misconduct[0].team_id, teamA);

    await cleanupIncident(gameA);
    await cleanupIncident(gameB);
    await destroySession(sessionId);
  });

  test('date range filter excludes incidents outside the range', async () => {
    const sessionId = await createSyntheticSession();
    const teamId = randomId('test-team');
    const insideGame = randomId('test-game');
    const outsideGame = randomId('test-game');

    await createTestIncident({ gameId: insideGame, teamId, teamName: 'Test Team', gameDate: '2026-09-15', eventType: 'Red Card', reason: 'DOGSO-H', minute: 30, supplementalReport: 'x' });
    await createTestIncident({ gameId: outsideGame, teamId, teamName: 'Test Team', gameDate: '2026-12-01', eventType: 'Red Card', reason: 'DOGSO-H', minute: 30, supplementalReport: 'x' });

    const res = await apiGet('/api/misconduct?teamId=' + teamId + '&dateFrom=2026-09-01&dateTo=2026-10-01', sessionId);
    const gameIds = res.body.misconduct.map(m => m.game_id);
    assert.ok(gameIds.includes(insideGame), 'incident inside the range should be included');
    assert.ok(!gameIds.includes(outsideGame), 'incident outside the range should be excluded');

    await cleanupIncident(insideGame);
    await cleanupIncident(outsideGame);
    await destroySession(sessionId);
  });
});

// ---------- Review save/upsert ----------

describe('Review save workflow', () => {
  test('saving a review updates status/decision/notes and stamps the reviewer name', async () => {
    const sessionId = await createSyntheticSession('Committee Member One');
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');

    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'Violent Conduct', minute: 55, supplementalReport: 'Incident details.',
    });

    // Before any review, should default to 'pending' with no explicit row
    const beforeRes = await apiGet('/api/misconduct?teamId=' + teamId, sessionId);
    assert.strictEqual(beforeRes.body.misconduct[0].status, 'pending');

    const saveRes = await apiPost('/api/misconduct/' + entryId + '/review', {
      status: 'sanctioned', decision: '2', committeeNotes: 'Two game suspension issued.',
    }, sessionId);
    assert.strictEqual(saveRes.status, 200);

    const afterRes = await apiGet('/api/misconduct?teamId=' + teamId, sessionId);
    const updated = afterRes.body.misconduct.find(m => m.entry_id === entryId);
    assert.strictEqual(updated.status, 'sanctioned');
    assert.strictEqual(updated.decision, '2');
    assert.strictEqual(updated.committee_notes, 'Two game suspension issued.');
    assert.strictEqual(updated.reviewed_by, 'Committee Member One');

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('saving a review twice UPDATES the same row, does not create a duplicate', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');

    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'Abusive Language', minute: 70, supplementalReport: 'x',
    });

    await apiPost('/api/misconduct/' + entryId + '/review', { status: 'under_review', decision: '', committeeNotes: 'first pass' }, sessionId);
    await apiPost('/api/misconduct/' + entryId + '/review', { status: 'sanctioned', decision: '1', committeeNotes: 'final decision' }, sessionId);

    const countResult = await pool.query('SELECT COUNT(*) FROM misconduct_reviews WHERE entry_id = $1', [entryId]);
    assert.strictEqual(parseInt(countResult.rows[0].count, 10), 1, 'should be exactly 1 review row, not 2');

    const res = await apiGet('/api/misconduct?teamId=' + teamId, sessionId);
    assert.strictEqual(res.body.misconduct[0].status, 'sanctioned', 'latest save should win');
    assert.strictEqual(res.body.misconduct[0].committee_notes, 'final decision');

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('an invalid status value is rejected', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'Biting or Spitting', minute: 5, supplementalReport: 'x',
    });

    const res = await apiPost('/api/misconduct/' + entryId + '/review', { status: 'not_a_real_status' }, sessionId);
    assert.strictEqual(res.status, 400);

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });
});

describe('Suspension issuing', () => {
  test('marking sanctioned with a valid games number creates an active suspension', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-10',
      eventType: 'Red Card', reason: 'Serious Foul Play', minute: 60, supplementalReport: 'x',
    });

    const res = await apiPost('/api/misconduct/' + entryId + '/review', { status: 'sanctioned', decision: '2', committeeNotes: 'test' }, sessionId);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.suspensionAction, 'issued');
    assert.strictEqual(res.body.gamesSuspended, 2);

    const susResult = await pool.query('SELECT * FROM suspensions WHERE team_id = $1', [teamId]);
    assert.strictEqual(susResult.rows.length, 1);
    assert.strictEqual(susResult.rows[0].games_suspended, 2);
    assert.strictEqual(susResult.rows[0].status, 'active');
    assert.strictEqual(new Date(susResult.rows[0].issued_from_game_date).toISOString().slice(0, 10), '2026-09-10');

    await pool.query('DELETE FROM suspensions WHERE team_id = $1', [teamId]);
    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('marking sanctioned without a valid games number is rejected, no suspension created', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-10',
      eventType: 'Red Card', reason: 'Serious Foul Play', minute: 60, supplementalReport: 'x',
    });

    const res = await apiPost('/api/misconduct/' + entryId + '/review', { status: 'sanctioned', decision: '', committeeNotes: 'test' }, sessionId);
    assert.strictEqual(res.status, 400);

    const susResult = await pool.query('SELECT * FROM suspensions WHERE team_id = $1', [teamId]);
    assert.strictEqual(susResult.rows.length, 0, 'no suspension should have been created');

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('reversing a sanctioned decision removes the suspension', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-10',
      eventType: 'Red Card', reason: 'Serious Foul Play', minute: 60, supplementalReport: 'x',
    });

    await apiPost('/api/misconduct/' + entryId + '/review', { status: 'sanctioned', decision: '3', committeeNotes: 'initial' }, sessionId);
    let susResult = await pool.query('SELECT * FROM suspensions WHERE team_id = $1', [teamId]);
    assert.strictEqual(susResult.rows.length, 1, 'suspension should exist after sanctioning');

    const reverseRes = await apiPost('/api/misconduct/' + entryId + '/review', { status: 'dismissed', decision: '', committeeNotes: 'reversed on appeal' }, sessionId);
    assert.strictEqual(reverseRes.body.suspensionAction, 'removed');

    susResult = await pool.query('SELECT * FROM suspensions WHERE team_id = $1', [teamId]);
    assert.strictEqual(susResult.rows.length, 0, 'suspension should be gone after reversing the decision');

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('re-saving with a different games number updates the same suspension row, does not duplicate', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-10',
      eventType: 'Red Card', reason: 'Serious Foul Play', minute: 60, supplementalReport: 'x',
    });

    await apiPost('/api/misconduct/' + entryId + '/review', { status: 'sanctioned', decision: '1', committeeNotes: 'first' }, sessionId);
    await apiPost('/api/misconduct/' + entryId + '/review', { status: 'sanctioned', decision: '4', committeeNotes: 'corrected' }, sessionId);

    const susResult = await pool.query('SELECT * FROM suspensions WHERE team_id = $1', [teamId]);
    assert.strictEqual(susResult.rows.length, 1, 'should still be exactly 1 row, not 2');
    assert.strictEqual(susResult.rows[0].games_suspended, 4, 'should reflect the latest games number');

    await pool.query('DELETE FROM suspensions WHERE team_id = $1', [teamId]);
    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });
});

after(async () => {
  await pool.end();
});

/*
 * WHAT THIS SUITE DOES NOT COVER (needs manual testing - see
 * admin_console_test_plan.md):
 *   - The actual OAuth login flow (browser-based, real SportsEngine login)
 *   - The orgAdmin role gate specifically (this suite bypasses login
 *     entirely via a synthetic session, so it never exercises the code path
 *     that checks role_assignments after a real /oauth/me call)
 *   - Session expiry behavior over real time (8-hour cookie lifetime)
 *   - Any visual/UI behavior (badge colors, expand/collapse, filter UI)
 */
