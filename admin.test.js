// Admin Console API test suite.
//
// IMPORTANT DIFFERENCE FROM matchday's test suite: every route here requires
// a real login session, and real OAuth login can't be scripted without an
// actual browser. So this suite creates a SYNTHETIC session directly in
// Postgres - bypassing the browser-only login step specifically, not the
// actual authorization logic each endpoint runs.
//
// ARCHITECTURE THIS SUITE TESTS (as of the auto-suspension rework):
//   - Suspensions are auto-created by MATCHDAY at match-report submission
//     time, not by this admin console. Since this suite doesn't call
//     matchday's API, createTestIncident() below simulates that by
//     directly inserting the suspension row matchday would have created,
//     using the same STANDARD_SUSPENSION_GAMES mapping matchday uses.
//   - misconduct_reviews.status is just 'pending' / 'reviewed'.
//   - The review-save endpoint NEVER creates or deletes a suspension - it
//     only ever UPDATEs games_suspended on an already-existing row.
//   - Suspensions are never deleted, regardless of status changes.
//
// Usage:
//   TEST_BASE_URL=https://your-admin-console.onrender.com \
//   TEST_DATABASE_URL=postgresql://... \
//   node --test test/

const { test, describe, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { Pool } = require('pg');

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:8787';
const pool = new Pool({
  connectionString: process.env.TEST_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Must match matchday's server.js mapping exactly.
const STANDARD_SUSPENSION_GAMES = {
  'Serious Foul Play': 1, 'DOGSO-F': 1, 'DOGSO-H': 1, '2nd Caution': 1,
  'Violent Conduct': 3, 'Abusive Language': 3, 'Biting or Spitting': 3,
};

function randomId(prefix) {
  return prefix + '-' + crypto.randomBytes(6).toString('hex');
}

async function createSyntheticSession(name = 'Test Admin') {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const seUserId = randomId('test-admin-user');
  const sessionExpiresAt = new Date(Date.now() + 60 * 60 * 1000);
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
 * Postgres. For Red Cards, ALSO creates the suspension row - simulating
 * what matchday's server does automatically at submission time.
 */
async function createTestIncident({ gameId, teamId, teamName, gameDate, eventType, reason, minute, supplementalReport }) {
  await pool.query(
    `INSERT INTO match_report_scores (game_id, game_date, team1_id, team1_name, team1_score, team2_id, team2_name, team2_score, submitted_at)
     VALUES ($1, $2, $3, $4, 1, 'opp-team', 'Opponent', 0, now())
     ON CONFLICT (game_id) DO NOTHING`,
    [gameId, gameDate, teamId, teamName]
  );

  const profileId = randomId('test-player');
  const playerName = 'Test Player';

  const result = await pool.query(
    `INSERT INTO match_report_entries (game_id, team_id, team_name, person_type, profile_id, name, event_type, minute, reason, supplemental_report, submitted_at)
     VALUES ($1, $2, $3, 'player', $4, $5, $6, $7, $8, $9, now())
     RETURNING id`,
    [gameId, teamId, teamName, profileId, playerName, eventType, minute, reason, supplementalReport]
  );
  const entryId = result.rows[0].id;

  if (eventType === 'Red Card') {
    const standardGames = STANDARD_SUSPENSION_GAMES[reason];
    await pool.query(
      `INSERT INTO suspensions (entry_id, profile_id, team_id, team_name, player_name, games_suspended, standard_games, issued_from_game_date, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $6, $7, 'active', now())`,
      [entryId, profileId, teamId, teamName, playerName, standardGames, gameDate]
    );
  }

  return entryId;
}

async function cleanupIncident(gameId) {
  const entries = await pool.query('SELECT id FROM match_report_entries WHERE game_id = $1', [gameId]);
  for (const row of entries.rows) {
    await pool.query('DELETE FROM suspensions WHERE entry_id = $1', [row.id]);
    await pool.query('DELETE FROM misconduct_reviews WHERE entry_id = $1', [row.id]);
  }
  await pool.query('DELETE FROM match_report_entries WHERE game_id = $1', [gameId]);
  await pool.query('DELETE FROM match_report_scores WHERE game_id = $1', [gameId]);
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
    const fakeSessionId = crypto.randomBytes(32).toString('hex');
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

describe('Misconduct list filtering', () => {
  test('defaults to Red Cards only, and includes games_suspended/standard_games for them', async () => {
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
    assert.strictEqual(defaultRes.body.misconduct.every(m => m.event_type === 'Red Card'), true);

    const rcRow = defaultRes.body.misconduct.find(m => m.entry_id === rcEntryId);
    assert.strictEqual(rcRow.standard_games, 3, 'Violent Conduct standard should be 3');
    assert.strictEqual(rcRow.games_suspended, 3, 'should start equal to standard, unadjusted');

    const withYellowRes = await apiGet('/api/misconduct?teamId=' + teamId + '&includeYellow=true', sessionId);
    assert.strictEqual(withYellowRes.body.misconduct.length, 2);

    await cleanupIncident(gameId);
    await cleanupIncident(ycGameId);
    await destroySession(sessionId);
  });

  test('results are sorted by most recent game first', async () => {
    const sessionId = await createSyntheticSession();
    const teamId = randomId('test-team');
    const olderGameId = randomId('test-game');
    const newerGameId = randomId('test-game');

    await createTestIncident({ gameId: olderGameId, teamId, teamName: 'Test Team', gameDate: '2026-08-01', eventType: 'Red Card', reason: 'Serious Foul Play', minute: 20, supplementalReport: 'Older.' });
    await createTestIncident({ gameId: newerGameId, teamId, teamName: 'Test Team', gameDate: '2026-10-15', eventType: 'Red Card', reason: 'Serious Foul Play', minute: 20, supplementalReport: 'Newer.' });

    const res = await apiGet('/api/misconduct?teamId=' + teamId, sessionId);
    const gameIdsInOrder = res.body.misconduct.map(m => m.game_id);
    assert.strictEqual(gameIdsInOrder[0], newerGameId);
    assert.strictEqual(gameIdsInOrder[1], olderGameId);

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
    assert.ok(gameIds.includes(insideGame));
    assert.ok(!gameIds.includes(outsideGame));

    await cleanupIncident(insideGame);
    await cleanupIncident(outsideGame);
    await destroySession(sessionId);
  });
});

describe('Review save workflow', () => {
  test('a new incident starts as pending, with the suspension already at standard value', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');

    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'Serious Foul Play', minute: 55, supplementalReport: 'Incident details.',
    });

    const res = await apiGet('/api/misconduct?teamId=' + teamId, sessionId);
    const row = res.body.misconduct.find(m => m.entry_id === entryId);
    assert.strictEqual(row.status, 'pending');
    assert.strictEqual(row.standard_games, 1);
    assert.strictEqual(row.games_suspended, 1);

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('saving with status=reviewed and a games number updates the suspension and stamps the reviewer', async () => {
    const sessionId = await createSyntheticSession('Committee Member One');
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');

    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'Violent Conduct', minute: 55, supplementalReport: 'Incident details.',
    });

    const saveRes = await apiPost('/api/misconduct/' + entryId + '/review', {
      status: 'reviewed', gamesSuspended: '2', committeeNotes: 'Reduced from standard 3 to 2.',
    }, sessionId);
    assert.strictEqual(saveRes.status, 200);
    assert.strictEqual(saveRes.body.suspensionUpdated, true);
    assert.strictEqual(saveRes.body.gamesSuspended, 2);

    const afterRes = await apiGet('/api/misconduct?teamId=' + teamId, sessionId);
    const updated = afterRes.body.misconduct.find(m => m.entry_id === entryId);
    assert.strictEqual(updated.status, 'reviewed');
    assert.strictEqual(updated.games_suspended, 2);
    assert.strictEqual(updated.standard_games, 3);
    assert.strictEqual(updated.committee_notes, 'Reduced from standard 3 to 2.');
    assert.strictEqual(updated.reviewed_by, 'Committee Member One');

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('reducing a 1-game standard down to 0 is valid', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'DOGSO-F', minute: 20, supplementalReport: 'x',
    });

    const res = await apiPost('/api/misconduct/' + entryId + '/review', { status: 'reviewed', gamesSuspended: '0', committeeNotes: 'Reduced to 0 on appeal.' }, sessionId);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.gamesSuspended, 0);

    const susResult = await pool.query('SELECT games_suspended FROM suspensions WHERE entry_id = $1', [entryId]);
    assert.strictEqual(susResult.rows[0].games_suspended, 0);

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('a negative games value is rejected', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'DOGSO-H', minute: 20, supplementalReport: 'x',
    });

    const res = await apiPost('/api/misconduct/' + entryId + '/review', { status: 'reviewed', gamesSuspended: '-1' }, sessionId);
    assert.strictEqual(res.status, 400);

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('an invalid status value is rejected (including the old pre-simplification statuses)', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'Biting or Spitting', minute: 5, supplementalReport: 'x',
    });

    for (const badStatus of ['under_review', 'sanctioned', 'dismissed', 'not_a_real_status']) {
      const res = await apiPost('/api/misconduct/' + entryId + '/review', { status: badStatus }, sessionId);
      assert.strictEqual(res.status, 400, `"${badStatus}" should be rejected under the 2-status model`);
    }

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('the suspension is NEVER deleted, regardless of status changes back and forth', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Red Card', reason: 'Abusive Language', minute: 70, supplementalReport: 'x',
    });

    await apiPost('/api/misconduct/' + entryId + '/review', { status: 'reviewed', gamesSuspended: '2' }, sessionId);
    await apiPost('/api/misconduct/' + entryId + '/review', { status: 'pending', gamesSuspended: '3' }, sessionId);
    await apiPost('/api/misconduct/' + entryId + '/review', { status: 'reviewed', gamesSuspended: '1' }, sessionId);

    const susResult = await pool.query('SELECT * FROM suspensions WHERE entry_id = $1', [entryId]);
    assert.strictEqual(susResult.rows.length, 1, 'suspension should still exist - never deleted');
    assert.strictEqual(susResult.rows[0].games_suspended, 1);

    await cleanupIncident(gameId);
    await destroySession(sessionId);
  });

  test('saving a review for a Yellow Card (no suspension exists) does not error, suspensionUpdated is false', async () => {
    const sessionId = await createSyntheticSession();
    const gameId = randomId('test-game');
    const teamId = randomId('test-team');
    const entryId = await createTestIncident({
      gameId, teamId, teamName: 'Test Team', gameDate: '2026-09-01',
      eventType: 'Yellow Card', reason: 'Dissent', minute: 12, supplementalReport: null,
    });

    const res = await apiPost('/api/misconduct/' + entryId + '/review', { status: 'reviewed', committeeNotes: 'Noted.' }, sessionId);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.suspensionUpdated, false);

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
 *   - The actual OAuth login flow, the orgAdmin role gate, session expiry
 *   - Any visual/UI behavior
 *   - matchday's OWN auto-suspension-creation logic (simulated here via
 *     createTestIncident, never calls matchday's real API - that's covered
 *     separately in matchday.test.js, which also needs updating to test
 *     the no-resubmission lock and auto-suspension creation)
 */
