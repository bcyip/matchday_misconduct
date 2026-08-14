# USCCS Admin Console — Misconduct Review

A login-protected app for the discipline committee to review Red Card (and optionally Yellow Card) incidents and adjust suspensions. Deliberately a **separate app** from `matchday` — this is the one place in the system handling sensitive, named disciplinary data, so it has real individual login rather than the public-link model used everywhere else.

## Architecture

- **Server:** Node.js, `pg` (Postgres driver) — real OAuth session handling, no framework.
- **Database:** the **same** Supabase Postgres instance `matchday` uses (shared, not duplicated) — plus its own tables: `misconduct_reviews`, `admin_sessions`. Reads/writes `suspensions`, which `matchday` also writes to.
- **Auth:** SportsEngine OAuth ("User Authentication" flow) — real per-person login, gated by the `orgAdmin` composite role on the org (`SE_ORG_ID`). No separate custom allowlist currently (a known, deliberately deferred hardening step — see "Known gaps" below).

### Required environment variables

| Variable | Purpose |
|---|---|
| `SE_CLIENT_ID`, `SE_CLIENT_SECRET` | SportsEngine OAuth app credentials |
| `SE_ORG_ID` | Org ID a user's `role_assignments` must include `orgAdmin` for |
| `ADMIN_BASE_URL` | This app's own public URL — used to build the OAuth `redirect_uri` (must exactly match what's registered with SportsEngine) |
| `DATABASE_URL` | Same Supabase connection string as `matchday` |
| `PORT` | Usually set automatically by the host |

## Workflows

### 1. Login
`/oauth/login` → SportsEngine's real login page → `/oauth/callback` (with CSRF-protected `state` parameter) → checks `role_assignments` for `orgAdmin` on `SE_ORG_ID` → creates a Postgres-backed session (8-hour lifetime, HTTP-only cookie) → redirects to the main list.

### 2. Misconduct list
Defaults to **Red Cards only**, sorted by most recent game first. Filterable by team, player name (partial match), and date range; a checkbox includes Yellow Cards too. Each row shows a status badge and, for Red Cards, the current vs. standard games-suspended value side by side.

### 3. Reviewing an incident
Click a row to expand it — shows the full supplemental report, who last reviewed it, and an editable form:
- **Status:** `pending` or `reviewed` — that's the entire model, nothing more granular.
- **Games Suspended:** pre-filled with the current value (starts equal to the standard for that reason). Can be adjusted up, down, or all the way to **0** (a 1-game standard can be reduced to 0 on appeal).
- **Committee Notes:** free text.

### Critical invariant: suspensions are auto-created by `matchday`, never by this app
Every Red Card submitted through `matchday` **immediately** creates a `suspensions` row at the standard value — before any committee member has looked at it. This admin console **only ever `UPDATE`s** `games_suspended` on that existing row. It **never creates or deletes** a suspension, regardless of how many times the status is flipped between `pending` and `reviewed`. This was a deliberate, explicit requirement — verified by an automated test that flips status three times and confirms exactly one suspension row survives throughout.

## Known gaps (documented, not yet addressed)

- **No custom admin allowlist.** Access is gated purely on the `orgAdmin` role — fine while there's one admin, but fragile the moment anyone gets that role for an unrelated reason (billing, website admin, etc.), since it's a bundled composite role, not something scoped to discipline specifically.
- **`matchday` doesn't yet read from `suspensions`** — a suspended player still appears normally on their team's roster in the check-in flow. The write side (this app) is complete; the read side (filtering a suspended player out) is a deliberately separate, not-yet-built stage.

## Running the automated tests

```bash
npm install
TEST_BASE_URL=https://your-admin-console.onrender.com \
TEST_DATABASE_URL="your-supabase-connection-string" \
npm test
```

**Important difference from `matchday`'s test suite:** every route here requires a real login session, and real OAuth login can't be scripted without an actual browser. This suite creates a **synthetic session directly in Postgres** (`TEST_DATABASE_URL` is required specifically for this) — bypassing the browser-only login step, not the actual authorization logic each endpoint independently runs. It also simulates `matchday`'s auto-suspension-creation behavior directly in Postgres, since it doesn't call `matchday`'s live API.

**What's covered:** session rejection/acceptance, Red-Card-only default filtering (and the Yellow Card toggle), sort order, team/date filters, the full review-save flow (status + games + notes, reviewer name stamping), 0 as a valid reduced value, negative values rejected, old pre-simplification status values rejected, and — the most important one — **suspensions surviving multiple status flips without ever being deleted.**

**What's NOT covered by automation** (see `admin_console_test_plan.md` for the manual checklist): the real OAuth login flow itself, the `orgAdmin` gate against a real non-admin account, session expiry over real time, the CSRF fallback page, and all visual/UI behavior.

## Schema migrations applied (in order)

1. Initial schema — `misconduct_reviews`, `suspensions`, `admin_sessions`, plus `game_date` added to `matchday`'s `match_report_scores`.
2. `suspensions_review_id_unique` constraint (pre-auto-suspension rework).
3. Auto-suspension rework — `suspensions.entry_id` + `standard_games` columns, `suspensions_entry_id_unique` constraint, `misconduct_reviews.status` simplified to the 2-value `pending`/`reviewed` model.
4. `suspensions.games_suspended` CHECK constraint loosened from `> 0` to `>= 0` (to allow reducing a 1-game standard down to 0).

If setting this up fresh, apply all four in order — each depends on tables/columns the previous one created.
