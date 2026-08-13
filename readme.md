# Admin Console — Manual Test Plan

These specifically cover what `test/admin.test.js` **cannot** — anything requiring
a real browser, real SportsEngine login, or visual judgment. Run the automated
suite first (`npm test`); use this checklist for everything else.

## 1. Real OAuth Login Flow

- [ ] Visit the admin console while logged out — redirected to `/oauth/login`, not shown a blank/broken page
- [ ] Click through to SportsEngine's real login page, log in as an account **with** the `orgAdmin` role
- [ ] Land back on the admin console successfully, misconduct list loads
- [ ] `/api/whoami` (or the header display) shows your correct real name/email
- [ ] Log out (`/oauth/logout`) — session actually ends; reloading the page redirects to login again, doesn't silently stay authenticated

## 2. The orgAdmin Gate (needs a second, non-admin SportsEngine account to test properly)

- [ ] Log in with a SportsEngine account that does **not** have the `orgAdmin` role for your org — confirm you see the "Not authorized" message, not access to the console
- [ ] Confirm that account is **not** silently granted a session (check `admin_sessions` in Supabase — no row should exist for that attempt)

## 3. CSRF / State Parameter

- [ ] Manually visit the SportsEngine authorize URL directly (skipping `/oauth/login`, so no `state` cookie gets set) using the admin console's redirect URI — confirm you see the raw-code display page (the "not a real login attempt" fallback), not a broken error or an accidental login

## 4. Session Expiry

- [ ] (Time-consuming, optional) Confirm a session actually stops working after its 8-hour lifetime — either wait it out, or manually edit a session's `session_expires_at` in Supabase to the past and confirm the next request redirects to login instead of silently succeeding

## 5. Visual / UI Checks

- [ ] Status badge colors are visually distinct and correctly mapped: pending (gray), under review (blue), sanctioned (red), dismissed (green)
- [ ] The status legend row above the table accurately describes each status
- [ ] Clicking a row expands it to show the full supplemental report and review form; clicking again collapses it
- [ ] The "Games Suspended" field only accepts numeric input (try typing letters — should be blocked by the number input type)
- [ ] After saving a review, the row's badge updates immediately without a full page reload
- [ ] Filter changes (team dropdown, date range, Include Yellow Cards checkbox) update the list without requiring a manual "Apply" click
- [ ] Player name search has a reasonable debounce — doesn't fire a request on every single keystroke

## 6. Real End-to-End Data Check

- [ ] Submit a real match report through `matchday` with a manually-added Red Card (not the auto-generated 2nd-Caution kind) and a real supplemental report
- [ ] Confirm that exact incident appears in the admin console's list, with the correct game date, team, player, reason, minute, and full supplemental report text
- [ ] Save a review on it, confirm it persists correctly on reload

## 7. Mobile / Responsive (lower priority — this app is primarily desk-based)

- [ ] Confirm the page is at least usable (not completely broken) on a phone, even if not optimized the way `matchday` was
