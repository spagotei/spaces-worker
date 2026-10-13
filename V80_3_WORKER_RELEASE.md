# Spaces V80.3 — Worker Partner, Support Email & Archive Backend

This patch was developed against the Worker source uploaded October 8, 2026 (`spaces/src/worker.js`, migrations through `0032_support_operations_v77.sql`). It **does not deploy, send live email, migrate production D1, or publish apps**.

## What it changes

- Adds `GET/POST /v1/support/partners` (Founder/Staff only) for approval, denial and revocation. Decisions are saved in D1 with audit records. Staff cannot approve their own Space; restricted Spaces and banned owners cannot be approved.
- Adds `GET/POST /v1/partners/applications` for Space owners to submit and review their own applications.
- Adds `GET /v1/spaces/trust` and `GET /v1/spaces/:id/trust` for public authoritative Partner badges. The current V80 frontend still uses a static `spaces-trust.json`; it needs a separate integration pass before badges auto-update.
- Adds `GET /v1/support/email/capabilities` and `POST /v1/support/email`, using the existing Cloudflare `EMAIL` binding. Template IDs, sender identity, recipient ownership, image hostnames, roles and rate limits are validated by the Worker. Emails are audited without storing their bodies. **Delivery is not guaranteed merely because the provider accepts a message.**
- Adds `GET /v1/support/v80/my-archives` and `PATCH /v1/support/v80/cases/:id/archive` for a member's personal archive/restore preference, independent of the staff case lifecycle.
- Adds `GET /v1/support/v80/archive-health` for staff-only aggregate archive diagnostics.
- Fixes a missing `targetType='user'` argument in the existing session restriction lookup. This is a targeted auth bug fix.
- Adds migration `0033_partner_email_member_archives_v80.sql` and an in-memory Worker integration test suite.
- Leaves existing V73/V77 ticket, report and permanent-delete implementations in place.

## Install (safe local patch)

Place `SPACES_V80_3_WORKER_PARTNERS_EMAIL_ARCHIVES.cjs` in Downloads, then:

```powershell
cd "C:\Users\ldc-c\OneDrive\Documents\spaces"
node "$env:USERPROFILE\Downloads\SPACES_V80_3_WORKER_PARTNERS_EMAIL_ARCHIVES.cjs"
npm.cmd run beta:worker
```

The installer backs up and rolls back touched files if local checks fail. It runs the test suite against **an in-memory SQLite database and mock email binding**, never production. It does not change `wrangler.jsonc`.

## Production rollout (only after QA)

1. Back up the live D1 database first. Verify the Wrangler binding targets the intended Spaces database. Example: `npx.cmd wrangler d1 export DB --remote --output .\spaces-before-v80-3.sql` (store this backup securely; never commit it).
2. Apply migration locally and review results: `npx.cmd wrangler d1 migrations apply DB --local`.
3. Apply the additive migration to production: `npx.cmd wrangler d1 migrations apply DB --remote`.
4. Deploy Worker: `npx.cmd wrangler deploy`.
5. Smoke-test with a Founder, Staff, Support and Member account; use expendable tickets and a test Space. Do not send live test email to unrelated users.
6. Confirm front-end API URL and bearer-token wiring. The V80 Partner and Email UI currently uses relative `/v1/...` calls with `credentials:'include'`, but this Worker authenticates via `Authorization: Bearer <session token>`. **Do not weaken Worker auth to make those UI calls pass.** The frontend must use its existing authenticated API client. Provide the current SpacesApp and SpacesSite source for that integration.
7. Replace static Partner/Official badge projection with the authoritative `GET /v1/spaces/trust` response. Never use public trust badges to grant privileges.
8. Test member archives and staff archives in desktop, website and Android. This patch supplies backend endpoints but cannot connect missing frontend buttons without those repositories.

## Email setup

The existing `SPACES_EMAIL_FROM` is `security@yourspaces.net` in your Wrangler config. By default all V80 templates send from that configured address, with a branded display name. To use dedicated addresses, configure **verified** sender addresses on the same domain (and in Cloudflare Email Service):

- `SPACES_EMAIL_SUPPORT_FROM` (for example `support@yourspaces.net`)
- `SPACES_EMAIL_NOREPLY_FROM` (for example `noreply@yourspaces.net`)
- `SPACES_EMAIL_SECURITY_FROM` (for example `security@yourspaces.net`)
- `SPACES_EMAIL_IMAGE_HOSTS` optional comma-separated list of trusted HTTPS image hosts. `yourspaces.net` and `www.yourspaces.net` are already allowed.

Do not add addresses to the Wrangler config until the Email Service permits those senders. The browser cannot override From or Reply-To. Support agents may only email ticket owners; Staff/Founder can send approved Partner notices; security and beta-invite templates are Founder-only. A Partner approval email requires an active Partner status in D1.

## Remaining beta blockers

- V80 UI requests currently omit Bearer auth and may target the wrong origin. Frontend integration requires SpacesApp and SpacesSite source.
- The Partner website contains program terms but does not yet submit owner applications to the Worker.
- Static `spaces-trust.json` is not automatically synchronized with authoritative Partner status. Update the badge component to fetch Worker data; avoid treating the static file as authority.
- The email preview permits arbitrary HTTPS images, but the Worker intentionally limits delivery images to trusted hosts. Align the UI and add presets to your site asset directory.
- Local integration tests cannot prove remote D1 state, Cloudflare sender verification, device UX, or production archive retention behavior.
- Legal policies are drafts requiring review before public release.
- V81 voice/streaming is not part of this patch.
