# CLAUDE.md

The canonical guide for both humans and agents working in this repo is
[`AGENTS.md`](AGENTS.md). Read it first.

A few things worth repeating because getting them wrong is expensive:

- **Tests are offline and credential-free.** M1's login can spend an MFA code
  and is rate-limited. Never write a test that authenticates or hits the
  network. Ask before running anything that would touch the live API.
- **Never trust an HTTP status — and failure is dual-channel.** M1 returns
  `200 OK` both with a top-level `errors` array (transport/GraphQL failures)
  and with a clean envelope but `didSucceed: false` (business/auth failures).
  Check both: `client::execute` and `client::check_did_succeed`.
- **Reads only, w.r.t. account state.** The mutations sent are `Authenticate`,
  `Reauthenticate`, and `CreateAccountDocumentLink` (mints a download link),
  and a browser session is renewed with one `refresh_token` grant at
  `account.m1.com/oauth/token`; none changes account state. Adding a real
  write pulls in the confirmation rules and doc updates described in
  `AGENTS.md`.
- **The password login is blocked at M1's edge** (Cloudflare 403 since
  2026-10-27). The working login is `auth login --browser` (a Chrome window
  the owner signs in through), with `auth login --browser-session --stdin` as
  the fallback without Chrome. Only the owner runs them — never test any
  login live, and never launch the sign-in window from a test.
- **MFA is a replay, not a resume.** `auth login --code` re-sends the whole
  `Authenticate` mutation with `emailCode`, and asks for the password again.
  There is no challenge object and no resume mutation.
- **Fixtures are synthetic.** Never commit a raw capture; pre-signed document
  URLs and bearer tokens are live credentials.
