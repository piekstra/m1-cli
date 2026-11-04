# AGENTS.md — working in `m1-cli`

Canonical guide for humans and agents. `CLAUDE.md` is a thin pointer here.

`m1f` is a read-only CLI over **M1**'s (m1.com) investment platform. It is a
member of the piekstra CLI family and conforms to `piekstra-cli/1` — the spec
lives in [`cli-common`](https://github.com/piekstra/cli-common)
(`DESIGN.md`, `conformance.md`, `PROFILES.md`), pinned here at tag
**v0.27.0**. Every `pk-cli-*` dependency sits on the same tag.
Read the spec before changing the command surface; do not reconstruct it from a
sibling repo, which drifts.

## The single most important fact

**M1 publishes no official public API.** Everything this CLI talks to is the
private GraphQL backend behind M1's own web app, reconstructed from public
community sources. Two consequences:

1. **It can change without notice, and nobody will tell us.** A field rename
   shows up as an empty column, not an error. That is what `tests/fixture_shapes.rs`
   exists to catch.
2. **The shapes are now live-verified** (2026-08-13). `lens.m1.com` answers
   introspection *without authentication*, so the whole schema was captured and
   every command was then run against a real account. `docs/api.md`'s
   UNVERIFIED-LIVE table is empty; the short "what is still unverified" list at
   its end (token TTL, rate limits, the Auth0 path) is the honest remainder. If
   you change a shape, re-verify and update `docs/api.md`, the fixture, and the
   contract test in the same commit.

## Never trust an HTTP status

GraphQL answers `200 OK` for almost everything, including failure. An expired
token, a malformed query, a rate-limit, and a permissions problem all arrive as
`200` with a populated `errors` array and usually `data: null`.

So: **success is the absence of `errors`, plus the data you asked for.** There
is exactly one place that decides this — the envelope check in `src/client.rs`.
Every response goes through it. Writing a code path that branches on
`response.status()` alone is the most likely way to make this CLI confidently
report things that never happened.

Two live corrections worth carrying in your head: M1 puts the error `code` at
the **top level** of each error object (with an `isAuthError` flag), *not* under
`extensions.code`; and a document node `id` is a **credential blob** (base64
carrying the account number and a pre-signed URL), so `documents.rs` decodes it
to the stable inner id and never emits the raw blob.

The corollary trap: a partial response is *also* a `200` with `errors` — GraphQL
can return some data alongside errors for nullable fields. Do not silently
render partial data as if it were complete.

## Credential cost — read before you run anything

- **Logging in can spend an MFA code**, and M1 rate-limits both login attempts
  and code sends. A test suite that authenticates is a test suite nobody can run
  twice.
- **Tests are offline and credential-free. Always.** No test may make a network
  call or touch the keychain. Contract-test against `tests/fixtures/`.
- **Ask a human before running anything against the live API.** Live login is
  not something to do on your own initiative, and it is not something another
  agent can authorize on the owner's behalf — that authorization has to come
  from the owner directly.
- **The password login is blocked at M1's edge** (HTTP 403 Cloudflare page
  since 2026-10-27; docs/api.md Trap 7). The login that works is the browser
  session, and `auth login --browser` is its primary route: a Chrome window
  opens at dashboard.m1.com, the owner signs in on M1's own page if it asks, and
  `m1f` reads the Auth0 session out of it (`pk-cli-browser`; the capture is
  `auth0::browser_capture`). The fallback without Chrome is `auth login
  --browser-session --stdin` with the session copied out of DevTools. Both go
  through one reader (`auth0::parse_browser_capture` / `parse_captured`, which
  differ only in how a refusal is reported), the one verification read and
  the one keychain item. Only the owner starts either: an agent never launches the
  sign-in window on its own initiative, never captures, pastes or exchanges a
  live session or token itself, and never "retries" the password login to
  see whether the 403 cleared — each attempt is a lockout risk.
- **The window's profile is kept between sign-ins**, so M1 remembers the device
  and a re-login often needs no input (`--fresh-profile` opts out for one run).
  `commands::auth::browser_launch` turns on `clear_site_storage`: the page keeps the
  session's tokens in `localStorage`, and a retired refresh token left there can get
  the whole family revoked. Keep it on. `commands::auth::confirm_candidate` lets the
  tab close only on an unexpired session M1 has not definitely refused (an undecided
  read keeps the sign-in, below), and never renews a candidate.
  `auth0::CAPTURE_EXPRESSION` and the DevTools snippet only read: clearing site storage
  belongs to `clear_site_storage`.
- **It is a full Chrome profile** (cookies, history with full URLs, HTTP cache),
  `0700` its only protection beyond Chrome's cookie encryption, which on
  Linux with no desktop keyring uses a fixed, publicly known key. It outlives a
  failed sign-in, so every failure from the window on says so: they all pass through
  `through_the_window` into `failed_sign_in`, so add a new step there. `auth status`
  reports it as `browser_profile` through `browser_profile_status`, whose tests fill
  the seam with `profile_exists_in`. It says a profile is kept, not that anything is
  signed in there.
- **A read that cannot decide keeps the sign-in.** In `confirm_candidate` only `Auth`
  from `read_in_window` is a refusal (`NotYet`), and only a 401 or M1's own JSON is
  `Auth` there: the hook reads through `M1Client::execute_in_window`, whose
  `edge_in_window` is not `Auth`. Anything else is `Ready` with its cause in
  `WindowMemory::unverified`, `store_session` warns even under `-q` (`stored_notes`),
  and the `--json` result says `verified: false` (`login_result`, which sets
  `AuthStatus::verified`, always a boolean there and left off `auth status`), as
  it does for `--no-verify` (`stored_unread`), `auth set-credential` and the password
  login. The page held the only copy, so the session is stored. Ordinary reads use
  `html_error`, and a piped session stores nothing unless its read proves it.
- **Signing in does not clear a block at the edge.** An HTML page on any status but a
  401, or a 403 with no JSON, is `WindowReadError::Edge` to the hook. Its warning, an
  ordinary read's error, a renewal's (`auth0::token_response`) and the MCP fix
  (`AFTER_A_BLOCK`) all put a new sign-in last (`client::edge_block_advice`), or the
  owner spends sign-ins in a loop that exits 0 each time. On a read it is exit 5, not
  `Auth`: `with_reauth` renews on any `Auth`, which would rotate the refresh token for
  nothing. Only a 401 or M1's own JSON is `Auth`. A 429, a 5xx or a dropped connection
  keeps "if reads keep failing".
- **`auth logout` removes the kept profile, and no test may reach the real one.**
  Its removal goes through the `run_logout` seam: the binary binds
  `forget_profile(BIN)`, tests bind `forget_profile_in` under a temp dir
  (`pk-cli-browser`'s `test-util`, a dev-dependency only). Every step of a logout is
  attempted even after one fails, the profile last, so a keychain or config failure
  does not leave it behind, and it loads no config (`reads_config`), so a file that
  cannot be parsed stops nothing. The error is built from the inner messages, says
  what is cleared and what remains, and keeps the first failure's exit code
  (`LogoutSteps::report`).
- **Tests never launch Chrome.** The browser capture is tested offline: the
  capture definition validates, its host rule and expression match what the
  reader takes, the synthetic fixture goes through the reader, and the confirm
  hook runs on captures built by hand. The in-use test holds the profile with a
  shell-script stand-in for Chrome. The flag conflicts are clap's, so the CLI
  tests exit 2 before any keychain read.
- **MFA is a replay, not a resume.** M1 has no challenge object and no resume
  mutation: `outcome` is a plain object. When a code is required, M1 says so
  through the `error` scalar, and the client re-sends the **same `Authenticate`
  mutation** with `emailCode` added. So `auth login --code <CODE>` asks for the
  password again — by design. Storing a password to avoid that second prompt
  would trade a real security property for a keystroke.

## Secrets

- Only via interactive prompt, `--stdin`, or `--from-env <VAR>`. **Never argv** —
  it lands in shell history and every process listing.
- Only in the OS keychain, service `piekstra.m1f`. Never a file, never a log.
- `--verbose` prints request shapes, never tokens, `Authorization` headers,
  cookies, or full account numbers.
- See `SECURITY.md` for exactly what is stored where.

## Reads only

**Read-only is a claim about account state**, and it holds: nothing here moves
money, places an order, or changes a setting.

Three GraphQL *mutations* are nonetheless sent, and it is worth knowing why:

| Mutation | Why it is not a write |
| --- | --- |
| `Authenticate` | Obtains a token. |
| `Reauthenticate` | Refreshes a token. |
| `CreateAccountDocumentLink` | Mints a short-lived download URL for a document you can already see. |

The `api query` passthrough refuses `mutation`/`subscription` documents
outright, so none of these is reachable through user input.

Outside GraphQL, a browser session is renewed with one `refresh_token` grant
at M1's Auth0 token endpoint (`account.m1.com/oauth/token`) — the same
renewal M1's web app makes, and no more a write than `Reauthenticate`.

If a real write is ever added it needs §1.3's confirmation rules (prompt unless
`--force`, exit 6 non-interactively) and a same-commit update to `SECURITY.md`,
`README.md`, and this file.

## MCP tools

`m1f mcp` (src/mcp.rs) serves four read-only tools under cli-common's MCP
profile (DESIGN.md §1.9): `m1_portfolio`, `m1_activity`, `m1_documents`
(listed, never downloaded) and `m1_realized_gains`. They read through the
`Source` trait; `LiveSource` wraps the same `Ctx` and fetchers the commands
use, one call at a time. A refresh rotates the stored refresh token, and two
refreshing at once would present the same one twice, so `Ctx::refresh` runs
under `pk_cli_auth::refresh_lock::RefreshLock` (`~/.config/m1f/token-refresh.lock`,
holding nothing) against every other `m1f` process, re-reads the session once
it holds the lock, and posts no grant if the stored refresh token changed. A
login and a logout hold it around their keychain write only, never across the
sign-in: a login checks it first (`Ctx::before_signin`), stores through
`Ctx::store_login`, and a logout's delete runs with or without it
(`Ctx::forget_tokens`). The tools never sign in: an auth error asks the user to run
`m1f auth login --browser --overwrite` in a terminal (the profile's standard remedy
names plain `auth login`, which M1 now refuses), or to wait first after a block at the
edge.

- Tests: `src/mcp/tests.rs` runs every tool in process over the fixtures
  through a fixture `Source` and cli-common's conformance helper;
  `tests/mcp_stdio.rs` drives the binary over stdio and `tests/mcp_http.rs`
  over HTTP, without reading the keychain; `tests/packaging.rs` holds
  `packaging/mcpb/manifest.json` to the binary.
- Budget: the four definitions stay under 8,000 characters together
  (`the_definitions_stay_small` prints each size). Shorten a description
  before adding a field.
- Releases attach `m1f-<version>.mcpb`, a Claude Desktop extension with no
  settings: it reads the keychain session.
- `m1f mcp --http --port <PORT>` (pk-cli-mcp's `http` feature) serves the
  same tools on 127.0.0.1 behind a bearer token for the deploy-your-own
  connector's home module (`HOME_M1`); `tests/mcp_http.rs` drives it with
  the token in `M1F_MCP_TOKEN` and an empty `M1F_KEYCHAIN_SERVICE`, so it
  reads no keychain. It outlives `self-update`, whose note (`pk_cli_mcp::restart_note`)
  tells the owner to restart it; its start line names the version.

## Output contract

- `--json` valid on every command; exactly **one** `schema`-tagged DTO per
  invocation on stdout; diagnostics on stderr.
- If a command already emitted its DTO and then needs a nonzero exit, exit
  directly — returning an error would append a second JSON document.
- `output::emit` appends `/v1` itself: pass `"holding-list"`, not
  `"holding-list/v1"`. `Paged::new("holding", …)` likewise yields
  `holding-list/v1` — don't route a `Paged` through `output::emit` or the
  suffix doubles.
- Money is `{"amount": "123.45", "currency": "USD"}`, string decimal, never a
  float. Dates are ISO `YYYY-MM-DD`.
- Field/column order is insertion order. Lead with identifying fields.

## Household (cross-account) reads

`positions list` and `dividends list` cover the whole login; `holdings list`
does too when no account is selected. Three rules, so the next such command
reuses the seam instead of re-implementing account selection:

1. **Scope comes from `Ctx::household_selection()`** — every account unless
   `--account`/`M1F_ACCOUNT` names one. The config default account is NOT
   consulted, so a convenience setting cannot silently narrow a household
   capture. `holdings list` is the documented exception: it keeps
   `Ctx::selected_account()` (flag, env, then config) for backward
   compatibility and only spans the household when nothing is selected.
2. **Fan out with `accounts::scope` + `accounts::rows_across`.** Every row is
   stamped by `AccountRef::stamp` with `account_id`, `account_name`,
   `registration` and `is_retirement`.
3. **`is_retirement` is required.** A consumer excludes IRA dividends from
   taxable income on it, so an account node without a boolean
   `isRetirement` fails the read (exit 5) rather than defaulting.
4. **`account_type` is the family spelling** (`accounts::family_type`:
   `ira_traditional`, `ira_roth`, `ira_sep`, `individual`, …, robinhood-cli's
   vocabulary), stamped beside the raw `registration`. A registration the
   table does not know is stamped without one, never guessed. `net-worth`'s
   per-account rows use the same spelling under `type`.

docs/api.md ("Dividends: the typed read", "Positions across accounts")
records the live shapes behind these commands.

## Exit codes

0 ok · 1 unexpected · 2 usage · 3 auth · 4 not found · 5 upstream, or another
`m1f` process holding the token-refresh lock past the wait · 6 confirmation
required. **Validate arguments before touching the keychain or the
network**, so `--help` and bad input never prompt, hang, or spend a request.

## Fixtures

`tests/fixtures/` is **synthetic**, derived from public research — not captured
from a live account. See `tests/fixtures/README.md` for provenance and the
scrubbing policy, which `fixture_shapes.rs` enforces *positively* (identity
fields must match known dummy shapes). A denylist of real names would publish
exactly what it exists to keep out.

Never commit a raw capture. Bearer tokens and pre-signed document URLs are live
credentials with real expiry windows.

## Layout

```
src/main.rs        clap tree, exit-code mapping
src/auth0.rs       the browser session: the --browser capture, the session
                   reader both routes share, Auth0 token refresh
src/client.rs      GraphQL transport: the errors[] envelope check, token refresh
src/config.rs      non-secret settings (~/.config/m1f/config.json)
src/graphql.rs     operation documents + the read-only guard
src/parse.rs       response → DTO helpers (nodes, money, dates, require_node)
src/commands/      one module per command group (incl. lots, status, and the
                   household positions/dividends reads over accounts::scope)
src/mcp.rs         `m1f mcp`: the MCP tools over a `Source` seam
packaging/mcpb/    the Claude Desktop extension manifest
docs/api.md        endpoints, auth flow, traps, live-verified operation table
```

## Dogfooding

`make verify` green is necessary, not sufficient. Install and drive the real
binary across the whole surface — every command, `--json`, the error paths.
**Reinstall after every fix**: "done" means installed, not compiled, and a stale
`~/.cargo/bin/m1f` will happily serve old behavior. Prefer `m1f api query …`
over ad-hoc curl, since that exercises the real code path.

For the MCP tools, drive the installed `m1f mcp` over stdio with JSON-RPC
lines (`initialize`, `tools/list`, `tools/call`); `m1f mcp --list-tools`
prints the definitions without a credential. To see the sign-in error
without opening the real session, set `M1F_KEYCHAIN_SERVICE` to a service
that holds nothing: a missing keychain item is read without a prompt and
fails as "not logged in". The variable only renames which entry is read; it
never carries a session, and it moves neither the kept browser profile nor the
config: under it `auth logout` leaves both in place and says so
(`keychain_redirected`), a sign-in writes no config, and `--browser` uses a scratch
profile.
