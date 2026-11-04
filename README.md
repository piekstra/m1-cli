# m1-cli (`m1f`)

Read your [M1](https://m1.com) investment accounts, holdings, activity, tax
documents, per-lot cost basis, money-movement history, dividend yields, and
household net worth from the command line.

Conforms to the `piekstra-cli/1` spec and the `documents/v1` domain profile
(see [cli-common](https://github.com/piekstra/cli-common)). Keychain-secured,
`--json` on every command, agent-friendly.

> [!WARNING]
> **Unofficial.** M1 publishes no public API. This CLI talks to the private
> GraphQL backend behind M1's own web app. Every operation was **verified
> against a live account on 2026-08-13** — login (with email MFA), accounts,
> holdings, activity, per-lot tax data, and a real consolidated-1099 PDF
> download — but M1 can change the backend without notice, and a field rename
> shows up as an empty column, not an error. Not affiliated with or endorsed
> by M1 Holdings.

> [!NOTE]
> **Read-only.** `m1f` issues nothing that moves money, places a trade, or
> changes a setting. It sends three GraphQL mutations — `Authenticate`,
> `Reauthenticate`, and `CreateAccountDocumentLink` (which mints a short-lived
> download link) — and renews a browser session at M1's Auth0 token
> endpoint; none of them alters account state. The `api query`
> passthrough refuses `mutation` and `subscription` documents outright.
> See [`SECURITY.md`](SECURITY.md#scope).

## Install

```sh
cargo install --git https://github.com/piekstra/m1-cli --locked
```

Or from a release tarball; `m1f self-update` keeps it current.

## Getting started

M1's own web app signs in through Auth0, and since **2026-10-27** its
Cloudflare front answers the old password login with an HTTP 403 page. So the
login that works is a **browser session**: you sign in on M1's website, and
`m1f` takes the session the web app keeps.

```sh
m1f auth login --browser
m1f auth status
```

`--browser` opens a Chrome window at <https://dashboard.m1.com>, in a profile
`m1f` keeps between sign-ins. Sign in there as usual; your password and any
emailed code go to M1's page, never to `m1f`. Once the page holds a session M1 does
not refuse, `m1f` takes it out of the page, closes the tab at once (so the web app
cannot rotate the refresh token it just handed over) and quits Chrome. The wait
is up to 10 minutes and Ctrl-C cancels. If Chrome is installed somewhere unusual,
point `M1F_CHROME` at its binary. To replace a stored session, add `--overwrite`.

`m1f` checks the session with one read (`viewer.isAuthenticated`) before it
stores anything, then renews it on its own. If M1 refuses it, the window stays open
for a new sign-in. If the read cannot decide (a bot check, M1 throttled or down), `m1f`
stores the session anyway, since the page held the only copy, exits 0, and warns even
under `-q` that it is unverified; `--json` says `verified: false`. If reads then keep
failing, run `m1f auth login --browser --overwrite`. After a bot check, wait or try
another network first: a new sign-in may not help, because the block is on the client
rather than the session.

The kept profile lets M1 remember this device, so a later sign-in often needs no
password, code or bot check: the window opens, the session is read and the window
closes. It lives at `~/Library/Application Support/piekstra.m1f/browser-profile`
on macOS and under `$XDG_DATA_HOME` (or `~/.local/share`) on Linux, owner-only
(`0700`); other systems use a scratch profile every time. `m1f auth login
--browser --fresh-profile` signs in once through a scratch profile, deleted
afterwards, and leaves the kept one alone.

The trade is more than cookies. It is a full Chrome profile, so it also keeps
browsing history with full URLs, query strings included, and the HTTP cache, for
whatever you open in that window. Chrome's cookie encryption does not cover those:
the directory's `0700` mode is their only protection, and ordinary backups usually
include the directory ([`SECURITY.md`](SECURITY.md)). On Linux with no desktop
keyring Chrome encrypts the cookies with a fixed, publicly known key, so there the
session cookie has only `0700` too.

It does not keep the session's tokens. M1's page holds them in site storage, which
`m1f` removes before Chrome starts and again once Chrome has stopped. A crash or a
second Ctrl-C skips the second removal; the next launch or `m1f auth logout` covers
it.

The profile stays after a failed sign-in too, and every failure once the window
has opened says so: a timeout, a closed window, Ctrl-C, a keychain write that fails.
Those can leave a live session in it.
`m1f auth status` says whether a profile is kept (`browser_profile` with `--json`),
not whether anything is signed in there. `m1f auth logout` removes it
and clears the stored session with it. It attempts every step even after one fails,
then says what is cleared and what remains, and exits with the first failure's code.
While a sign-in or a Chrome window is using the profile, it clears the session,
exits 1 and says only the profile remains; close the window and run it again.
[`docs/api.md`](docs/api.md#the-browser-capture-auth-login---browser) records
exactly what is read and from which host, and
[Trap 7](docs/api.md#trap-7-the-password-login-answers-a-cloudflare-403) the
reasoning.

### Without Chrome

Copy the session out of any browser and pipe it in. It stores the same
session as `--browser`.

1. Open a private (incognito) window at <https://dashboard.m1.com> and sign in
   as usual (password and any code happen on M1's page).
2. DevTools (Cmd-Opt-I) → Console:

   ```js
   copy(localStorage[Object.keys(localStorage).find(k =>
     k.startsWith('@@auth0spajs@@::') && k.includes('lens.m1finance.com'))])
   ```

3. In a terminal:

   ```sh
   pbpaste | m1f auth login --browser-session --stdin
   m1f auth status
   ```

4. Close the private window **without signing out**. The session carries a
   refresh token that M1 may rotate on each renewal; a browser still holding
   the old one would use it later, and Auth0 answers that reuse by revoking
   the session everywhere.

`m1f auth login --help` carries both routes.

The password login (`m1f auth login`, which prompts for the password, then
`--code <CODE>` for an emailed code) is kept for when the edge lets it through
again; today it exits 3 and points at `m1f auth login --browser`.

## Commands

```sh
m1f status                                 # M1 system status — no login required

m1f accounts list                          # investment accounts
m1f config set account acct-123            # pick a default, or pass --account

m1f holdings list                          # positions in that account (every account if none is set)
m1f positions list                         # every account's positions, family position-list/v1
m1f dividends list --since 2026-01-01      # every account's dividends, family dividend-list/v1
m1f activity list --since 2026-01-01 --until 2026-12-31
m1f activity list --limit 20

m1f lots list                              # per-lot cost basis (Form 8949 detail)
m1f lots list --closed                     # sold lots only — realized gain/loss
m1f lots list --open                       # still-held lots — unrealized

m1f transactions list                      # normalized FDX ledger (richest for tax)
m1f transactions list --since 2026-01-01 --limit 50

m1f net-worth                              # household total; the Invest line one row per account
m1f summary                                # per-account snapshot: value, cost, gain %, funding
m1f trading                                # queued orders, auto-invest, next window, pending transfers
m1f trading -a <ROTH_IRA_ID>               # just that account
m1f ira -a <ROTH_IRA_ID>                   # IRA contribution room by year (tax)
m1f transfers list                         # money movements: deposits/withdrawals
m1f transfers list --since 2026-01-01

m1f documents list                         # statements and tax forms (all types)
m1f documents list --type tax-form         # just 1099s / 5498s / 1099-Rs
m1f documents download <ID> -o ~/tax/
m1f documents download --all -o ~/tax/2026/m1/
m1f documents download <ID> -o -           # stream the PDF to stdout

m1f api query '{ __typename }'             # read-only GraphQL passthrough
m1f api query - < query.graphql
m1f api query 'query Q($id: ID!) { … }' --variables '{"id":"acct-123"}'

m1f info                                   # capability discovery (cli-info/v1)
m1f mcp                                    # serve read-only tools to Claude (see Use with Claude)
m1f mcp --http --port 8731                 # the same, on 127.0.0.1 for your own Cloudflare Worker
m1f completions zsh
```

`positions list` and `dividends list` are household reads: they span every
account unless `--account`/`M1F_ACCOUNT` names one, and ignore the config
default account. Each row carries `account_id`, `account_name`,
`account_type`, `registration` and `is_retirement`, so a dividend paid inside
an IRA can be told apart from a taxable one, and a traditional IRA from a Roth
IRA. `account_type` is the family spelling robinhood-cli uses —
`ira_traditional`, `ira_roth`, `ira_sep`, `individual`, `joint`, … — mapped
from M1's registration; a rollover IRA is registered `TRADITIONAL_IRA`, so it
reads `ira_traditional`.

`net-worth` keeps M1's own headline figures (`total`, `assets`,
`liabilities`) and its product lines (Earn, Borrow, Spend), but lists the
Invest line one row per investment account — `account_id`, `name`, `type`
(the same family spelling), `registration`, `is_retirement`, `total` — so an
IRA's balance can be read on its own. If the accounts do not add up to M1's
Invest figure to the cent, the difference is its own `Invest` row, so the rows
always sum to what they did. An account M1 cannot price is listed without a
`total`; its value is in that `Invest` row, which is then present even at
`0.00`.

`m1f status` and `m1f api query` (unauthenticated documents) work **without a
login** — M1 answers introspection and system status anonymously.

Every command takes `--json`. Machine output goes to stdout as a single
`schema`-tagged DTO; diagnostics go to stderr.

```sh
m1f holdings list --json | jq '.items[] | {symbol, value: .value.amount}'
```

## Use with Claude

`m1f mcp` serves five read-only tools over MCP, so Claude can answer
questions about your own M1 accounts. There is no hosted service: the tools
run on your computer, in your copy of `m1f`, and call M1's backend directly
with the session `m1f auth login --browser` stored in your OS keychain.

| Tool | Answers |
| --- | --- |
| `m1_portfolio` | What am I worth at M1, and what do I hold? Net worth, each account's total, and the positions, narrowed by `account` (its name) or `symbol` |
| `m1_activity` | What happened over a period? Trades, deposits, withdrawals and dividends by `since`/`until` dates (year to date by default), `account`, `type` (`Trade`, `Cash`, `Position`) and `symbol` |
| `m1_documents` | Which statements and tax forms exist? Listed by `type` (`tax-form` for 1099s) and `since`/`until`; never downloaded (`m1f documents download` does that) |
| `m1_realized_gains` | What did I realize this year? Closed lots by sale date, with exact short-term, long-term and wash-sale totals; taxable accounts unless `account` names an IRA |
| `m1_trading` | Is a sale queued, and when does it trade? Each account's queued orders, rebalances and estimated trades, auto-invest, the next window, cash available for withdrawal and pending transfers, narrowed by `account`; a figure M1 did not give is null |

Results are concise by default (`response_format: "detailed"` adds ids and
provider detail), 25 records a page with a cursor for more, and never larger
than about 32,000 characters. `m1_trading` returns one entry per account
instead of pages. Accounts are named, not numbered. Descriptions
come from M1 and other parties; the server tells Claude to treat them as
data, not instructions.

**Sign in first.** M1 sign-in is through a browser, so no settings form can
hold it. Install `m1f` and run `m1f auth login --browser` in a terminal
(see [Getting started](#getting-started)). Both ways of connecting Claude
below then use that session from the OS keychain (service `piekstra.m1f`),
and refresh it in place as the commands do. If the session is missing or has
lapsed, the tools say so and ask you to run `m1f auth login --browser --overwrite`
in a terminal; they never sign in by themselves. After a block at the edge they say to
wait or try another network first.

**Claude Code.** Add the `m1-cli` plugin from the
[piekstra plugin marketplace](https://github.com/piekstra/claude-plugins):

```console
$ claude plugin marketplace add piekstra/claude-plugins
$ claude plugin install m1-cli@piekstra-plugins
```

or register the server yourself:

```console
$ claude mcp add m1 -- m1f mcp
```

**Claude Desktop.** Download `m1f-<version>.mcpb` from the
[latest release](https://github.com/piekstra/m1-cli/releases/latest) and
open it. It asks for nothing: the bundled `m1f` reads the session your
installed `m1f` stored. On macOS the bundled binary is a different program
to the keychain, so its first call raises a keychain prompt for the
`piekstra.m1f` item; choose **Always Allow**, or every call will ask again.

Any other MCP client that launches a local server can run `m1f mcp`.

**Claude on the web and mobile.** claude.ai reaches tools through a remote
connector, and M1 sign-in stays on your computer, so `m1f` serves the same
tools from your computer to a connector you deploy into your own Cloudflare
account:

```console
$ m1f mcp --new-token            # once: a bearer token, saved in the keychain and printed for the Worker
$ m1f mcp --http --port 8731     # serve on 127.0.0.1 only
```

The connector, [cli-common's `connector/`](https://github.com/piekstra/cli-common/tree/main/connector#tools-from-your-computer-home-modules),
reaches that port through a Cloudflare Tunnel in your account; its README
walks through the tunnel, the VPC service, a launchd agent that keeps the
server running, and the `HOME_M1_TOKEN` secret, with the threat model.
`--http` binds 127.0.0.1 only, refuses to start without the token, refuses
any request whose `Host` is not loopback or that carries an `Origin`, and
serves the read-only tools only. The session never leaves your computer, but
tool results do: your balances, positions and activity pass through
Cloudflare and reach Claude ([`SECURITY.md`](SECURITY.md)). While the computer
sleeps, the tools answer that it is offline.

After `m1f self-update`, restart the server: a running one keeps the old code,
and its launchd agent restarts it only when it exits. Its start line names the
version.

```console
$ launchctl kickstart -k gui/$(id -u)/com.piekstra.m1f-mcp-http
```

`self-update` does not reach a Claude Desktop extension, which runs its own copy.
Install the new release's `.mcpb` too. A server or extension on an older version
renews without the lock the others use, which can cost a sign-in.

## Tax documents

The household's first M1 *taxable* account was opened in **2026**, so its first
consolidated 1099 covers **TY2026** and arrives in early 2027 — but the login
also carries older accounts with a back-catalog of forms (consolidated 1099s,
1099-Rs, 5498s, 1099-INTs going back to 2020). `m1f documents list --type
tax-form` lists them; `m1f lots list --closed` gives per-lot realized gain/loss
for Form 8949, which is richer than the 1099-B PDF.

M1 keeps only the **last ~3 years** of statements self-serve, so an annual
`m1f documents download --all -o …` is worth scheduling. Details, including the
2023 Apex clearing-firm gap that affects older cost basis, are in
[`docs/api.md`](docs/api.md#tax-documents).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | unexpected error |
| 2 | usage error |
| 3 | auth required, or credentials invalid/expired |
| 4 | not found |
| 5 | upstream/provider error, or another `m1f` process holding the token-refresh lock past the wait |
| 6 | confirmation required |

Scripts can branch on 3 ("run the login flow") and 5 ("M1 issue or a busy lock,
retry later") without parsing messages.

## Security

Secrets enter only by the browser capture (`--browser`), prompt, `--stdin`, or
`--from-env <VAR>` — **never argv**, which would put your password or session
in shell history and every process listing. Tokens live only in the OS
keychain (`piekstra.m1f`); your password is never stored at all, and of a
browser session only the access token, refresh token, expiry and client id
are kept. See [`SECURITY.md`](SECURITY.md).

## A note on trusting the output

M1's GraphQL backend returns **HTTP 200 for failures**, and its login payload
reports failure *inside a perfectly clean GraphQL envelope*. Both traps are
handled in one place each, and both are documented in
[`docs/api.md`](docs/api.md) — because the failure mode they produce is a CLI
that confidently shows you an empty portfolio, or reports a login that never
happened. If you extend this tool, read those two sections first.

## Development

```sh
make dev        # debug build, signed with the stable dev identity
make verify     # fmt-check + lint + test + smoke — what CI runs
make install
```

Tests are **offline and credential-free**: no test touches the network or the
keychain, because a login can spend an MFA code and is rate-limited. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md).

## License

MIT
