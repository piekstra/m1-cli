# Security policy

## Reporting

Open a private security advisory on the repository (Security → Advisories → New
draft). Please do not file a public issue for anything credential-related.

## What this tool holds

`m1f` talks to M1's own web/mobile backend with your own credentials. It has no
telemetry, and no server component unless you run `m1f mcp --http` (see
[The MCP server](#the-mcp-server)). Everything it stores is local, except the
copy of the `--http` bearer token you give your own Cloudflare Worker:

| Thing | Where it lives | Notes |
| --- | --- | --- |
| Password | **Never stored by default.** | Only read at `auth login` time, from a prompt/stdin/env, and sent straight to the login mutation. The browser-session login never sees it: the owner types it into M1's own page. |
| Access token | OS keychain, service `piekstra.m1f` | Short-lived bearer token. Refreshed in place. A browser session's is an Auth0 access token for M1's API. |
| Refresh token | OS keychain, service `piekstra.m1f` | Long-lived. Treat as equivalent to your password. A browser session's is sent only to M1's Auth0 token endpoint (`https://account.m1.com/oauth/token`). |
| Browser-session capture | **Not stored.** | `auth login --browser` reads auth0-spa-js's cache entry out of the sign-in window; `auth login --browser-session` reads it from stdin/env. Either way only the access token, refresh token, expiry and client id are kept; the id token and the profile claims in it are dropped. A token whose audience is not M1's API, or whose issuer is not `account.m1.com`, is refused before anything is sent anywhere — so a captured or pasted token cannot direct the refresh token to another host. |
| Sign-in window profile | **Kept on disk**, `0700`, until `auth logout` removes it | See [The kept browser profile](#the-kept-browser-profile). `--fresh-profile` uses a scratch `0700` directory in the temp dir instead, created exclusively under an unpredictable name and deleted when the window closes, Ctrl-C included. Chrome's DevTools port (loopback only, a port Chrome picks) has no authentication: while the window is open, any local process that reaches it could read that window's session. The window is open only while you sign in; the dashboard tab is closed the moment the session is read, then Chrome is stopped. The session is read only from pages on exactly `dashboard.m1.com` (docs/api.md, "The browser capture"). |
| MFA breadcrumb | OS keychain, service `piekstra.m1f` | Only a marker that a code was requested — it holds **no credential**, because M1 has no resumable session. Deleted on the next successful login. |
| `--http` bearer token | OS keychain, service `piekstra.m1f`, item `mcp-http-token`, or `M1F_MCP_TOKEN`; **a copy in your Cloudflare Worker**, as its `HOME_M1_TOKEN` secret | Only if you use `m1f mcp --http`. It admits a caller to the read-only tools on 127.0.0.1; it signs in to nothing at M1. |
| Refresh lock | `~/.config/m1f/token-refresh.lock` | An empty file. `m1f` processes hold it while renewing the session, so two never present one refresh token. That holds once every copy sharing the keychain item is 0.5.2 or later, including a server not yet restarted and an installed Claude Desktop extension, which bundles its own binary. No secrets. |
| Non-secret settings | `~/.config/m1f/config.json` | Username, default account id. No secrets. |

## Invariants

These are enforced by code and tests, not just convention:

- **Secrets never enter through argv.** `auth login` accepts a secret only via
  the browser capture (`--browser`), interactive prompt, `--stdin`, or
  `--from-env <VAR>`. A password on the command line lands in your shell
  history and in every process listing on the machine; there is deliberately
  no flag that accepts one. The browser capture passes nothing secret on
  Chrome's command line either: only the start page and the profile path.
- **Secrets never reach a log.** `--verbose` prints request shapes, never
  `Authorization` headers, tokens, cookies, or full account numbers. The one
  place it echoes a server response — the GraphQL `errors[]` envelope, printed
  for schema discovery — is passed through a redactor
  (`client::redact_errors`) that allowlists safe fields and masks
  account-number-shaped digit runs and id-blob-shaped tokens in the message,
  because on this reverse-engineered API an error can echo request context.
  Enforced by `client::redact_errors_drops_unknown_fields_and_scrubs_the_message`.
- **`m1f` never writes a secret to a file.** The keychain is its only
  persistence. The one exception is Chrome's own: the profile a `--browser`
  sign-in keeps (below) holds what Chrome keeps for the pages opened in it, until
  `auth logout` removes it. `--fresh-profile` avoids it.
- **No raw captures are committed.** Fixtures under `tests/fixtures/` are
  synthetic. A pre-signed document URL is a live credential with a real
  expiry — capturing one into a repo leaks account access, so the test suite
  enforces that identity-bearing fields match known dummy shapes.
- **A document's node `id` is a credential and is never emitted raw.** M1's
  `Document.id` is base64 of a payload embedding the account number and a
  pre-signed download URL (verified live). `documents.rs` decodes it and emits
  only the stable *inner* document id; the account number and URL stay out of
  the DTO, out of `--json`, and out of logs. The download URL is used in-band
  and never printed.

## The MCP server

`m1f mcp` serves read-only tools to an MCP client (Claude Code, Claude
Desktop) over stdio, on this machine only; it opens no port unless run
with `--http` (below). It uses the
session already in the keychain, exactly as the commands do, refreshing it
in place, and never signs in: a missing or lapsed session is an error asking
the user to run `m1f auth login --browser` in a terminal. No tool downloads
a document or emits a document's raw id or link. The Claude Desktop
extension (`.mcpb`) takes no settings and so holds no credential of its
own; on macOS its bundled binary needs the user's approval, once, to read
the `piekstra.m1f` keychain item.

`m1f mcp --http --port <PORT>` serves the same tools over HTTP for the
user's own Cloudflare Worker, which reaches it through the user's own
Cloudflare Tunnel (cli-common's `connector/`). It binds 127.0.0.1 only, with
no flag for another address, and refuses to start without a bearer token of
32 or more characters, from `M1F_MCP_TOKEN` or the keychain item
`mcp-http-token` (`piekstra.m1f`), which `m1f mcp --new-token` makes from
256 random bits and replaces only with `--overwrite`. Every request must
carry the token (compared in constant time) and a `Host` of `127.0.0.1` or
`localhost`, and must not carry an `Origin`; there are no CORS headers. Only
the read-only tools are served (all four are). The session stays in the
keychain: the Worker sends tool calls and receives results, and never sees
a cookie or a token for M1.

**Tool results leave your computer on this path.** They hold your financial
data (balances, positions, activity, realized gains, the list of your tax
documents). They cross Cloudflare, through your tunnel and your Worker, and
reach Claude, which shows them in your conversation. Who holds what, and what
a leaked token can do, is in the connector's
[threat model](https://github.com/piekstra/cli-common/blob/main/connector/README.md#threat-model).

`M1F_KEYCHAIN_SERVICE` renames the keychain service read, for tests and
for checking the error paths against an empty service. It carries no
secret. It moves neither the kept browser profile nor the config, so while it names
another service `auth logout` leaves both in place and says so, a sign-in writes no
config, and `--browser` signs in through a scratch profile.

## The kept browser profile

`auth login --browser` runs Chrome in a profile of its own, so nothing of your
everyday browser is read, and keeps it so M1's sign-in remembers this device: a
later sign-in often needs no password, code or bot check. It lives at
`~/Library/Application Support/piekstra.m1f/browser-profile` on macOS and under
`$XDG_DATA_HOME` or `~/.local/share` on Linux; a launch is refused if the path is
a symlink, another user's or not `0700`. It is a full Chrome profile, and that is
the trade for fewer sign-ins. It holds:

- M1's cookies: Auth0's single sign-on session and the remembered device;
- browsing history with full URLs, query strings included;
- the HTTP cache, for whatever the responses allow: account data among it;
- `localStorage`, IndexedDB and other site storage;
- any password you let Chrome save.

Chrome encrypts its cookies at rest with a key from the system's keyring: on macOS
the "Chrome Safe Storage" key in the login keychain. On Linux with no desktop
keyring it falls back to a fixed, publicly known key, so there the session cookie
has only the directory's `0700` mode protecting it. Everywhere, the encryption
does not cover the history, the HTTP cache or site storage, so `0700` is their only
protection. The directory sits where ordinary user-level backups usually look, so
exclude it from any backup you don't want holding this.

**The session's tokens stay in it.** auth0-spa-js keeps the access and refresh
tokens in `localStorage`, which Chrome does not encrypt, so `0700` is all that
protects that copy of a live refresh token. The capture only reads: a removal from
the page may not reach the disk before Chrome stops, and the evaluation can run more
than once. Once `m1f` renews, the copy is retired, and the next window can present
it, which Auth0 answers by revoking the whole family, the session in the keychain
included; you then sign in again. cli-common has no way yet to clear site storage
around a launch. `--fresh-profile` avoids this for one run, and `auth logout`
removes the copy. The capture refuses anything expired or that M1 does not accept,
and `m1f` never renews from the window. A throttle or an outage during that check
ends the wait with an error, and takes nothing. `--browser --no-verify`, which would
skip the check, is refused unless `--fresh-profile` is there too.

**The profile outlives a failed sign-in.** However a sign-in fails once its window
has opened (a timeout, a closed window, Ctrl-C, M1 throttled or down during the
check, a keychain write that fails), the profile stays with what the sign-in got as
far as, which can be a live session, and the error says so. `m1f auth status` reads
only the keychain and config, so it does not show the profile.

## Revoking access

`m1f auth logout` clears the stored tokens and removes the kept browser profile,
and only that directory, as its last step; `--forget` also clears the config
identity. There is no way to remove the profile alone. Every step is attempted even
after one fails, and a config that cannot be parsed stops none of them, so a keychain
or config failure does not leave the profile behind.
If one fails, the error says what is cleared and what remains, and how to finish,
with the first failure's exit code. The profile's removal refuses while a sign-in or
a Chrome is using it, or when the path is a symlink or another user's; on its own
that is exit 1, with only the profile remaining.

That removes this machine's copies of the credentials; it does not invalidate
the session server-side. To do that, change your M1 password and sign out other
devices from M1's own web app or mobile app.

The delete runs even when the refresh lock is unavailable. If another process has
held the lock past the wait, `auth logout` deletes the tokens and exits 5 saying
so, because a renewal in flight can store them again. Run it again in a minute to
settle it.

`auth logout` does not touch `mcp-http-token` and does not stop `m1f mcp --http`.
The server stays up, its callers get auth errors, and **a later login silently
restores the token holder's access**. Revoke that access separately:

- **Invalidate the token:** `m1f mcp --new-token --overwrite`, then restart the
  server (`launchctl kickstart -k gui/$(id -u)/com.piekstra.m1f-mcp-http`). The
  old token works until the restart. A server that takes its token from
  `M1F_MCP_TOKEN` needs the variable changed instead. To keep using the
  connector, put the new value in the Worker's `HOME_M1_TOKEN`.
- **Remove the path:** stop the launchd agent
  (`launchctl bootout gui/$(id -u)/com.piekstra.m1f-mcp-http`) and the tunnel,
  and delete the tunnel and VPC service
  ([removing it](https://github.com/piekstra/cli-common/blob/main/connector/README.md#updating-rotating-and-removing)).

## Scope

`m1f` is read-only **with respect to account state**: it issues nothing that
moves money, places a trade, or changes a setting.

For precision, it does send three GraphQL mutations, none of which is a write in
that sense:

- `Authenticate` and `Reauthenticate` — obtain and refresh a token.
- `CreateAccountDocumentLink` — mints a short-lived signed URL for a document
  you can already list. It is sent only for the ACCOUNT_DOCUMENT class;
  investment documents (statements, 1099s) carry their own embedded signed URL
  and are fetched directly. It changes no account state.

Outside GraphQL, a browser session (`auth login --browser` or
`--browser-session`) is renewed with one `refresh_token` grant at M1's Auth0
token endpoint (`https://account.m1.com/oauth/token`) — the same renewal M1's
web app makes.
It obtains a token and changes no account state.

The `api query` passthrough refuses `mutation` and `subscription` documents, so
no user-supplied mutation can reach the API. If any of this ever changes, it
changes in the same commit as this paragraph.
