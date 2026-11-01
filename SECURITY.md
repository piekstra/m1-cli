# Security policy

## Reporting

Open a private security advisory on the repository (Security → Advisories → New
draft). Please do not file a public issue for anything credential-related.

## What this tool holds

`m1f` talks to M1's own web/mobile backend with your own credentials. It has no
server component and no telemetry. Everything it stores is local:

| Thing | Where it lives | Notes |
| --- | --- | --- |
| Password | **Never stored by default.** | Only read at `auth login` time, from a prompt/stdin/env, and sent straight to the login mutation. The browser-session login never sees it: the owner types it into M1's own page. |
| Access token | OS keychain, service `piekstra.m1f` | Short-lived bearer token. Refreshed in place. A browser session's is an Auth0 access token for M1's API. |
| Refresh token | OS keychain, service `piekstra.m1f` | Long-lived. Treat as equivalent to your password. A browser session's is sent only to M1's Auth0 token endpoint (`https://account.m1.com/oauth/token`). |
| Browser-session capture | **Not stored.** | `auth login --browser` reads auth0-spa-js's cache entry out of the sign-in window; `auth login --browser-session` reads it from stdin/env. Either way only the access token, refresh token, expiry and client id are kept; the id token and the profile claims in it are dropped. A token whose audience is not M1's API, or whose issuer is not `account.m1.com`, is refused before anything is sent anywhere — so a captured or pasted token cannot direct the refresh token to another host. |
| Sign-in window profile | A fresh `0700` directory in the temp dir, **deleted** when the login ends | `auth login --browser` runs Chrome in a throwaway profile, created exclusively under an unpredictable name, so nothing of your everyday browser is read and nothing of the sign-in stays behind. Chrome's DevTools port (loopback only, a port Chrome picks) has no authentication: while the window is open, any local process that reaches it could read that window's session. The window is open only while you sign in; the dashboard tab is closed the moment the session is read, then Chrome is stopped and the profile removed, Ctrl-C included. The session is read only from pages on exactly `dashboard.m1.com` (docs/api.md, "The browser capture"). |
| MFA breadcrumb | OS keychain, service `piekstra.m1f` | Only a marker that a code was requested — it holds **no credential**, because M1 has no resumable session. Deleted on the next successful login. |
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
- **Secrets never reach a file.** The keychain is the only persistence. The
  one exception is outside `m1f`'s hands: Chrome's own scratch profile holds
  the signed-in page while the sign-in window is open, and is deleted with it.
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

## Revoking access

`m1f auth logout --forget` clears the stored tokens and the config identity.
That removes this machine's copy of the credentials; it does not invalidate the
session server-side. To do that, change your M1 password and sign out other
devices from M1's own web app or mobile app.

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
