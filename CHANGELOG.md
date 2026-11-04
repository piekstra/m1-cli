# Changelog

## v0.6.2 — 2026-11-04

- `m1_activity`, `m1_documents` and `m1_realized_gains`: a row with no id is an upstream error, including a document whose id blob no longer decodes. They used to fall to the count within their day.
- `auth logout --forget` speaks to a server on `$M1F_MCP_TOKEN` too, which never had a keychain item to remove.
- cli-common v0.29.0, up from v0.27.0.

## v0.6.1 — 2026-11-03

Moves to cli-common v0.27.0.

- `auth logout --forget` removes the connector token `mcp-http-token`, and says what that does not
  end, even when another step fails: a running `m1f mcp --http` keeps the token it started with.
- `m1_activity`, `m1_documents` and `m1_realized_gains` page by position, so a row that arrives
  between pages repeats nothing and skips nothing. Rows of the same day now run in a fixed order of
  their own. A cursor from an earlier version still works, as the count of rows it holds.
- A tool call waits 45 seconds for the one before it, then says so, where it used to wait without
  limit behind a keychain prompt. It holds its turn for the whole call, however many accounts it
  reads.
- A password and a refresh token stay on the host they were for. reqwest re-sends a body on a 307
  or 308, so the token request and the login and renewal mutations refuse a redirect to another
  host.
- On Windows, a session too long for one credential is split and read back as one.

## v0.6.0 — 2026-11-03

A browser sign-in now runs in a profile `m1f` keeps, where it used to run in a
scratch profile deleted after every sign-in. Moves to cli-common v0.20.0.

- `m1f auth login --browser` keeps its Chrome profile on disk, owner-only
  (`0700`), at `~/Library/Application Support/piekstra.m1f/browser-profile` on
  macOS and under `$XDG_DATA_HOME` (or `~/.local/share`) on Linux, so M1's own
  cookies carry over and a later sign-in often needs no password, code or bot
  check. Other systems still use a scratch profile every time.
- The trade: it is a full Chrome profile, so it also holds browsing history with full
  URLs, query strings included, and the HTTP cache. Chrome's cookie encryption does
  not cover those; `0700` is their only protection, and ordinary backups usually include the directory.
  On Linux with no desktop keyring Chrome encrypts the cookies with a fixed, publicly
  known key, so there the session cookie has only `0700` too. SECURITY.md has the
  details.
- `m1f auth login --browser --fresh-profile` runs one sign-in in a scratch
  profile, and leaves the kept one alone.
- `m1f auth logout` also removes the kept profile, as its last step, and now attempts
  every step even after one fails, or when the config cannot be parsed. If one fails
  it says what is cleared and what remains, and exits with the first failure's code.
  While a sign-in or a Chrome is
  using the profile, or when the path is a symlink or another user's, that is exit 1
  with only the profile remaining.
- Every failure once the window has opened now says the kept profile stays and that
  `m1f auth logout` removes it: a timeout, a closed window, Ctrl-C, M1 throttled or
  down during the check, a keychain write that fails.
- `m1f auth status` reports whether a profile is kept (`browser_profile` with
  `--json`, a `Browser:` line otherwise), not whether anything is signed in there.
- While `M1F_KEYCHAIN_SERVICE` names another service, `m1f auth logout` leaves the
  kept profile and the config in place and says so, a sign-in writes no config, and
  `--browser` signs in through a scratch profile.
- The profile keeps no tokens between runs. Its site storage, where M1's page holds
  them, is removed before Chrome starts and again once Chrome has stopped; after a
  crash or a second Ctrl-C, the next launch removes it. Its cookies stay, and Chrome
  now quits over its debug port, so a fresh one reaches the disk.
- The capture now takes a session only once it has not expired and M1 has not refused
  it (`viewer.isAuthenticated`), and a session from the window is never renewed at
  login. That is its one read: it goes straight to the keychain afterwards. A token M1
  refused with a 401 or its own JSON is not sent again, and a timeout says what M1
  answered.
- If that read cannot decide (a Cloudflare page, a throttle, an outage, a dropped
  connection, an answer with no verdict), the sign-in is kept: the session is stored,
  the exit is 0, `--json` says `verified: false`, and a warning says why, even under
  `-q`, that it is unverified, and that if reads keep failing, `m1f auth login --browser
  --overwrite` is the way out.
- After a Cloudflare page or a 403 with no JSON, that warning says a new sign-in may not
  help, because the block is on the client rather than the session: wait or try another
  network, and only if reads still fail after that, run `m1f auth login --browser
  --overwrite`. An ordinary read's error, a renewal's and the MCP tools' fix say the same.
- An HTML page on an ordinary read is now exit 5, where it was exit 3, and it no longer
  renews the session: it is not M1's own refusal, and a renewal would rotate the refresh
  token for nothing. A 401 whatever its body is exit 3 after one renewal, as M1's own JSON
  refusal is. A 401 with neither JSON nor HTML was exit 5.
- The MCP tools' sign-in fix names `m1f auth login --browser --overwrite`, because a
  lapsed session is still stored and the command refuses without the flag.
- A login result under `--json` now always carries `verified`, a boolean: `true` when a
  read accepted the session and `false` otherwise. `--no-verify` on `--browser` or
  `--browser-session` and the password login say `false`. So does `auth set-credential`,
  which printed no result under `--json` before and now prints this one; its stderr line
  now says the session is stored unverified. The field is cli-common's
  `AuthStatus::verified`, and `auth status` leaves it off.
- Before going back to an older release, run `m1f auth logout`. An older release does
  not know the kept profile and its logout leaves it behind; otherwise delete
  `~/Library/Application Support/piekstra.m1f/browser-profile` (on Linux, under
  `$XDG_DATA_HOME` or `~/.local/share`) by hand afterwards.
- A 429 or a 5xx with an HTML body is now exit 5, like any other 429 or 5xx, and no
  longer reads as a refused session (exit 3) on any command.
