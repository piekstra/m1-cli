# Changelog

## v0.6.0 — 2026-11-03

Moves to cli-common v0.17.0 and Rust 1.89. A browser sign-in now runs in a
profile `m1f` keeps, where it used to run in a scratch profile deleted after every
sign-in.

- `m1f auth login --browser` keeps its Chrome profile on disk, owner-only
  (`0700`), at `~/Library/Application Support/piekstra.m1f/browser-profile` on
  macOS and under `$XDG_DATA_HOME` (or `~/.local/share`) on Linux, so M1's own
  cookies carry over and a later sign-in often needs no password, code or bot
  check. Other systems still use a scratch profile every time.
- The trade: it is a full Chrome profile, so it also holds browsing history with
  full URLs, query strings included, the HTTP cache and site storage. Chrome's
  cookie encryption does not cover those; `0700` is their only protection, and
  ordinary backups usually include the directory. On Linux with no desktop keyring
  Chrome encrypts the cookies with a fixed, publicly known key, so there the session
  cookie has only `0700` too. SECURITY.md has the details.
- `m1f auth login --browser --fresh-profile` runs one sign-in in a scratch
  profile, and leaves the kept one alone.
- `m1f auth logout` also removes the kept profile, as its last step. While a
  sign-in or a Chrome is using it, or when the path is a symlink or another
  user's, it exits 1 saying the session (and, with `--forget`, the config
  identity) is already cleared, that only the profile remains and how to finish.
- Every failure once the window has opened now says the kept profile stays and that
  `m1f auth logout` removes it: a timeout, a closed window, Ctrl-C, M1 throttled or
  down during the check, a keychain write that fails. `m1f auth status` does not
  report the profile: cli-common has no public way to ask whether one exists.
- While `M1F_KEYCHAIN_SERVICE` names another service, `m1f auth logout` leaves the
  kept profile in place and says so, and `--browser` signs in through a scratch
  profile.
- The capture takes the session's tokens out of `localStorage` as it reads them,
  so the kept profile holds cookies and not a refresh token that `m1f` will rotate
  and the next window could present, which is the reuse Auth0 answers by revoking
  the whole family.
- The capture now takes a session only once it has not expired and M1 accepts it
  (`viewer.isAuthenticated`), and a session from the window is never renewed at
  login. A token M1 refused is not sent again. A throttle or an outage during that
  check ends the wait with an error.
- `m1f auth login --browser --no-verify` now needs `--fresh-profile`: without the
  check, nothing tells a session left in a kept profile from a live one.
- A 429 or a 5xx with an HTML body is now exit 5, like any other 429 or 5xx, and no
  longer reads as a refused session (exit 3) on any command.
