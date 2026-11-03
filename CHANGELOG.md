# Changelog

## v0.6.0 — 2026-11-03

A browser sign-in now runs in a profile `m1f` keeps, where it used to run in a
scratch profile deleted after every sign-in. Moves to cli-common v0.19.0.

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
- The capture now takes a session only once it has not expired and M1 accepts it
  (`viewer.isAuthenticated`), and a session from the window is never renewed at
  login. A token M1 refused is not sent again. A throttle or an outage during that
  check ends the wait with an error.
- A 429 or a 5xx with an HTML body is now exit 5, like any other 429 or 5xx, and no
  longer reads as a refused session (exit 3) on any command.
