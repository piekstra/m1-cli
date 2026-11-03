//! Domain command modules. Each read emits a `schema`-tagged DTO in `--json`
//! mode and a shaped table/kv view in text mode.

pub mod accounts;
pub mod activity;
pub mod api;
pub mod auth;
pub mod dividends;
pub mod documents;
pub mod holdings;
pub mod ira;
pub mod lots;
pub mod networth;
pub mod positions;
pub mod status;
pub mod summary;
pub mod transactions;
pub mod transfers;

use std::cell::RefCell;

use pk_cli_auth::reauth::with_reauth;
use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_core::{CliError, CommonArgs, RangeArgs};
use pk_cli_secrets::{CredentialStore, Secret};
use serde_json::Value;

use crate::client::{M1Client, PendingChallenge, TokenBundle};
use crate::config::Config;

// The output contract lives in the shared crate; re-exported so the command
// modules keep their short `use super::{emit, items, table_view}`.
pub use pk_cli_core::output::{rows_of as items, table_view};

/// Keychain account keys under service `piekstra.m1f`. Separate entries so the
/// token bundle and a parked MFA challenge rotate independently.
pub const TOKEN_ACCOUNT: &str = "tokens";
pub const PENDING_ACCOUNT: &str = "pending-challenge";

pub struct Ctx<'a> {
    pub common: &'a CommonArgs,
    pub cfg: &'a Config,
    pub creds: &'a CredentialStore,
    pub account_override: Option<&'a str>,
}

impl Ctx<'_> {
    /// The account id to act on: `--account`/`M1F_ACCOUNT`, else config.
    ///
    /// Returns a usage error naming both fixes rather than silently picking
    /// one of several accounts — guessing wrong shows someone another
    /// account's holdings.
    pub fn account(&self) -> Result<String, CliError> {
        self.account_override
            .map(str::to_string)
            .or_else(|| self.cfg.account.clone())
            .ok_or_else(|| {
                CliError::Usage(
                    "no account selected — pass --account <ID> or run \
                     `m1f config set account <ID>` (see `m1f accounts list`)"
                        .into(),
                )
            })
    }

    /// The selected account for `holdings list`: `--account`/`M1F_ACCOUNT`,
    /// else config — the per-account resolution every account-scoped command
    /// uses, kept so an existing `config set account` still narrows holdings.
    /// With nothing selected, holdings reads the household instead of failing.
    pub fn selected_account(&self) -> Option<String> {
        self.account_override
            .map(str::to_string)
            .or_else(|| self.cfg.account.clone())
    }

    /// The one scope rule for household reads (`positions list`,
    /// `dividends list`): every account on the login unless `--account` /
    /// `M1F_ACCOUNT` names one. The config default account is deliberately
    /// NOT consulted — a convenience setting must not silently narrow a
    /// household capture. Pass the result to `accounts::scope`.
    pub fn household_selection(&self) -> Option<&str> {
        self.account_override
    }

    pub fn tokens(&self) -> Result<Option<TokenBundle>, CliError> {
        let Some(raw) = self.creds.get(TOKEN_ACCOUNT)? else {
            return Ok(None);
        };
        // A malformed bundle is treated as "not logged in" rather than a hard
        // failure: the fix is the same login the user would run anyway.
        Ok(serde_json::from_str(raw.expose()).ok())
    }

    fn store_tokens(&self, bundle: &TokenBundle) -> Result<(), CliError> {
        let raw = serde_json::to_string(bundle)
            .map_err(|e| CliError::Other(format!("serializing token bundle: {e}")))?;
        self.creds.set(TOKEN_ACCOUNT, &Secret::new(raw))
    }

    /// Fail now if the lock a login's write needs is stuck or unusable, before
    /// anyone signs in or a secret is read from stdin.
    pub fn before_signin(&self) -> Result<(), CliError> {
        RefreshLock::for_binary(crate::BIN)?.before_signin()
    }

    /// Store a session a login obtained, under the lock a renewal holds, so a
    /// renewal in flight cannot overwrite it with the old session's tokens.
    pub fn store_login(&self, bundle: &TokenBundle) -> Result<(), CliError> {
        RefreshLock::for_binary(crate::BIN)?.store_signin(|| self.store_tokens(bundle))
    }

    /// Delete the stored session, under the lock a renewal holds if it can be
    /// had, so a renewal in flight cannot store it again after the logout. The
    /// delete runs either way: the lock must not keep a credential on the machine.
    ///
    /// `store_login` and this are one call over the real keychain, which no test
    /// may reach. `RefreshLock`'s own tests cover what these calls do.
    pub fn forget_tokens(&self) -> Result<(), CliError> {
        RefreshLock::forget_for_binary(crate::BIN, || self.creds.delete(TOKEN_ACCOUNT).map(|_| ()))
    }

    pub fn pending(&self) -> Result<Option<PendingChallenge>, CliError> {
        let Some(raw) = self.creds.get(PENDING_ACCOUNT)? else {
            return Ok(None);
        };
        Ok(serde_json::from_str(raw.expose()).ok())
    }

    pub fn store_pending(&self, pending: &PendingChallenge) -> Result<(), CliError> {
        let raw = serde_json::to_string(pending)
            .map_err(|e| CliError::Other(format!("serializing pending challenge: {e}")))?;
        self.creds.set(PENDING_ACCOUNT, &Secret::new(raw))
    }

    pub fn clear_pending(&self) -> Result<(), CliError> {
        self.creds.delete(PENDING_ACCOUNT).map(|_| ())
    }

    /// An authenticated client built from a stored session.
    fn client_for(&self, bundle: Option<TokenBundle>) -> Result<M1Client, CliError> {
        let bundle = bundle
            .ok_or_else(|| CliError::Auth(format!("not logged in — run `{BROWSER_LOGIN}`")))?;
        M1Client::new(
            &self.cfg.base_url(),
            Some(bundle.access_token),
            self.common.verbose,
        )
    }

    /// An unauthenticated client, for the login flow itself.
    pub fn anonymous(&self) -> Result<M1Client, CliError> {
        M1Client::anonymous(&self.cfg.base_url(), self.common.verbose)
    }

    /// Run a read, refreshing the access token once if it has lapsed.
    ///
    /// **Reads only** — the retry rails re-run `op`, which would double-apply a
    /// write. A fresh client is built per attempt so the retry picks up the
    /// token that `refresh` just wrote to the keychain.
    pub fn read<T>(&self, op: impl Fn(&M1Client) -> Result<T, CliError>) -> Result<T, CliError> {
        let presented = RefCell::new(None);
        with_reauth(
            || {
                let bundle = self.tokens()?;
                presented.replace(bundle.clone());
                op(&self.client_for(bundle)?)
            },
            || self.refresh(presented.borrow().as_ref()),
        )
    }

    /// Exchange the stored refresh token for a new access token, given the
    /// session whose access token M1 just refused.
    ///
    /// Deliberately does *not* fall back to a password re-login: `m1f` never
    /// stores a password, and a fresh login can demand an MFA code that no
    /// unattended run could answer.
    fn refresh(&self, presented: Option<&TokenBundle>) -> Result<(), CliError> {
        let refresh_token = renewable(
            self.cfg.auto_login(),
            presented.is_some(),
            presented.and_then(|b| b.refresh_token.as_deref()),
            presented.map_or(BROWSER_LOGIN, TokenBundle::login_hint),
        )
        .map_err(CliError::Auth)?;
        renew_session(
            &RefreshLock::for_binary(crate::BIN)?,
            refresh_token,
            || self.tokens(),
            |stored, refresh_token| {
                if !self.common.quiet {
                    eprintln!("access token expired — refreshing");
                }
                // A browser session renews at M1's Auth0 tenant; a password
                // bundle through the legacy `Reauthenticate` mutation.
                match &stored.auth0 {
                    Some(grant) => crate::auth0::refresh(grant, refresh_token, self.common.verbose),
                    None => auth::refresh_tokens(self, refresh_token),
                }
            },
            |fresh| self.store_tokens(fresh),
        )
    }
}

/// One renewal, safe against every other `m1f` process: the long-running
/// `mcp --http` server, a stdio server, a command in a terminal. They share one
/// rotating refresh token, and Auth0 answers a second use of a retired one by
/// revoking the session (docs/api.md, "The shared-refresh-token trap"), which
/// costs the owner a sign-in. So the session is read again under the lock, and
/// a stored refresh token other than the one `presented` means another process
/// renewed while this one waited: no grant, and the retry picks up its tokens.
fn renew_session(
    lock: &RefreshLock,
    presented: &str,
    read: impl FnOnce() -> Result<Option<TokenBundle>, CliError>,
    grant: impl FnOnce(&TokenBundle, &str) -> Result<TokenBundle, CliError>,
    store: impl FnOnce(&TokenBundle) -> Result<(), CliError>,
) -> Result<(), CliError> {
    lock.renew(
        // Logged out while this process waited: there is nothing to renew.
        || read()?.ok_or_else(|| CliError::Auth(format!("not logged in — run `{BROWSER_LOGIN}`"))),
        |stored| stored.refresh_token.as_deref() == Some(presented),
        |stored| {
            let fresh = grant(&stored, presented)?;
            store(&fresh)?;
            Ok(fresh)
        },
    )
    .map(drop)
}

/// The login that works today, named when nothing is stored.
const BROWSER_LOGIN: &str = crate::auth0::LOGIN;

/// The refresh token an automatic renewal may present, or why it can't proceed.
///
/// Split from the action so the policy is testable without a keychain, and so
/// every refusal names the one command that fixes it (`hint`: the stored
/// bundle's own login, [`TokenBundle::login_hint`]).
fn renewable<'a>(
    auto_login: bool,
    has_bundle: bool,
    refresh_token: Option<&'a str>,
    hint: &str,
) -> Result<&'a str, String> {
    // Never-logged-in is checked first and worded differently. The reauth rails
    // replace the original error with whatever this returns, so saying "access
    // token expired" here would tell a brand-new user their token expired —
    // pointing them at a problem they don't have.
    if !has_bundle {
        return Err(format!("not logged in — run `{hint}`"));
    }
    if !auto_login {
        return Err(format!(
            "access token expired — run `{hint}` (auto_login is off)"
        ));
    }
    refresh_token.ok_or_else(|| {
        format!("access token expired and no refresh token is stored — run `{hint}`")
    })
}

/// Emit a DTO, taking the `--json` flag off the context.
pub fn emit(ctx: &Ctx, schema: &str, payload: Value, text: impl FnOnce(&Value)) {
    pk_cli_core::output::emit(ctx.common.json, schema, payload, text)
}

/// Print a "nothing here" line to stderr, so stdout stays a clean data stream.
pub fn note_empty(ctx: &Ctx, what: &str) {
    if !ctx.common.quiet {
        eprintln!("no {what} found");
    }
}

/// Whether a **newest-first** cursor loop can stop early given the range flags.
///
/// Shared by `activity` and `transfers`, whose feeds both arrive newest-first
/// and key on a `date` field: once `--limit` rows are held (with no `--since`
/// reaching further back), or the oldest row already predates `--since`, there
/// is nothing older worth fetching. A pure predicate so both commands page
/// identically without duplicating the rule.
pub fn done_paging(range: &RangeArgs, rows: &[Value]) -> bool {
    if let (Some(limit), None) = (range.limit, range.since.as_ref()) {
        if rows.len() >= limit as usize {
            return true;
        }
    }
    if let Some(since) = &range.since {
        if let Some(oldest) = rows.iter().filter_map(|r| r["date"].as_str()).min() {
            if oldest < since.as_str() {
                return true;
            }
        }
    }
    false
}

/// Apply the shared range flags to a list of DTO rows: keep those whose
/// `date_key` falls in the `--since`/`--until` window (inclusive; ISO dates
/// compare lexically), then cap at `--limit`. A row with no/absent date is not
/// filtered out by a bound, only by the limit.
pub fn paginate(rows: Vec<Value>, date_key: &str, range: &RangeArgs) -> Vec<Value> {
    let keep = |row: &Value| {
        let date = row.get(date_key).and_then(Value::as_str);
        let after = range
            .since
            .as_deref()
            .zip(date)
            .map(|(s, d)| d >= s)
            .unwrap_or(true);
        let before = range
            .until
            .as_deref()
            .zip(date)
            .map(|(u, d)| d <= u)
            .unwrap_or(true);
        after && before
    };
    rows.into_iter()
        .filter(keep)
        .take(range.limit.map(|n| n as usize).unwrap_or(usize::MAX))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::Duration;

    fn rows() -> Vec<Value> {
        vec![
            json!({ "date": "2026-08-05" }),
            json!({ "date": "2026-07-05" }),
            json!({ "date": "2026-06-05" }),
        ]
    }

    #[test]
    fn done_paging_stops_once_rows_predate_since() {
        let range = RangeArgs {
            since: Some("2026-08-01".into()),
            until: None,
            limit: None,
        };
        let rows = vec![json!({"date": "2026-08-05"}), json!({"date": "2026-07-30"})];
        assert!(done_paging(&range, &rows));
        assert!(!done_paging(&range, &[json!({"date": "2026-08-05"})]));
    }

    #[test]
    fn done_paging_stops_once_limit_is_satisfied_without_a_since() {
        let range = RangeArgs {
            since: None,
            until: None,
            limit: Some(2),
        };
        let rows = vec![json!({"date": "2026-08-05"}), json!({"date": "2026-08-04"})];
        assert!(done_paging(&range, &rows));
    }

    #[test]
    fn done_paging_is_false_with_no_flags() {
        assert!(!done_paging(
            &RangeArgs::default(),
            &[json!({"date": "2026-08-05"})]
        ));
    }

    #[test]
    fn since_and_until_are_inclusive() {
        let r = RangeArgs {
            since: Some("2026-07-01".into()),
            until: Some("2026-08-05".into()),
            limit: None,
        };
        let out = paginate(rows(), "date", &r);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["date"], json!("2026-08-05"));
    }

    #[test]
    fn limit_caps_after_filtering() {
        let r = RangeArgs {
            since: None,
            until: None,
            limit: Some(1),
        };
        assert_eq!(paginate(rows(), "date", &r).len(), 1);
    }

    #[test]
    fn no_flags_keeps_everything() {
        assert_eq!(paginate(rows(), "date", &RangeArgs::default()).len(), 3);
    }

    fn ctx_parts(config_account: Option<&str>) -> (CommonArgs, Config, CredentialStore) {
        let cfg = Config {
            account: config_account.map(str::to_string),
            ..Config::default()
        };
        // Constructing a store names the keychain service; it reads nothing.
        (
            CommonArgs::default(),
            cfg,
            CredentialStore::for_binary("m1f-test"),
        )
    }

    #[test]
    fn a_config_default_narrows_holdings_but_not_household_reads() {
        let (common, cfg, creds) = ctx_parts(Some("acct-cfg"));
        let ctx = Ctx {
            common: &common,
            cfg: &cfg,
            creds: &creds,
            account_override: None,
        };
        assert_eq!(ctx.selected_account().as_deref(), Some("acct-cfg"));
        assert_eq!(ctx.household_selection(), None);
    }

    #[test]
    fn an_explicit_account_narrows_both() {
        let (common, cfg, creds) = ctx_parts(Some("acct-cfg"));
        let ctx = Ctx {
            common: &common,
            cfg: &cfg,
            creds: &creds,
            account_override: Some("acct-flag"),
        };
        assert_eq!(ctx.selected_account().as_deref(), Some("acct-flag"));
        assert_eq!(ctx.household_selection(), Some("acct-flag"));
    }

    #[test]
    fn nothing_selected_means_the_household_for_both() {
        let (common, cfg, creds) = ctx_parts(None);
        let ctx = Ctx {
            common: &common,
            cfg: &cfg,
            creds: &creds,
            account_override: None,
        };
        assert_eq!(ctx.selected_account(), None);
        assert_eq!(ctx.household_selection(), None);
    }

    fn session(refresh: &str) -> TokenBundle {
        TokenBundle {
            access_token: format!("dummy-access-for-{refresh}"),
            refresh_token: Some(refresh.into()),
            ..TokenBundle::default()
        }
    }

    /// Two processes' worth of contenders: each has its own open of the lock
    /// file, which is what contends, and both saw the same refresh token
    /// refused. Offline, with the keychain and the token endpoint stood in for.
    #[test]
    fn two_contenders_post_one_grant_and_both_use_its_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token-refresh.lock");
        let stored = Arc::new(Mutex::new(session("dummy-refresh-1")));
        let grants = Arc::new(Mutex::new(Vec::new()));
        let start = Arc::new(Barrier::new(2));
        let contenders: Vec<_> = (0..2)
            .map(|_| {
                let (path, stored, grants, start) = (
                    path.clone(),
                    Arc::clone(&stored),
                    Arc::clone(&grants),
                    Arc::clone(&start),
                );
                std::thread::spawn(move || {
                    start.wait();
                    renew_session(
                        &RefreshLock::at(path),
                        "dummy-refresh-1",
                        || Ok(Some(stored.lock().unwrap().clone())),
                        |_, presented| {
                            grants.lock().unwrap().push(presented.to_string());
                            std::thread::sleep(Duration::from_millis(100));
                            Ok(session("dummy-refresh-2"))
                        },
                        |fresh| {
                            *stored.lock().unwrap() = fresh.clone();
                            Ok(())
                        },
                    )
                })
            })
            .collect();
        for contender in contenders {
            contender.join().unwrap().unwrap();
        }
        assert_eq!(*grants.lock().unwrap(), ["dummy-refresh-1"]);
        assert_eq!(
            stored.lock().unwrap().refresh_token.as_deref(),
            Some("dummy-refresh-2")
        );
    }

    #[test]
    fn a_stored_token_that_changed_skips_the_grant() {
        let dir = tempfile::tempdir().unwrap();
        renew_session(
            &RefreshLock::at(dir.path().join("token-refresh.lock")),
            "dummy-refresh-1",
            || Ok(Some(session("dummy-refresh-2"))),
            |_, _| panic!("another process renewed: no grant"),
            |_| panic!("nothing new to store"),
        )
        .unwrap();
    }

    #[test]
    fn a_logout_while_waiting_is_an_auth_error_and_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let err = renew_session(
            &RefreshLock::at(dir.path().join("token-refresh.lock")),
            "dummy-refresh-1",
            || Ok(None),
            |_, _| panic!("logged out: no grant"),
            |_| panic!("logged out: nothing to store"),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("not logged in"), "{err}");
    }

    #[test]
    fn a_held_lock_is_a_bounded_error_and_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token-refresh.lock");
        RefreshLock::at(&path)
            .hold(|| {
                let err = renew_session(
                    &RefreshLock::at(&path).wait_at_most(Duration::from_millis(100)),
                    "dummy-refresh-1",
                    || panic!("no read without the lock"),
                    |_, _| panic!("no grant without the lock"),
                    |_| panic!("nothing to store"),
                )
                .unwrap_err();
                assert!(err.to_string().contains("try again"), "{err}");
                Ok(())
            })
            .unwrap();
    }

    const LEGACY: &str = "m1f auth login";

    #[test]
    fn refresh_proceeds_when_a_refresh_token_is_stored() {
        assert_eq!(
            renewable(true, true, Some("dummy-refresh"), LEGACY),
            Ok("dummy-refresh")
        );
    }

    #[test]
    fn refresh_declines_when_auto_login_is_off() {
        let why = renewable(false, true, Some("dummy-refresh"), LEGACY).expect_err("blocked");
        assert!(why.contains("auto_login is off"), "{why}");
        assert!(why.contains("m1f auth login"), "{why}");
    }

    #[test]
    fn refresh_declines_without_a_refresh_token() {
        let why = renewable(true, true, None, LEGACY).expect_err("blocked");
        assert!(why.contains("no refresh token"), "{why}");
        assert!(why.contains("m1f auth login"), "{why}");
    }

    /// A browser session that cannot renew points at the browser login, not
    /// at the password login Cloudflare blocks.
    #[test]
    fn a_browser_session_refusal_names_the_browser_login() {
        let stored = TokenBundle {
            auth0: Some(crate::auth0::Auth0Grant::default()),
            ..TokenBundle::default()
        };
        let why = renewable(true, true, None, stored.login_hint()).expect_err("blocked");
        assert!(
            why.contains("`m1f auth login --browser --overwrite`"),
            "{why}"
        );
    }

    /// A user who has never logged in must not be told their token expired.
    /// The reauth rails replace the original error with this one, so the
    /// wording here is what they actually see.
    #[test]
    fn never_logged_in_says_so_rather_than_claiming_expiry() {
        for auto in [true, false] {
            let why = renewable(auto, false, None, BROWSER_LOGIN).expect_err("blocked");
            assert!(why.contains("not logged in"), "{why}");
            assert!(why.contains("`m1f auth login --browser`"), "{why}");
            assert!(!why.contains("expired"), "misleading message: {why}");
        }
    }
}
