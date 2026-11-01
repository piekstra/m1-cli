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

use pk_cli_auth::reauth::with_reauth;
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

    pub fn store_tokens(&self, bundle: &TokenBundle) -> Result<(), CliError> {
        let raw = serde_json::to_string(bundle)
            .map_err(|e| CliError::Other(format!("serializing token bundle: {e}")))?;
        self.creds.set(TOKEN_ACCOUNT, &Secret::new(raw))
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

    /// An authenticated client built from the stored access token.
    pub fn client(&self) -> Result<M1Client, CliError> {
        let bundle = self
            .tokens()?
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
        with_reauth(|| op(&self.client()?), || self.refresh())
    }

    /// Exchange the stored refresh token for a new access token.
    ///
    /// Deliberately does *not* fall back to a password re-login: `m1f` never
    /// stores a password, and a fresh login can demand an MFA code that no
    /// unattended run could answer.
    fn refresh(&self) -> Result<(), CliError> {
        let bundle = self.tokens()?;
        let refresh_token = bundle.as_ref().and_then(|b| b.refresh_token.clone());
        let hint = bundle
            .as_ref()
            .map_or(BROWSER_LOGIN, TokenBundle::login_hint);
        if let Some(reason) = refresh_blocked(
            self.cfg.auto_login(),
            bundle.is_some(),
            refresh_token.is_some(),
            hint,
        ) {
            return Err(CliError::Auth(reason));
        }
        let refresh_token = refresh_token.expect("checked");
        if !self.common.quiet {
            eprintln!("access token expired — refreshing");
        }
        // A browser session renews at M1's Auth0 tenant; a password bundle
        // through the legacy `Reauthenticate` mutation.
        let fresh = match bundle.and_then(|b| b.auth0) {
            Some(grant) => crate::auth0::refresh(&grant, &refresh_token, self.common.verbose)?,
            None => auth::refresh_tokens(self, &refresh_token)?,
        };
        self.store_tokens(&fresh)
    }
}

/// The login that works today, named when nothing is stored.
const BROWSER_LOGIN: &str = crate::auth0::LOGIN;

/// Why an automatic token refresh can't proceed, if it can't.
///
/// Split from the action so the policy is testable without a keychain, and so
/// every refusal names the one command that fixes it (`hint`: the stored
/// bundle's own login, [`TokenBundle::login_hint`]).
fn refresh_blocked(
    auto_login: bool,
    has_bundle: bool,
    has_refresh_token: bool,
    hint: &str,
) -> Option<String> {
    // Never-logged-in is checked first and worded differently. The reauth rails
    // replace the original error with whatever this returns, so saying "access
    // token expired" here would tell a brand-new user their token expired —
    // pointing them at a problem they don't have.
    if !has_bundle {
        return Some(format!("not logged in — run `{hint}`"));
    }
    if !auto_login {
        return Some(format!(
            "access token expired — run `{hint}` (auto_login is off)"
        ));
    }
    if !has_refresh_token {
        return Some(format!(
            "access token expired and no refresh token is stored — run `{hint}`"
        ));
    }
    None
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

    const LEGACY: &str = "m1f auth login";

    #[test]
    fn refresh_proceeds_when_a_refresh_token_is_stored() {
        assert_eq!(refresh_blocked(true, true, true, LEGACY), None);
    }

    #[test]
    fn refresh_declines_when_auto_login_is_off() {
        let why = refresh_blocked(false, true, true, LEGACY).expect("blocked");
        assert!(why.contains("auto_login is off"), "{why}");
        assert!(why.contains("m1f auth login"), "{why}");
    }

    #[test]
    fn refresh_declines_without_a_refresh_token() {
        let why = refresh_blocked(true, true, false, LEGACY).expect("blocked");
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
        let why = refresh_blocked(true, true, false, stored.login_hint()).expect("blocked");
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
            let why = refresh_blocked(auto, false, false, BROWSER_LOGIN).expect("blocked");
            assert!(why.contains("not logged in"), "{why}");
            assert!(why.contains("`m1f auth login --browser`"), "{why}");
            assert!(!why.contains("expired"), "misleading message: {why}");
        }
    }
}
